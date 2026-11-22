package dev.maplesu.manager.workmode.storage

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.switch.JournalErrors
import dev.maplesu.manager.workmode.switch.JournalReplay
import dev.maplesu.manager.workmode.switch.SwitchJournal
import dev.maplesu.manager.workmode.switch.SwitchOp
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption

/**
 * live/store 路径根映射：设备上 `liveRoot=File("/")`、`storeRoot=File(MoveSet.STORE_ROOT)`；
 * 主机单测用两个临时目录。所有 FileMoveExecutor 的路径都必须经这里解析（可测且可注入）。
 */
data class MovePathRoots(val liveRoot: File, val storeRoot: File) {
    fun live(livePath: String): File = File(liveRoot, livePath.trimStart('/'))

    fun store(storePath: String): File {
        require(storePath == MoveSet.STORE_ROOT || storePath.startsWith("${MoveSet.STORE_ROOT}/")) {
            MoveSet.Errors.STORE_PATH_INVALID
        }
        val relative = storePath.removePrefix(MoveSet.STORE_ROOT).trimStart('/')
        return if (relative.isEmpty()) storeRoot else File(storeRoot, relative)
    }
}

/** 一次切换计划的稳定摘要（journal 行的 planSha256 字段；02 §3.3）。 */
fun MovePlan.planSha256(): String {
    val canonical = buildString {
        append("v1\n").append(switchId).append('\n').append(from.suffix).append('→').append(to.suffix).append('\n')
        outbound.forEach { append("out:").append(it.livePath).append(':').append(it.owner.suffix).append('\n') }
        inbound.forEach { append("in:").append(it.livePath).append(':').append(it.owner.suffix).append('\n') }
    }
    return Hashes.sha256Hex(canonical)
}

/**
 * 文件系统执行实现。
 *
 * 语义：
 * - 执行顺序由 [MovePlan] 决定（outbound 逆序 / inbound 正序，由 [MoveSet.plan] 生成）；
 * - 每步先写 journal `MOVE_INTENT`（fsync），动作成功写 `MOVE_DONE`，失败写 `FAIL`（A5）；
 * - 同挂载只做 rename（A2 先校验源形态、A3 移动后复核目标在/源消失/类型不变）；
 * - `CROSS_MOUNT_COPY` 走 copy → 读回校验（sha/软链 target/目录结构）→ 删源（A4），
 *   校验失败保留源、删除半目标；
 * - 失败即停（fail-fast），返回 failures 由调用方决定 [rollback]；
 * - [converge] 按"源在/目标在/都在/都不在"四态收敛，两者都在 → `MOVE_AMBIGUOUS`（A6）。
 *
 * 设备差异（不在主机实现内，由 W05/W07/02 的 root 适配器补）：rename 的 SELinux xattr 保留
 * 是内核语义；跨挂载 copy 后的 `chcon`/chown 需要 root shell，本类只保证字节与类型正确。
 */
class FileMoveExecutor(
    private val roots: MovePathRoots,
) : MoveExecutor {

    private sealed interface Step {
        data object Moved : Step
        data object Skipped : Step
        data class Failed(val failure: MoveFailure) : Step
    }

    override fun execute(plan: MovePlan, journal: SwitchJournal): MoveReport {
        val movedOut = mutableListOf<String>()
        val movedIn = mutableListOf<String>()
        val skipped = mutableListOf<String>()
        val failures = mutableListOf<MoveFailure>()

        for (entry in plan.outbound) {
            when (val step = move(plan, journal, entry, forward = true, op = SwitchOp.MOVE_INTENT)) {
                Step.Moved -> movedOut += entry.livePath
                Step.Skipped -> skipped += entry.livePath
                is Step.Failed -> {
                    failures += step.failure
                    return MoveReport(movedOut, movedIn, skipped, failures)
                }
            }
        }
        for (entry in plan.inbound) {
            // inbound 的正向是 store→live：move() 里 forward=false 即 store→live。
            when (val step = move(plan, journal, entry, forward = false, op = SwitchOp.MOVE_INTENT)) {
                Step.Moved -> movedIn += entry.livePath
                Step.Skipped -> skipped += entry.livePath
                is Step.Failed -> {
                    failures += step.failure
                    return MoveReport(movedOut, movedIn, skipped, failures)
                }
            }
        }
        return MoveReport(movedOut, movedIn, skipped, failures)
    }

    override fun rollback(plan: MovePlan, journal: SwitchJournal): MoveReport {
        val movedBack = mutableListOf<String>()
        val skipped = mutableListOf<String>()
        val failures = mutableListOf<MoveFailure>()
        // 逆序：先撤 inbound（live → store），再撤 outbound（store → live）。
        for (entry in plan.inbound.reversed()) {
            when (val step = reverse(plan, journal, entry, forwardWasInbound = true)) {
                Step.Moved -> movedBack += entry.livePath
                Step.Skipped -> skipped += entry.livePath
                is Step.Failed -> failures += step.failure
            }
        }
        for (entry in plan.outbound.reversed()) {
            when (val step = reverse(plan, journal, entry, forwardWasInbound = false)) {
                Step.Moved -> movedBack += entry.livePath
                Step.Skipped -> skipped += entry.livePath
                is Step.Failed -> failures += step.failure
            }
        }
        return MoveReport(emptyList(), movedBack, skipped, failures)
    }

    override fun converge(plan: MovePlan, journal: SwitchJournal): MoveReport {
        val replay = journal.replay(plan.switchId)
        if (replay is JournalReplay.Degraded && replay.code == JournalErrors.SEQ_GAP) {
            return MoveReport(
                emptyList(), emptyList(), emptyList(),
                listOf(MoveFailure("", "RECOVERY_REQUIRED", replay.code)),
            )
        }
        val movedOut = mutableListOf<String>()
        val movedIn = mutableListOf<String>()
        val skipped = mutableListOf<String>()
        val failures = mutableListOf<MoveFailure>()
        val work = plan.outbound.map { it to true } + plan.inbound.map { it to false }
        for ((entry, forward) in work) {
            val live = roots.live(entry.livePath)
            val store = roots.store(MoveSet.storePathFor(entry.owner, entry.livePath))
            val liveExists = exists(live)
            val storeExists = exists(store)
            val step = when {
                liveExists && storeExists && !mergesPreserved(entry,
                    if (forward) live else store, if (forward) store else live) -> Step.Failed(
                    MoveFailure(entry.livePath, MoveSet.Errors.AMBIGUOUS, "live and store both exist"),
                )
                forward && liveExists -> move(plan, journal, entry, forward = true, op = SwitchOp.MOVE_INTENT)
                // inbound 的正向是 store→live：move() 里 forward=false 即 store→live。
                !forward && storeExists -> move(plan, journal, entry, forward = false, op = SwitchOp.MOVE_INTENT)
                else -> Step.Skipped
            }
            when (step) {
                Step.Moved -> if (forward) movedOut += entry.livePath else movedIn += entry.livePath
                Step.Skipped -> skipped += entry.livePath
                is Step.Failed -> failures += step.failure
            }
        }
        return MoveReport(movedOut, movedIn, skipped, failures)
    }

    // ---------------------------------------------------------------- internals

    private fun reverse(
        plan: MovePlan,
        journal: SwitchJournal,
        entry: MoveEntry,
        forwardWasInbound: Boolean,
    ): Step {
        val receipt = roots.live(MoveSet.rollbackReceiptPath(plan.switchId, entry, !forwardWasInbound))
        if (receipt.isFile) return Step.Skipped
        val result = reverseUnrecorded(plan, journal, entry, forwardWasInbound)
        if (result is Step.Failed) return result
        return try {
            Files.createDirectories(receipt.parentFile.toPath())
            FileOutputStream(receipt).use { it.write(1); it.fd.sync() }
            AtomicControlFile.syncDirectory(receipt.parentFile)
            result
        } catch (error: Exception) {
            Step.Failed(MoveFailure(entry.livePath, MoveSet.Errors.VERIFY_FAILED, "rollback receipt"))
        }
    }

    private fun reverseUnrecorded(
        plan: MovePlan,
        journal: SwitchJournal,
        entry: MoveEntry,
        forwardWasInbound: Boolean,
    ): Step {
        val live = roots.live(entry.livePath)
        val store = roots.store(MoveSet.storePathFor(entry.owner, entry.livePath))
        // inbound 正向 store→live ⇒ 反向 live→store；outbound 正向 live→store ⇒ 反向 store→live。
        val source = if (forwardWasInbound) live else store
        val target = if (forwardWasInbound) store else live
        journalOp(journal, plan, SwitchOp.MOVE_BACK, entry.livePath)
        if (!exists(source)) {
            journalOp(journal, plan, SwitchOp.SKIP, entry.livePath, "MOVE_SOURCE_ABSENT")
            return Step.Skipped
        }
        if (exists(target) && !mergesPreserved(entry, source, target)) {
            if (!forwardWasInbound && entry.livePath == "/data/adb/ksud" &&
                source.isFile && !isSymbolicLink(source) && target.isFile && !isSymbolicLink(target) &&
                Hashes.sha256(source) == Hashes.sha256(target)) {
                return try {
                    Files.move(source.toPath(), target.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING)
                    Step.Moved
                } catch (error: Exception) {
                    Step.Failed(MoveFailure(entry.livePath, MoveSet.Errors.RENAME_FAILED, "daemon restore"))
                }
            }
            journalOp(journal, plan, SwitchOp.FAIL, entry.livePath, MoveSet.Errors.DEST_EXISTS)
            return Step.Failed(MoveFailure(entry.livePath, MoveSet.Errors.DEST_EXISTS, target.path))
        }
        return runMove(entry, source, target)
    }

    private fun move(
        plan: MovePlan,
        journal: SwitchJournal,
        entry: MoveEntry,
        forward: Boolean,
        op: SwitchOp,
    ): Step {
        val live = roots.live(entry.livePath)
        val store = roots.store(MoveSet.storePathFor(entry.owner, entry.livePath))
        val source = if (forward) live else store
        val target = if (forward) store else live
        // A5：intent 先落盘（journal.append 内部 fsync）。
        journalOp(journal, plan, op, entry.livePath)
        if (!exists(source)) {
            journalOp(journal, plan, SwitchOp.SKIP, entry.livePath, "MOVE_SOURCE_ABSENT")
            return Step.Skipped
        }
        if (exists(target) && !mergesPreserved(entry, source, target)) {
            journalOp(journal, plan, SwitchOp.FAIL, entry.livePath, MoveSet.Errors.DEST_EXISTS)
            return Step.Failed(MoveFailure(entry.livePath, MoveSet.Errors.DEST_EXISTS, target.path))
        }
        // A2：rename 前按 expectedShape 校验源（形态不符 → 阻断，不许静默 rm）。
        shapeMismatch(source, entry.expectedShape)?.let { detail ->
            journalOp(journal, plan, SwitchOp.FAIL, entry.livePath, MoveSet.Errors.SOURCE_SHAPE_MISMATCH)
            return Step.Failed(MoveFailure(entry.livePath, MoveSet.Errors.SOURCE_SHAPE_MISMATCH, detail))
        }
        val step = runMove(entry, source, target)
        // A5：动作成功 → MOVE_DONE；失败已由 runMove 返回 FAIL 语义（code 由调用方落 evidence）。
        if (step == Step.Moved) journalOp(journal, plan, SwitchOp.MOVE_DONE, entry.livePath)
        return step
    }

    private fun runMove(entry: MoveEntry, source: File, target: File): Step {
        if (mergesPreserved(entry, source, target)) return mergePreserved(entry, source, target)
        val sourceIsLink = isSymbolicLink(source)
        val sourceIsDir = source.isDirectory
        val step: Step = try {
            if (entry.mount == MoveMount.CROSS_MOUNT_COPY) {
                copyVerified(source, target)
                deleteTree(source)
            } else {
                target.parentFile?.let { parent ->
                    if (!parent.exists() && !parent.mkdirs()) throw IOException("MOVE_PARENT_INVALID")
                }
                try {
                    Files.move(source.toPath(), target.toPath())
                } catch (error: IOException) {
                    // A1：同挂载 rename 失败不得静默降级为 copy。
                    val code = if (isCrossDevice(error)) MoveSet.Errors.EXDEV_UNSUPPORTED
                    else MoveSet.Errors.RENAME_FAILED
                    throw MoveStepFailure(code, error.message.orEmpty())
                }
            }
            // A3：目标在 + 源消失 + 类型不变。
            if (!exists(target) || exists(source)) {
                throw MoveStepFailure(MoveSet.Errors.VERIFY_FAILED, "post-move state")
            }
            if (isSymbolicLink(target) != sourceIsLink ||
                (!sourceIsLink && target.isDirectory != sourceIsDir)
            ) {
                throw MoveStepFailure(MoveSet.Errors.VERIFY_FAILED, "post-move type changed")
            }
            Step.Moved
        } catch (failure: MoveStepFailure) {
            runCatching { if (exists(target) && !exists(source)) deleteTree(target) }
            Step.Failed(MoveFailure(entry.livePath, failure.code, failure.detail))
        } catch (error: Exception) {
            Step.Failed(MoveFailure(entry.livePath, MoveSet.Errors.VERIFY_FAILED, error.message.orEmpty()))
        }
        return step
    }

    private fun mergesPreserved(entry: MoveEntry, source: File, target: File): Boolean =
        source.isDirectory && !isSymbolicLink(source) &&
            (!exists(target) || (target.isDirectory && !isSymbolicLink(target))) &&
            MoveSet.preservedPathsUnder(entry.livePath).any { exists(roots.live(it)) }

    /** Keep the shared installer lock at its live path while moving the other children. */
    private fun mergePreserved(entry: MoveEntry, source: File, target: File): Step = try {
        val live = roots.live(entry.livePath)
        val protected = MoveSet.preservedPathsUnder(entry.livePath).map { roots.live(it) }
        val held = protected.filter { exists(it) }
        val children = source.listFiles().orEmpty().filter { child ->
            source != live || protected.none { it == child }
        }.toMutableList()
        if (source != live) {
            for (path in listOf(MoveSet.RECOVERY_ROOT, MoveSet.NORMAL_RECOVERY_TOKEN, MoveSet.HIDDEN_STATE)) {
                val shared = roots.live(path)
                if (shared !in protected || !exists(shared)) continue
                val legacy = children.firstOrNull { it.name == shared.name } ?: continue
                val archiveRoot = roots.live(MoveSet.LEGACY_RECOVERY_ROOT)
                Files.createDirectories(archiveRoot.toPath())
                val archive = Files.createTempDirectory(archiveRoot.toPath(), "${entry.owner.suffix}.")
                Files.move(legacy.toPath(), archive.resolve(shared.name))
                children.remove(legacy)
            }
        }
        if (children.any { exists(File(target, it.name)) }) {
            throw MoveStepFailure(MoveSet.Errors.DEST_EXISTS, "conflicting child")
        }
        if (!target.isDirectory && !target.mkdirs()) {
            throw MoveStepFailure(MoveSet.Errors.RENAME_FAILED, "target directory")
        }
        for (child in children) {
            val childEntry = entry.copy(livePath = "${entry.livePath}/${child.name}")
            when (val moved = runMove(childEntry, child, File(target, child.name))) {
                is Step.Failed -> throw MoveStepFailure(moved.failure.code, moved.failure.detail)
                else -> Unit
            }
        }
        if (held.any { !exists(it) }) {
            throw MoveStepFailure(MoveSet.Errors.VERIFY_FAILED, "protected subtree missing")
        }
        if (source.listFiles().orEmpty().any { child -> source != live || protected.none { it == child } }) {
            throw MoveStepFailure(MoveSet.Errors.VERIFY_FAILED, "source remains")
        }
        source.delete() // Empty store shells disappear; a live directory with its lock stays.
        Step.Moved
    } catch (failure: MoveStepFailure) {
        Step.Failed(MoveFailure(entry.livePath, failure.code, failure.detail))
    } catch (error: Exception) {
        Step.Failed(MoveFailure(entry.livePath, MoveSet.Errors.VERIFY_FAILED, error.message.orEmpty()))
    }

    private fun journalOp(
        journal: SwitchJournal,
        plan: MovePlan,
        op: SwitchOp,
        livePath: String,
        code: String = "",
    ) {
        journal.append(
            switchId = plan.switchId,
            planSha256 = plan.planSha256(),
            stage = "S4",
            step = "4b",
            op = op,
            partition = "",
            // 02 §3.3 固定字段集没有路径字段；把路径附在 code 前缀，仅用于取证可读性。
            code = if (code.isEmpty()) "" else MoveSet.redactEvidence("$code:$livePath"),
        )
    }

    /** 源形态校验：null = 匹配；否则返回不匹配描述。 */
    private fun shapeMismatch(source: File, expectedShape: String): String? = when (expectedShape) {
        MoveEntry.REAL_DIR, MoveEntry.REAL_DIR_EMPTY -> when {
            !source.isDirectory -> "expected dir"
            isSymbolicLink(source) -> "expected real dir, found symlink"
            else -> null
        }
        MoveEntry.SYMLINK -> if (!isSymbolicLink(source)) "expected symlink" else null
        MoveEntry.SYMLINK_TREE -> if (!source.isDirectory) "expected dir tree" else null
        MoveEntry.FILE -> when {
            !source.isFile -> "expected file"
            isSymbolicLink(source) -> "expected real file, found symlink"
            else -> null
        }
        MoveEntry.ABSENT -> if (exists(source)) "expected absent" else null
        else -> "unknown expected shape: $expectedShape"
    }

    /** copy → 读回校验（sha / 软链 target / 目录结构）→ 删源（A4）。失败保留源。 */
    private fun copyVerified(source: File, target: File) {
        try {
            val entries = collectEntries(source)
            target.parentFile?.let { parent ->
                if (!parent.exists() && !parent.mkdirs()) throw IOException("MOVE_PARENT_INVALID")
            }
            entries.forEach { (relative, fingerprint) ->
                val destination = File(target, relative)
                when (fingerprint.kind) {
                    EntryKind.DIR -> if (!destination.exists() && !destination.mkdirs()) {
                        throw IOException(MoveSet.Errors.COPY_VERIFY_FAILED)
                    }
                    EntryKind.SYMLINK -> {
                        destination.parentFile?.mkdirs()
                        Files.createSymbolicLink(destination.toPath(), File(fingerprint.linkTarget!!).toPath())
                    }
                    EntryKind.FILE -> {
                        destination.parentFile?.mkdirs()
                        val sourceFile = File(source, relative)
                        FileOutputStream(destination).use { output ->
                            sourceFile.inputStream().use { it.copyTo(output) }
                            output.flush()
                            output.fd.sync()
                        }
                        if (Hashes.sha256(destination.readBytes()) != fingerprint.sha256) {
                            throw IOException(MoveSet.Errors.COPY_VERIFY_FAILED)
                        }
                    }
                }
            }
            // 结构复核：每个源条目在目标侧存在且类型/sha/target 一致。
            entries.forEach { (relative, fingerprint) ->
                val destination = File(target, relative)
                val ok = when (fingerprint.kind) {
                    EntryKind.DIR -> destination.isDirectory
                    EntryKind.SYMLINK -> isSymbolicLink(destination) &&
                        Files.readSymbolicLink(destination.toPath()).toString() == fingerprint.linkTarget
                    EntryKind.FILE -> destination.isFile && !isSymbolicLink(destination) &&
                        Hashes.sha256(destination.readBytes()) == fingerprint.sha256
                }
                if (!ok) throw IOException(MoveSet.Errors.COPY_VERIFY_FAILED)
            }
        } catch (failure: MoveStepFailure) {
            runCatching { if (exists(target)) deleteTree(target) }
            throw failure
        } catch (error: Exception) {
            runCatching { if (exists(target)) deleteTree(target) }
            throw MoveStepFailure(
                if (error is IOException) MoveSet.Errors.COPY_VERIFY_FAILED else MoveSet.Errors.COPY_VERIFY_FAILED,
                error.message.orEmpty(),
            )
        }
    }

    private enum class EntryKind { DIR, FILE, SYMLINK }

    private data class EntryFingerprint(
        val kind: EntryKind,
        val sha256: String = "",
        val linkTarget: String? = null,
    )

    private fun collectEntries(root: File): Map<String, EntryFingerprint> {
        val result = linkedMapOf<String, EntryFingerprint>()
        val rootPath = root.toPath()
        Files.walk(rootPath).use { stream ->
            val iterator = stream.iterator()
            while (iterator.hasNext()) {
                val path = iterator.next()
                if (path == rootPath) continue
                val relative = rootPath.relativize(path).toString().replace(File.separatorChar, '/')
                when {
                    Files.isSymbolicLink(path) -> result[relative] = EntryFingerprint(
                        EntryKind.SYMLINK, linkTarget = Files.readSymbolicLink(path).toString(),
                    )
                    Files.isDirectory(path) -> result[relative] = EntryFingerprint(EntryKind.DIR)
                    Files.isRegularFile(path) -> result[relative] = EntryFingerprint(
                        EntryKind.FILE, sha256 = Hashes.sha256(Files.readAllBytes(path)),
                    )
                }
            }
        }
        return result
    }

    private fun exists(file: File): Boolean =
        runCatching { Files.exists(file.toPath(), LinkOption.NOFOLLOW_LINKS) }.getOrDefault(false)

    private fun isSymbolicLink(file: File): Boolean =
        runCatching { Files.isSymbolicLink(file.toPath()) }.getOrDefault(false)

    private fun isCrossDevice(error: IOException): Boolean {
        val message = error.message.orEmpty().lowercase()
        return message.contains("exdev") || message.contains("cross-device") ||
            message.contains("different disk") || message.contains("different file system")
    }

    private fun deleteTree(file: File) {
        if (!exists(file)) return
        Files.walk(file.toPath()).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach { path ->
                runCatching { Files.deleteIfExists(path) }
            }
        }
    }

    private class MoveStepFailure(val code: String, val detail: String) : IOException("$code: $detail")

    /** 诊断/测试：返回该条目在 live/store 两侧的存在性。 */
    fun presence(entry: MoveEntry): Pair<Boolean, Boolean> =
        exists(roots.live(entry.livePath)) to exists(roots.store(MoveSet.storePathFor(entry.owner, entry.livePath)))
}
