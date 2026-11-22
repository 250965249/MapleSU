package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.workmode.switch.SwitchStateNames
import dev.maplesu.manager.workmode.switch.ModeSwitchPreflight

import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootCapability
import dev.maplesu.manager.runtime.RootExecResult
import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.switch.AvbFacts
import dev.maplesu.manager.workmode.switch.BaselineManifest
import dev.maplesu.manager.workmode.switch.BaselinePartition
import dev.maplesu.manager.workmode.switch.CandidateResult
import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import dev.maplesu.manager.workmode.switch.PatchMarkers
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger

// 脚本 marker 是客户端与"设备 shell"之间的协议；测试重复字面量以便 marker 改名时立即失败。
private const val SWITCH_ID = "switch-1"
private const val ROOT = "#maplesu:preflight-root"
private const val SLOT = "#maplesu:preflight-slot"
private const val DEVICE = "#maplesu:preflight-device:"
private const val FREE = "#maplesu:preflight-free"
private const val WRITABLE = "#maplesu:preflight-writable"
private const val PLAN_WRITE = "#maplesu:begin-plan"
private const val STATE_WRITE = "#maplesu:state-write"
private const val STATE_READ = "#maplesu:state-read"
private const val SNAPSHOT_PRE = "#maplesu:snapshot-pre:"
private const val BASELINE_COPY = "#maplesu:baseline-copy"
private const val SOURCE_IMPORT = "#maplesu:source-import"
private const val SUBMIT_COPY = "#maplesu:submit-copy"
private const val COMMIT_CHECK = "#maplesu:commit-check:"
private const val COMMIT_WRITE = "#maplesu:commit-write"
private const val RESTORE_WRITE = "#maplesu:restore-write"
private const val ROLLBACK_WRITE = "#maplesu:rollback-write"
private const val EXPORT = "#maplesu:export"
private const val VERIFY = "#maplesu:verify"
private const val ABORT = "#maplesu:abort-clean"
private const val LIST_TX = "#maplesu:list-tx"

private val WRITE_COMMANDS = listOf("dd ", "mkdir ", "mv -f", "chmod ", "cp -f", "rm -rf", "printf ")

/**
 * Ultra 根通道切换客户端的主机（纯 JVM）测试。
 *
 * 约束：
 * - 绝不执行真实 root/分区命令：所有脚本进 [FakeRunner]，按脚本首行 marker 分派；
 * - 断言两级：**(a) 参数化脚本字符串**（路径单引号、dd 目标唯一、写前校验不写），
 *   **(b) 返回值/状态机**（ClientResult.code、ClientStatus.state）；
 * - 落盘的 state.json 内容通过 `persistedState()` 从 STATE_WRITE 脚本里的 JSON 还原
 *   （FakeRunner 不真正写文件，但脚本里带着完整 JSON 载荷）。
 */
class UltraRootModeSwitchClientTest {

    private val roots = mutableListOf<File>()

    @After
    fun cleanup() {
        roots.forEach { runCatching { it.deleteRecursively() } }
    }

    // ------------------------------------------------------------------ fixtures

    private class FakeRunner : (String) -> RootExecResult {
        private val handlers = LinkedHashMap<String, (String) -> RootExecResult>()
        val scripts = mutableListOf<String>()

        fun on(marker: String, block: (String) -> RootExecResult) {
            handlers[marker] = block
        }

        fun on(marker: String, output: String, code: Int = 0) {
            on(marker) { RootExecResult(RootBackend.ULTRA_ENV, code, output) }
        }

        fun fail(marker: String, code: Int = 1) {
            on(marker) { RootExecResult(RootBackend.ULTRA_ENV, code, "") }
        }

        override fun invoke(script: String): RootExecResult {
            scripts += script
            val line = script.lineSequence().firstOrNull().orEmpty()
            handlers[line]?.let { return it(script) }
            return handlers.entries
                .filter { line.startsWith(it.key) }
                .maxByOrNull { it.key.length }
                ?.value
                ?.invoke(script)
                ?: RootExecResult(RootBackend.ULTRA_ENV, 0, "")
        }

        fun withMarker(marker: String): List<String> =
            scripts.filter { it.lineSequence().firstOrNull() == marker }

        fun withPrefix(prefix: String): List<String> =
            scripts.filter { it.lineSequence().firstOrNull()?.startsWith(prefix) == true }

        fun writeScripts(): List<String> = scripts.filter { script ->
            WRITE_COMMANDS.any { script.contains(it) }
        }
    }

    private data class RecoveryCall(val from: WorkMode, val partition: String,
                                    val input: File, val outputDir: File, val sourceKnown: Boolean)

    private class Harness(val root: File, val requireBaselineForCommit: Boolean = false,
                          val withRecovery: Boolean = false) {
        val workRoot = File(root, "work").apply { mkdirs() }
        val appRoot = File(root, "app").apply { mkdirs() }
        val baselineRoot = File(workRoot, "boot/baseline")
        val mirrorDir = File(root, "mirrors").apply { mkdirs() }
        val outDir = File(appRoot, "out").apply { mkdirs() }

        var size = 4096L

        /** init_boot 的 PRE 快照摘要（目标分区）。 */
        var preSha: String = "a".repeat(64)

        /** boot 的 PRE 快照摘要（源分区，切换前带 LITE 补丁）。 */
        var sourceSha: String = "b".repeat(64)

        /** init_boot 的候选摘要（submitCandidate 时更新）。 */
        var targetSha: String = "c".repeat(64)

        /** 基线清单里 boot / init_boot 的摘要（空 = 该分区无基线 sha）。 */
        var bootBaselineSha: String = ""
        var initBootBaselineSha: String = ""

        /** 还原 dd 的回读摘要覆盖（空 = 用被还原分区的基线摘要）。 */
        var restoreWriteSha: String = ""

        var bootId: String = "boot-1"
        var toMode = WorkMode.KSU
        var requestedTarget: String? = null
        var requestedSource: String? = null
        val targetPartition get() = requestedTarget ?: if (toMode == WorkMode.KSU) "init_boot" else "boot"
        val logs = mutableListOf<String>()
        val bootBytes = ByteArray(4096) { 3 }
        val initBootBytes = ByteArray(4096) { 5 }
        val recoveredBytes = ByteArray(4096) { 11 }
        val recoveredSha = Hashes.sha256(recoveredBytes)
        val recoveredShas = mutableMapOf<String, String>()
        val recoveryCalls = mutableListOf<RecoveryCall>()
        var recovery: (RecoveryCall) -> CandidateResult = { call -> recovered(call) }
        var exportedBytes: ByteArray? = null

        val runner = FakeRunner()
        val client: UltraRootModeSwitchClient

        init {
            if (withRecovery) {
                sourceSha = Hashes.sha256(bootBytes)
                preSha = Hashes.sha256(initBootBytes)
            }
            client = UltraRootModeSwitchClient(
                runner = runner,
                workRoot = workRoot,
                logger = { logs += it },
                destinationRoots = listOf(appRoot),
                baselineRoot = baselineRoot,
                clock = { 1_000L },
                bootIdSource = { bootId },
                requireBaselineForCommit = requireBaselineForCommit,
                sourceRecovery = if (withRecovery) { from, partition, input, outputDir, known ->
                    RecoveryCall(from, partition, input, outputDir, known).let { call ->
                        recoveryCalls += call
                        recovery(call)
                    }
                } else null,
            )
            runner.on(ROOT, "0\n")
            runner.on(SLOT, "_a\n")
            runner.on(DEVICE + "boot", "dev=/dev/block/by-name/boot_a\nsize=$size\n")
            runner.on(DEVICE + "init_boot", "dev=/dev/block/by-name/init_boot_a\nsize=$size\n")
            runner.on(FREE, "${64L * 1024 * 1024}\n")
            runner.on(WRITABLE, "1\n")
            // 每个计划分区各一次 PRE dd（源 + 目标）。
            runner.on(SNAPSHOT_PRE + "boot") {
                RootExecResult(RootBackend.ULTRA_ENV, 0, "$sourceSha  /dev/block/by-name/boot_a\n$size\n")
            }
            runner.on(SNAPSHOT_PRE + "init_boot") {
                RootExecResult(RootBackend.ULTRA_ENV, 0, "$preSha  /dev/block/by-name/init_boot_a\n$size\n")
            }
            // 写前本地复核（candidate / pre:<name> / base:<name>），按镜像文件名分派。
            runner.on(COMMIT_CHECK) { script ->
                RootExecResult(RootBackend.ULTRA_ENV, 0, commitCheckOutput(script))
            }
            // 基线镜像复制（cp + sha256sum）；回读 sha 必须等于清单记录。
            runner.on(BASELINE_COPY) { script ->
                val sha = when {
                    script.contains("base-init_boot.img") -> initBootBaselineSha
                    script.contains("base-boot.img") -> bootBaselineSha
                    else -> ""
                }
                RootExecResult(RootBackend.ULTRA_ENV, 0, "$sha  /img\n")
            }
            runner.on(SUBMIT_COPY) { RootExecResult(RootBackend.ULTRA_ENV, 0, "$targetSha  /candidate\n") }
            runner.on(SOURCE_IMPORT) { script ->
                val source = File(Regex("cp -f '([^']+)'").find(script)!!.groupValues[1])
                val destination = File(Regex("sha256sum '([^']+)'").find(script)!!.groupValues[1])
                val bytes = source.readBytes()
                destination.parentFile.mkdirs()
                destination.writeBytes(bytes)
                val sha = Hashes.sha256(bytes)
                recoveredShas[if (destination.name == "base-boot.img") "boot" else "init_boot"] = sha
                RootExecResult(RootBackend.ULTRA_ENV, 0, "$sha  /base\n${bytes.size}\n")
            }
            runner.on(RESTORE_WRITE) { script ->
                val sha = restoreWriteSha.ifEmpty {
                    val partition = if (script.contains("of='/dev/block/by-name/init_boot_a'")) "init_boot" else "boot"
                    recoveredShas[partition] ?: if (partition == "init_boot") initBootBaselineSha else bootBaselineSha
                }
                RootExecResult(RootBackend.ULTRA_ENV, 0, "$sha  /dev\n")
            }
            runner.on(COMMIT_WRITE) {
                RootExecResult(RootBackend.ULTRA_ENV, 0, "$targetSha  /dev/block/by-name/${targetPartition}_a\n")
            }
            runner.on(ROLLBACK_WRITE) { script ->
                val sha = if (script.contains("of='/dev/block/by-name/boot_a'")) sourceSha else preSha
                RootExecResult(RootBackend.ULTRA_ENV, 0, "$sha  /dev\n")
            }
            runner.on(VERIFY) { script ->
                val sha = if (script.contains("'/dev/block/by-name/boot_a'")) {
                    if (targetPartition == "boot") targetSha else recoveredShas["boot"] ?: bootBaselineSha.ifEmpty { sourceSha }
                } else if (targetPartition == "init_boot") targetSha else recoveredShas["init_boot"] ?: initBootBaselineSha
                RootExecResult(RootBackend.ULTRA_ENV, 0, "$sha  /dev\n")
            }
            runner.on(EXPORT) { script ->
                if (withRecovery && script.contains("cp -f ")) {
                    val destination = File(Regex("sha256sum '([^']+)'").find(script)!!.groupValues[1])
                    val bytes = exportedBytes ?: when {
                        script.contains("base-") -> recoveredBytes
                        script.contains("pre-boot.img") -> bootBytes
                        else -> initBootBytes
                    }
                    destination.parentFile.mkdirs()
                    destination.writeBytes(bytes)
                }
                val sha = when {
                    script.contains("candidate-init_boot") || script.contains("candidate-boot") -> targetSha
                    script.contains("base-init_boot") -> recoveredShas["init_boot"] ?: initBootBaselineSha
                    script.contains("base-boot") -> recoveredShas["boot"] ?: bootBaselineSha
                    script.contains("pre-boot") -> sourceSha
                    else -> preSha
                }
                RootExecResult(RootBackend.ULTRA_ENV, 0, "$sha  /out\n")
            }
        }

        fun recovered(call: RecoveryCall): CandidateResult {
            call.outputDir.mkdirs()
            val image = File(call.outputDir, "source-base.img").apply { writeBytes(recoveredBytes) }
            return CandidateResult(image, recoveredSha, image.length(), structureEvidence = "source-only-recovery")
        }

        /** 写前复核输出：大小 + 镜像 sha（按脚本里的镜像文件名判定是哪一个）。 */
        fun commitCheckOutput(script: String): String {
            val sha = when {
                script.contains("base-init_boot.img") -> recoveredShas["init_boot"] ?: initBootBaselineSha.ifEmpty { preSha }
                script.contains("base-boot.img") -> recoveredShas["boot"] ?: bootBaselineSha.ifEmpty { sourceSha }
                script.contains("pre-init_boot.img") -> preSha
                script.contains("pre-boot.img") -> sourceSha
                script.contains("candidate-init_boot.img") || script.contains("candidate-boot.img") -> targetSha
                else -> ""
            }
            return "$size\n$sha  /img\n"
        }

        /**
         * 从最后一次 `state-write` 脚本里还原 state.json 的 JSON 载荷。
         *
         * 为什么不用真文件：FakeRunner 不执行 shell，`persist` 只更新内存缓存；
         * 但脚本里带着完整 JSON（`printf '%s' '<json>'`），足以断言 images/preSize 等字段。
         */
        fun persistedState(): UltraSwitchStateFile? {
            val script = runner.withMarker(STATE_WRITE).lastOrNull() ?: return null
            val marker = "printf '%s' "
            val at = script.indexOf(marker)
            if (at < 0) return null
            val contentStart = at + marker.length + 1
            val end = script.indexOf("' > '", contentStart)
            if (end < 0) return null
            val payload = script.substring(contentStart, end).replace("'\\''", "'")
            return ControlJsonCodec.decodeOrNull<UltraSwitchStateFile>(payload)
        }

        fun txDir(switchId: String): File = File(File(workRoot, "tx"), switchId)

        fun stateFile(switchId: String): File = File(txDir(switchId), "state.json")

        fun planFile(switchId: String): File = File(txDir(switchId), "plan.json")

        fun journalFile(switchId: String): File = File(txDir(switchId), "journal.jsonl")

        fun ensureTx(switchId: String): File = txDir(switchId).apply { mkdirs() }

        fun mirrors(): Pair<File, File> {
            val superuser = File(mirrorDir, "superuser.json").apply { writeText("{\"schema\":1}") }
            val settings = File(mirrorDir, "settings.json").apply { writeText("{\"schema\":1}") }
            return superuser to settings
        }

        fun planFields(baselineId: String = ""): Map<String, String> = mapOf(
            "fromMode" to (if (toMode == WorkMode.KSU) WorkMode.LITE else WorkMode.KSU).name,
            "toMode" to toMode.name,
            "baselineId" to baselineId,
        ) + requestedTarget?.let { mapOf("targetPartition" to it) }.orEmpty() +
            requestedSource?.let { mapOf("sourcePartition" to it) }.orEmpty()
    }

    private fun harness(requireBaselineForCommit: Boolean = false, withRecovery: Boolean = false): Harness {
        val root = Files.createTempDirectory("maplesu-ultra-switch-").toFile()
        roots += root
        return Harness(root, requireBaselineForCommit, withRecovery)
    }

    @Test
    fun bootOnlyDeviceNormalInstallationResolvesBootAndSnapshotsOnlyBoot() {
        val h = harness()
        h.runner.fail(DEVICE + "init_boot")
        beginOk(h)
        assertEquals("boot", h.persistedState()!!.targetPartition)
        assertEquals(listOf("boot"), h.persistedState()!!.partitions.map { it.name })
    }

    @Test
    fun normalInstalledInBootReturnsToUltraWithoutRequiringInitBoot() {
        val h = harness()
        h.toMode = WorkMode.LITE
        h.requestedSource = "boot"
        h.runner.fail(DEVICE + "init_boot")
        beginOk(h)
        assertEquals(listOf("boot"), h.persistedState()!!.partitions.map { it.name })
    }

    @Test
    fun knownBootSourceUsesOnlyBootEvenWhenInitBootExists() {
        val h = harness()
        h.toMode = WorkMode.LITE
        h.requestedSource = "boot"
        beginOk(h)
        assertEquals("boot", h.persistedState()!!.sourcePartition)
        assertEquals(listOf("boot"), h.persistedState()!!.partitions.map { it.name })
    }

    @Test
    fun sourceCarrierIsRecoveredFromVerifiedPlanOnTheSameSlot() {
        val h = harness()
        val previous = "00000000-0000-0000-0000-000000000010"
        writeState(h, previous, SwitchStateNames.VERIFIED)
        val plan = ControlJsonCodec.decodeOrNull<UltraSwitchPlanFile>(h.planFile(previous).readText())!!
        h.planFile(previous).writeText(ControlJsonCodec.encode(plan.copy(targetPartition = "boot",
            partitions = listOf(UltraSwitchPlanPartition("boot", "WRITE_CANDIDATE", "/dev/block/by-name/boot_a", h.size)))))
        val state = ControlJsonCodec.decodeOrNull<UltraSwitchStateFile>(h.stateFile(previous).readText())!!
        h.stateFile(previous).writeText(ControlJsonCodec.encode(state.copy(targetPartition = "boot")))
        h.toMode = WorkMode.LITE
        beginOk(h)
        assertEquals("boot", h.persistedState()!!.sourcePartition)
        assertEquals(listOf("boot"), h.persistedState()!!.partitions.map { it.name })
    }

    @Test
    fun sourceCarrierFromAnotherSlotRemainsUnknown() {
        val h = harness()
        val previous = "00000000-0000-0000-0000-000000000010"
        writeState(h, previous, SwitchStateNames.VERIFIED)
        val plan = ControlJsonCodec.decodeOrNull<UltraSwitchPlanFile>(h.planFile(previous).readText())!!
        h.planFile(previous).writeText(ControlJsonCodec.encode(plan.copy(slotSuffix = "_b")))
        h.toMode = WorkMode.LITE
        beginOk(h)
        assertEquals("", h.persistedState()!!.sourcePartition)
        assertEquals(listOf("init_boot", "boot"), h.persistedState()!!.partitions.map { it.name })
    }

    @Test
    fun oldPlanWithoutSourceCarrierKeepsItsLegacySemantics() {
        val raw = """{"switchId":"$SWITCH_ID","fromMode":"KSU","toMode":"LITE","targetPartition":"boot"}"""
        val plan = ControlJsonCodec.decodeOrNull<UltraSwitchPlanFile>(raw)!!
        assertEquals(null, plan.sourcePartition)
        assertEquals(listOf("init_boot", "boot"), ModeSwitchPreflight.writeOrder(WorkMode.LITE,
            plan.targetPartition, plan.sourcePartition))
    }

    @Test
    fun unknownSourceUsesExistingSnapshotsAndLeavesAnUnchangedInitBootUnwritten() {
        val h = harness()
        h.toMode = WorkMode.LITE
        baselineManifest(h, "b1", bootSha = "d".repeat(64), initBootSha = h.preSha)
        beginOk(h, baselineId = "b1")
        assertEquals("", h.persistedState()!!.sourcePartition)
        snapshotOk(h)
        assertEquals("boot", h.persistedState()!!.sourcePartition)
        assertFalse(h.persistedState()!!.partitions.first { it.name == "init_boot" }.restoreRequired)
        submitOk(h)
        commitOk(h)
        assertEquals(listOf("write"), writeOrderOf(h))
    }

    private fun preflightOk(h: Harness, id: String = SWITCH_ID, baselineId: String = "") {
        val result = runBlocking { h.client.preflight(id, h.planFields(baselineId)) }
        assertTrue("preflight: ${result.code} ${result.detail}", result.ok)
    }

    private fun beginOk(h: Harness, id: String = SWITCH_ID, baselineId: String = "") {
        preflightOk(h, id, baselineId)
        val (superuser, settings) = h.mirrors()
        val result = runBlocking { h.client.begin(id, h.planFields(baselineId), superuser, settings) }
        assertTrue("begin: ${result.code} ${result.detail}", result.ok)
    }

    private fun snapshotOk(h: Harness, id: String = SWITCH_ID) {
        val result = runBlocking { h.client.snapshot(id) }
        assertTrue("snapshot: ${result.code} ${result.detail}", result.ok)
    }

    private fun submitOk(h: Harness, id: String = SWITCH_ID, bytes: ByteArray = ByteArray(4096) { 7 }): String {
        val file = File(h.mirrorDir, "candidate.img").apply { writeBytes(bytes) }
        val sha = Hashes.sha256(bytes)
        h.targetSha = sha
        val result = runBlocking { h.client.submitCandidate(id, h.targetPartition, file, sha) }
        assertTrue("submit: ${result.code} ${result.detail}", result.ok)
        return sha
    }

    private fun commitOk(h: Harness, id: String = SWITCH_ID): ClientResult {
        val result = runBlocking { h.client.commit(id) }
        assertTrue("commit: ${result.code} ${result.detail}", result.ok)
        return result
    }

    private fun fullFlow(h: Harness, baselineId: String = ""): String {
        beginOk(h, baselineId = baselineId)
        snapshotOk(h)
        submitOk(h)
        return SWITCH_ID
    }

    /** 所有"写分区"脚本的调用顺序（restore/write），用于断言写序。 */
    private fun writeOrderOf(h: Harness): List<String> = h.runner.scripts.mapNotNull { script ->
        when (script.lineSequence().firstOrNull()) {
            RESTORE_WRITE -> "restore"
            COMMIT_WRITE -> "write"
            else -> null
        }
    }

    private fun writeState(h: Harness, id: String, state: String, images: Map<String, String> = emptyMap(),
                           preSha: String = "", targetSha: String = "", bootId: String = "boot-1") {
        h.ensureTx(id)
        val plan = UltraSwitchPlanFile(
            switchId = id,
            fromMode = "LITE",
            toMode = "KSU",
            slotSuffix = "_a",
            targetPartition = "init_boot",
            partitions = listOf(
                UltraSwitchPlanPartition("init_boot", "WRITE_CANDIDATE", "/dev/block/by-name/init_boot_a", h.size),
                UltraSwitchPlanPartition("boot", "RESTORE_BASELINE", "/dev/block/by-name/boot_a", h.size),
            ),
        )
        val stateFile = UltraSwitchStateFile(
            switchId = id,
            state = state,
            stage = "S4",
            step = "4g",
            fromMode = "LITE",
            toMode = "KSU",
            planSha256 = "d".repeat(64),
            startBootId = bootId,
            targetPartition = "init_boot",
            partitions = listOf(
                UltraSwitchPartitionState(
                    "boot", "RESTORE_BASELINE", "/dev/block/by-name/boot_a", h.size,
                    preSha256 = "e".repeat(64),
                ),
                UltraSwitchPartitionState(
                    "init_boot", "WRITE_CANDIDATE", "/dev/block/by-name/init_boot_a", h.size,
                    preSha256 = preSha, targetSha256 = targetSha,
                ),
            ),
            images = images,
        )
        h.planFile(id).writeText(ControlJsonCodec.encode(plan))
        h.stateFile(id).writeText(ControlJsonCodec.encode(stateFile))
    }

    private fun baselineManifest(h: Harness, id: String = "b1", bootSha: String = "", initBootSha: String = ""): File {
        h.bootBaselineSha = bootSha
        h.initBootBaselineSha = initBootSha
        val partitions = buildList {
            if (bootSha.isNotEmpty()) add(BaselinePartition("boot", h.size, bootSha, true))
            if (initBootSha.isNotEmpty()) add(BaselinePartition("init_boot", h.size, initBootSha, true))
        }
        val manifest = BaselineManifest(
            id = id,
            createdAt = 1L,
            provenance = "OEM_PACKAGE",
            clean = true,
            verifiedAt = 1L,
            slot = "_a",
            firmware = "fw",
            kernelRelease = "5.10.0-android13-8-g",
            partitions = partitions,
            avb = AvbFacts(vbmetaPresent = false, verificationDisabled = false),
            patchMarkers = PatchMarkers(),
        )
        val dir = File(h.baselineRoot, id).apply { mkdirs() }
        val file = File(dir, "manifest.json")
        file.writeText(ControlJsonCodec.encode(manifest))
        return file
    }

    private fun quoted(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    private fun assertContains(haystack: String, needle: String) {
        assertTrue("missing <$needle> in:\n$haystack", haystack.contains(needle))
    }

    private fun assertNotContains(haystack: String, needle: String) {
        assertFalse("unexpected <$needle> in:\n$haystack", haystack.contains(needle))
    }

    // ------------------------------------------------------------------ preflight

    @Test
    fun preflightRejectsInjectedSwitchIdWithoutRunningAnyCommand() {
        val h = harness()
        val result = runBlocking { h.client.preflight("a'; rm -rf /", h.planFields()) }
        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.PLAN_INVALID, result.code)
        assertTrue(h.runner.scripts.isEmpty())
    }

    @Test
    fun preflightRejectsRelativeWorkRoot() {
        val root = Files.createTempDirectory("maplesu-ultra-switch-relative-").toFile()
        roots += root
        val client = UltraRootModeSwitchClient(
            runner = { RootExecResult(RootBackend.ULTRA_ENV, 0, "0") },
            workRoot = File("relative-work-root"),
            destinationRoots = listOf(root),
        )
        val result = runBlocking {
            client.preflight(SWITCH_ID, mapOf("fromMode" to "LITE", "toMode" to "KSU", "baselineId" to ""))
        }
        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.CONTROL_DIR_INVALID, result.code)
    }

    @Test
    fun preflightRejectsUnknownAndSameModes() {
        val h = harness()
        val unknown = runBlocking {
            h.client.preflight(SWITCH_ID, mapOf("fromMode" to "LITE", "toMode" to "KSUU", "baselineId" to ""))
        }
        assertEquals(ModeSwitchCodes.PLAN_INVALID, unknown.code)
        val same = runBlocking {
            h.client.preflight(SWITCH_ID, mapOf("fromMode" to "LITE", "toMode" to "LITE", "baselineId" to ""))
        }
        assertEquals(ModeSwitchCodes.SAME_MODE, same.code)
        assertTrue(h.runner.scripts.isEmpty())
    }

    @Test
    fun preflightIssuesOnlyReadOnlyCommands() {
        val h = harness()
        preflightOk(h)
        assertEquals(0, h.runner.writeScripts().size)
        assertTrue(h.runner.withMarker(ROOT).isNotEmpty())
        assertTrue(h.runner.withPrefix(DEVICE + "boot").isNotEmpty())
        assertTrue(h.runner.withMarker(FREE).isEmpty())
        assertTrue(h.runner.withMarker(WRITABLE).isEmpty())
        assertTrue(h.runner.withMarker(DEVICE + "vendor_boot").isEmpty())
    }

    @Test
    fun preflightRejectsMissingPartition() {
        val h = harness()
        h.requestedTarget = "init_boot"
        h.runner.on(DEVICE + "init_boot", "dev=\nsize=0\n")
        val result = runBlocking { h.client.preflight(SWITCH_ID, h.planFields()) }
        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.LAYOUT_UNSUPPORTED, result.code)
    }

    @Test
    fun preflightDoesNotRequireSpaceBudgetOrWritableAncestorProbe() {
        val h = harness()
        h.runner.fail(FREE)
        h.runner.fail(WRITABLE)
        val result = runBlocking { h.client.preflight(SWITCH_ID, h.planFields()) }
        assertTrue(result.ok)
        assertTrue(h.runner.withMarker(FREE).isEmpty())
        assertTrue(h.runner.withMarker(WRITABLE).isEmpty())
        assertTrue(h.runner.writeScripts().isEmpty())
    }

    @Test
    fun preflightRejectsInvalidSlotSuffix() {
        val h = harness()
        h.runner.on(SLOT, "_x\n")
        val result = runBlocking { h.client.preflight(SWITCH_ID, h.planFields()) }
        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.SLOT_INVALID, result.code)
    }

    @Test
    fun preflightRejectsNonZeroUid() {
        val h = harness()
        h.runner.on(ROOT, "2000\n")
        val result = runBlocking { h.client.preflight(SWITCH_ID, h.planFields()) }
        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.ROOT_UNAVAILABLE, result.code)
    }

    // ------------------------------------------------------------------ begin

    @Test
    fun beginResolvesActualInputsWithoutPreflight() {
        for (mode in listOf(WorkMode.KSU, WorkMode.LITE)) {
            val h = harness().also { it.toMode = mode }
            h.runner.fail(FREE)
            h.runner.fail(WRITABLE)
            val (superuser, settings) = h.mirrors()
            val result = runBlocking { h.client.begin(SWITCH_ID, h.planFields(), superuser, settings) }
            assertTrue("$mode begin: ${result.code} ${result.detail}", result.ok)
            assertEquals(h.targetPartition, h.persistedState()!!.targetPartition)
            assertEquals(SwitchStateNames.BEGIN, h.persistedState()!!.state)
            assertEquals(1, h.runner.withMarker(ROOT).size)
            assertEquals(1, h.runner.withMarker(SLOT).size)
            assertTrue(h.runner.withMarker(FREE).isEmpty())
            assertTrue(h.runner.withMarker(WRITABLE).isEmpty())
            assertTrue(h.runner.withMarker(DEVICE + "vendor_boot").isEmpty())
            assertTrue(h.runner.withMarker(COMMIT_WRITE).isEmpty())
            assertTrue(h.runner.withMarker(RESTORE_WRITE).isEmpty())
        }
    }

    @Test
    fun beginAfterClientRecreationUsesItsOwnInputs() {
        val h = harness()
        preflightOk(h)
        val recreated = UltraRootModeSwitchClient(h.runner, h.workRoot,
            destinationRoots = listOf(h.appRoot))
        val (superuser, settings) = h.mirrors()
        val result = runBlocking { recreated.begin(SWITCH_ID, h.planFields(), superuser, settings) }
        assertTrue("recreated begin: ${result.code} ${result.detail}", result.ok)
        assertEquals("init_boot", h.persistedState()!!.targetPartition)
        assertEquals(2, h.runner.withMarker(SLOT).size)
    }

    @Test
    fun beginResolvesCurrentSlotAndTargetAfterDiagnosticPreflight() {
        val h = harness()
        preflightOk(h)
        h.requestedTarget = "boot"
        h.runner.on(SLOT, "_b\n")
        h.runner.on(DEVICE + "boot", "dev=/dev/block/by-name/boot_b\nsize=8192\n")
        h.runner.on(DEVICE + "init_boot", "dev=\nsize=0\n")
        val (superuser, settings) = h.mirrors()
        val result = runBlocking { h.client.begin(SWITCH_ID, h.planFields(), superuser, settings) }
        assertTrue("current begin: ${result.code} ${result.detail}", result.ok)
        val state = h.persistedState()!!
        assertEquals("boot", state.targetPartition)
        assertEquals(listOf("boot"), state.partitions.map { it.name })
        assertEquals("/dev/block/by-name/boot_b", state.partitions.single().device)
        assertEquals(8192L, state.partitions.single().size)
        assertContains(h.runner.withMarker(PLAN_WRITE).single(), "\"slotSuffix\":\"_b\"")
    }

    @Test
    fun beginUsesCurrentAuthenticationInsteadOfEarlierPreflightSuccess() {
        val h = harness()
        preflightOk(h)
        h.runner.on(ROOT, "2000\n")
        val (superuser, settings) = h.mirrors()
        val result = runBlocking { h.client.begin(SWITCH_ID, h.planFields(), superuser, settings) }
        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.ROOT_UNAVAILABLE, result.code)
        assertTrue(h.runner.writeScripts().isEmpty())
    }

    @Test
    fun beginReturnsActualPlanWriteFailureWithoutWritableAncestorProbe() {
        val h = harness()
        h.runner.fail(PLAN_WRITE)
        val (superuser, settings) = h.mirrors()
        val result = runBlocking { h.client.begin(SWITCH_ID, h.planFields(), superuser, settings) }
        assertFalse(result.ok)
        assertEquals(UltraRootSwitchCodes.STATE_WRITE_FAILED, result.code)
        assertEquals("plan.json", result.detail)
        assertEquals(1, h.runner.withMarker(PLAN_WRITE).size)
        assertTrue(h.runner.withMarker(WRITABLE).isEmpty())
        assertTrue(h.runner.withMarker(STATE_WRITE).isEmpty())
        assertTrue(h.runner.withMarker(COMMIT_WRITE).isEmpty())
    }

    @Test
    fun beginWritesPlanAtomicallyAndNeverTouchesPartitions() {
        val h = harness()
        beginOk(h)
        val planScript = h.runner.withMarker(PLAN_WRITE).single()
        assertContains(planScript, "mkdir -p")
        assertContains(planScript, "printf '%s'")
        assertContains(planScript, ".tmp")
        assertContains(planScript, "mv -f")
        assertContains(planScript, "chmod 0600")
        assertContains(planScript, "plan.json")
        assertContains(planScript, "\"switchId\":\"$SWITCH_ID\"")
        assertContains(planScript, "\"targetPartition\":\"init_boot\"")
        assertContains(planScript, "\"device\":\"/dev/block/by-name/init_boot_a\"")
        assertNotContains(planScript, "dd ")
    }

    @Test
    fun beginRejectsMissingMirrorFiles() {
        val h = harness()
        preflightOk(h)
        val result = runBlocking {
            h.client.begin(
                SWITCH_ID, h.planFields(),
                File(h.mirrorDir, "missing-su.json"), File(h.mirrorDir, "missing-settings.json"),
            )
        }
        assertEquals(ModeSwitchCodes.PREPARE_EXPORT_FAILED, result.code)
        assertTrue(h.runner.withMarker(PLAN_WRITE).isEmpty())
    }

    // ------------------------------------------------------------------ snapshot

    @Test
    fun snapshotWritesPreImageForEveryPlannedPartition() {
        val h = harness()
        beginOk(h)
        snapshotOk(h)
        // 源（boot）与目标（init_boot）各一次 dd，且只 dd 自己那一个分区。
        val boot = h.runner.withMarker(SNAPSHOT_PRE + "boot").single()
        assertContains(boot, "dd if='/dev/block/by-name/boot_a'")
        assertContains(boot, "of=" + quoted(File(h.txDir(SWITCH_ID), "pre-boot.img").absolutePath))
        assertContains(boot, "bs=1M")
        assertContains(boot, "sync")
        assertContains(boot, "sha256sum " + quoted(File(h.txDir(SWITCH_ID), "pre-boot.img").absolutePath))
        assertContains(boot, "wc -c")
        assertEquals(1, Regex("dd if=").findAll(boot).count())
        val target = h.runner.withMarker(SNAPSHOT_PRE + "init_boot").single()
        assertContains(target, "dd if='/dev/block/by-name/init_boot_a'")
        assertContains(target, "of=" + quoted(File(h.txDir(SWITCH_ID), "pre-init_boot.img").absolutePath))
        assertEquals(1, Regex("dd if=").findAll(target).count())
        // 两个分区都记录 PRE 镜像 + preSha/preSize。
        val state = requireNotNull(h.persistedState())
        assertEquals(File(h.txDir(SWITCH_ID), "pre-boot.img").absolutePath, state.images["PRE:boot"])
        assertEquals(File(h.txDir(SWITCH_ID), "pre-init_boot.img").absolutePath, state.images["PRE:init_boot"])
        val bootRow = state.partitions.single { it.name == "boot" }
        assertEquals(h.sourceSha, bootRow.preSha256)
        assertEquals(h.size, bootRow.preSize)
        val targetRow = state.partitions.single { it.name == "init_boot" }
        assertEquals(h.preSha, targetRow.preSha256)
        assertEquals(h.size, targetRow.preSize)
        assertEquals("SNAPSHOT", state.state)
    }

    @Test
    fun snapshotPreparesBaselineImageForEveryPartitionWithBaseline() {
        val h = harness()
        baselineManifest(h, "b1", bootSha = "d".repeat(64), initBootSha = h.preSha)
        beginOk(h, baselineId = "b1")
        snapshotOk(h)
        // 只有 boot 需要复制基线镜像；init_boot 的当前内容已是基线 → 复用 PRE。
        val copy = h.runner.withMarker(BASELINE_COPY).single()
        assertContains(copy, "base-boot.img")
        assertContains(copy, "sha256sum")
        val state = requireNotNull(h.persistedState())
        assertEquals(File(h.txDir(SWITCH_ID), "base-boot.img").absolutePath, state.images["BASE:boot"])
        assertEquals(state.images["PRE:init_boot"], state.images["BASE:init_boot"])
        val bootRow = state.partitions.single { it.name == "boot" }
        assertEquals("d".repeat(64), bootRow.baselineSha256)
        assertEquals("d".repeat(64), bootRow.baseSha256)
        assertTrue(bootRow.restoreRequired)
        val targetRow = state.partitions.single { it.name == "init_boot" }
        assertEquals(h.preSha, targetRow.baseSha256)
        assertFalse(targetRow.restoreRequired)
    }

    @Test
    fun snapshotStatusExposesPreShaThroughReturnValue() {
        val h = harness()
        beginOk(h)
        val result = runBlocking { h.client.snapshot(SWITCH_ID) }
        assertTrue(result.ok)
        val status = requireNotNull(result.status)
        val row = status.partitions.first { it.name == "init_boot" }
        assertEquals(h.preSha, row.preSha256)
        assertEquals(SWITCH_ID, status.switchId)
        assertEquals("SNAPSHOT", status.state)
    }

    @Test
    fun snapshotUsesCurrentTargetWithoutRequiringAStockBaseline() {
        val h = harness()
        beginOk(h)
        snapshotOk(h)
        val state = requireNotNull(h.persistedState())
        assertEquals(state.images["PRE:init_boot"], state.images["BASE:init_boot"])
        assertEquals(h.preSha, state.partitions.single { it.name == "init_boot" }.baseSha256)
    }

    @Test
    fun knownSourceRecoveryRepatchesTheSameCarrierWithoutAStockManifest() {
        for (to in WorkMode.entries) {
            val partition = "boot"
            val h = harness(withRecovery = true).apply {
                toMode = to
                requestedTarget = partition
                requestedSource = partition
            }
            fullFlow(h)
            val call = h.recoveryCalls.single()
            assertEquals(if (to == WorkMode.KSU) WorkMode.LITE else WorkMode.KSU, call.from)
            assertEquals(partition, call.partition)
            assertTrue(call.sourceKnown)
            assertTrue(call.input.isFile)
            val state = h.persistedState()!!
            val row = state.partitions.single()
            assertEquals("", row.baselineSha256)
            assertEquals(h.recoveredSha, row.baseSha256)
            assertFalse(row.restoreRequired)
            commitOk(h)
            assertEquals(listOf("write"), writeOrderOf(h))
            assertContains(h.runner.withMarker(COMMIT_WRITE).single(), "of='/dev/block/by-name/${partition}_a'")
            h.bootId = "boot-2"
            assertTrue(runBlocking { h.client.verify(SWITCH_ID) }.ok)
        }
    }

    @Test
    fun recoveredSourceDigestDrivesCrossCarrierCommitExportAndVerifyWithoutPretendingToBeStock() {
        for (to in WorkMode.entries) {
            val h = harness(requireBaselineForCommit = true, withRecovery = true).apply {
                toMode = to
                requestedSource = if (to == WorkMode.KSU) "boot" else "init_boot"
            }
            fullFlow(h)
            val source = h.requestedSource!!
            val state = h.persistedState()!!
            val row = state.partitions.single { it.name == source }
            assertEquals("", row.baselineSha256)
            assertEquals(h.recoveredSha, row.baseSha256)
            assertTrue(row.restoreRequired)
            assertEquals(source, h.recoveryCalls.single().partition)
            val target = state.partitions.single { it.name == h.targetPartition }
            assertEquals(target.preSha256, target.baseSha256)
            assertEquals(state.images["PRE:${h.targetPartition}"], state.images["BASE:${h.targetPartition}"])
            val exported = File(h.outDir, "recovered-$source.img")
            assertTrue(runBlocking { h.client.exportImage(SWITCH_ID, "BASE", source, exported) })
            assertEquals(h.recoveredSha, Hashes.sha256(exported.readBytes()))
            val committed = commitOk(h)
            assertEquals(h.recoveredSha, committed.status!!.partitions.single { it.name == source }.observedSha256)
            assertEquals(if (to == WorkMode.KSU) listOf("write", "restore") else listOf("restore", "write"), writeOrderOf(h))
            h.bootId = "boot-2"
            val verified = runBlocking { h.client.verify(SWITCH_ID) }
            assertTrue("${verified.code}: ${verified.detail}", verified.ok)
            assertEquals(h.recoveredSha, verified.status!!.partitions.single { it.name == source }.targetSha256)
        }
    }

    @Test
    fun unknownNormalSourceRecoversBothPossibleCarriersAndLeavesUnchangedBootUnwritten() {
        val h = harness(withRecovery = true).apply { toMode = WorkMode.LITE }
        h.recovery = { call ->
            if (call.partition == "boot") CandidateResult(call.input, h.sourceSha, h.size)
            else h.recovered(call)
        }
        fullFlow(h)
        assertEquals(setOf("boot", "init_boot"), h.recoveryCalls.map { it.partition }.toSet())
        assertTrue(h.recoveryCalls.all { it.from == WorkMode.KSU && !it.sourceKnown })
        assertEquals(1, h.runner.withMarker(SOURCE_IMPORT).size)
        val state = h.persistedState()!!
        assertEquals(state.images["PRE:boot"], state.images["BASE:boot"])
        assertFalse(state.partitions.single { it.name == "boot" }.restoreRequired)
        assertTrue(state.partitions.single { it.name == "init_boot" }.restoreRequired)
        commitOk(h)
        assertEquals(listOf("restore", "write"), writeOrderOf(h))
        h.bootId = "boot-2"
        assertTrue(runBlocking { h.client.verify(SWITCH_ID) }.ok)
    }

    @Test
    fun validRecordedOriginalWinsBeforeTheRecoveryCallback() {
        val h = harness(withRecovery = true).apply { requestedSource = "boot" }
        baselineManifest(h, bootSha = "d".repeat(64), initBootSha = h.preSha)
        fullFlow(h, baselineId = "b1")
        assertTrue(h.recoveryCalls.isEmpty())
        assertTrue(h.runner.withMarker(SOURCE_IMPORT).isEmpty())
        val row = h.persistedState()!!.partitions.single { it.name == "boot" }
        assertEquals(h.bootBaselineSha, row.baselineSha256)
        assertEquals(h.bootBaselineSha, row.baseSha256)
    }

    @Test
    fun damagedRecordedOriginalUsesRecoveryAndKeepsItsDistinctDigest() {
        val h = harness(withRecovery = true).apply { requestedSource = "boot" }
        baselineManifest(h, bootSha = "d".repeat(64), initBootSha = h.preSha)
        h.runner.fail(BASELINE_COPY)
        fullFlow(h, baselineId = "b1")
        assertEquals("boot", h.recoveryCalls.single().partition)
        val row = h.persistedState()!!.partitions.single { it.name == "boot" }
        assertEquals(h.bootBaselineSha, row.baselineSha256)
        assertEquals(h.recoveredSha, row.baseSha256)
        commitOk(h)
        h.bootId = "boot-2"
        assertTrue(runBlocking { h.client.verify(SWITCH_ID) }.ok)
    }

    @Test
    fun recoveryCallbackAndOutputFailuresStopSnapshotBeforeAnyPartitionWrite() {
        val cases: List<Pair<String, (Harness) -> Unit>> = listOf(
            "RECOVERY_TEST_FAILED" to { h -> h.recovery = { CandidateResult(null, "", 0, "RECOVERY_TEST_FAILED", "test") } },
            ModeSwitchCodes.ROOT_UNAVAILABLE to { h -> h.recovery = { error("callback failed") } },
            "SOURCE_RECOVERY_OUTPUT_INVALID" to { h -> h.recovery = { call -> h.recovered(call).copy(sha256 = "f".repeat(64)) } },
            "SOURCE_RECOVERY_OUTPUT_INVALID" to { h -> h.recovery = { call -> h.recovered(call).copy(size = h.size - 1) } },
            "SOURCE_RECOVERY_OUTPUT_INVALID" to { h -> h.recovery = { call ->
                val candidate = h.recovered(call)
                candidate.image!!.writeBytes(byteArrayOf(1))
                candidate.copy(size = 1, sha256 = Hashes.sha256(byteArrayOf(1)))
            } },
            "SOURCE_RECOVERY_OUTPUT_INVALID" to { h -> h.recovery = { call ->
                h.recovered(call).copy(image = File(call.outputDir, "missing.img"))
            } },
            "SOURCE_RECOVERY_OUTPUT_INVALID" to { h -> h.recovery = { call ->
                val outside = File(h.root, "outside.img").apply { writeBytes(h.recoveredBytes) }
                h.recovered(call).copy(image = outside)
            } },
            "SOURCE_RECOVERY_INPUT_CHANGED" to { h -> h.recovery = { call ->
                val candidate = h.recovered(call)
                call.input.writeBytes(ByteArray(h.size.toInt()) { 27 })
                candidate
            } },
        )
        for ((expected, configure) in cases) {
            val h = harness(withRecovery = true).apply { requestedSource = "boot" }
            configure(h)
            beginOk(h)
            val result = runBlocking { h.client.snapshot(SWITCH_ID) }
            assertFalse(expected, result.ok)
            assertEquals(expected, result.code)
            assertEquals("BEGIN", h.persistedState()!!.state)
            assertTrue(h.runner.withMarker(COMMIT_WRITE).isEmpty())
            assertTrue(h.runner.withMarker(RESTORE_WRITE).isEmpty())
            assertTrue(h.runner.withMarker(ROLLBACK_WRITE).isEmpty())
        }
    }

    @Test
    fun recoveryExportAndImportFailuresStopSnapshotBeforeAnyPartitionWrite() {
        val cases: List<Pair<String, (Harness) -> Unit>> = listOf(
            "SOURCE_RECOVERY_EXPORT_FAILED" to { h -> h.runner.fail(EXPORT) },
            "SOURCE_RECOVERY_EXPORT_FAILED" to { h -> h.exportedBytes = ByteArray(h.size.toInt()) { 31 } },
            "SOURCE_RECOVERY_IMPORT_FAILED" to { h -> h.runner.fail(SOURCE_IMPORT) },
            "SOURCE_RECOVERY_IMPORT_FAILED" to { h -> h.runner.on(SOURCE_IMPORT, "${"f".repeat(64)}  /base\n${h.size}\n") },
            "SOURCE_RECOVERY_IMPORT_FAILED" to { h -> h.runner.on(SOURCE_IMPORT, "${h.recoveredSha}  /base\n${h.size - 1}\n") },
        )
        for ((expected, configure) in cases) {
            val h = harness(withRecovery = true).apply { requestedSource = "boot" }
            configure(h)
            beginOk(h)
            val result = runBlocking { h.client.snapshot(SWITCH_ID) }
            assertFalse(expected, result.ok)
            assertEquals(expected, result.code)
            assertEquals("BEGIN", h.persistedState()!!.state)
            assertTrue(h.runner.withMarker(COMMIT_WRITE).isEmpty())
            assertTrue(h.runner.withMarker(RESTORE_WRITE).isEmpty())
            assertTrue(h.runner.withMarker(ROLLBACK_WRITE).isEmpty())
        }
    }

    @Test
    fun failedRecoveredSourceCommitCompensatesWithPreImagesRatherThanRecoveredCopies() {
        val h = harness(withRecovery = true).apply {
            toMode = WorkMode.LITE
            requestedSource = "init_boot"
        }
        fullFlow(h)
        h.runner.fail(COMMIT_WRITE)
        val result = runBlocking { h.client.commit(SWITCH_ID) }
        assertEquals(UltraRootSwitchCodes.COMMIT_WRITE_FAILED, result.code)
        assertEquals("ROLLED_BACK", result.status!!.state)
        val rollbacks = h.runner.withMarker(ROLLBACK_WRITE)
        assertEquals(2, rollbacks.size)
        assertContains(rollbacks[0], "pre-boot.img")
        assertContains(rollbacks[1], "pre-init_boot.img")
        assertTrue(rollbacks.none { it.contains("base-") })
        assertEquals(h.sourceSha, result.status!!.partitions.single { it.name == "boot" }.observedSha256)
        assertEquals(h.preSha, result.status!!.partitions.single { it.name == "init_boot" }.observedSha256)
    }

    @Test
    fun oldProduceRecordWithoutRecoveredSourceCannotCommitThroughTheNewCallbackPath() {
        val h = harness(withRecovery = true)
        val directory = h.ensureTx(SWITCH_ID)
        val candidate = File(directory, "candidate-init_boot.img").apply { writeBytes(ByteArray(4096) { 7 }) }
        h.targetSha = Hashes.sha256(candidate.readBytes())
        val bootPre = File(directory, "pre-boot.img").apply { writeBytes(h.bootBytes) }
        val initBootPre = File(directory, "pre-init_boot.img").apply { writeBytes(h.initBootBytes) }
        writeState(h, SWITCH_ID, "PRODUCE", images = mapOf(
            "PRE:boot" to bootPre.absolutePath,
            "PRE:init_boot" to initBootPre.absolutePath,
            "CANDIDATE:init_boot" to candidate.absolutePath,
        ), preSha = h.preSha, targetSha = h.targetSha)

        val result = runBlocking { h.client.commit(SWITCH_ID) }

        assertFalse(result.ok)
        assertEquals("SOURCE_RECOVERY_INPUT_MISSING", result.code)
        assertTrue(h.recoveryCalls.isEmpty())
        assertTrue(h.runner.withMarker(COMMIT_WRITE).isEmpty())
        assertTrue(h.runner.withMarker(RESTORE_WRITE).isEmpty())
        assertTrue(h.runner.withMarker(ROLLBACK_WRITE).isEmpty())
    }

    @Test
    fun snapshotFailsWhenImageSizeDoesNotMatchPartition() {
        val h = harness()
        beginOk(h)
        h.runner.on(SNAPSHOT_PRE + "boot") {
            RootExecResult(RootBackend.ULTRA_ENV, 0, "${h.sourceSha}  /x\n${h.size - 1}\n")
        }
        val result = runBlocking { h.client.snapshot(SWITCH_ID) }
        assertFalse(result.ok)
        assertEquals(UltraRootSwitchCodes.SNAPSHOT_VERIFY_FAILED, result.code)
    }

    @Test
    fun snapshotRejectsTamperedPlanDevicePath() {
        val h = harness()
        writeState(h, SWITCH_ID, "BEGIN")
        val tampered = UltraSwitchPlanFile(
            switchId = SWITCH_ID,
            fromMode = "LITE",
            toMode = "KSU",
            slotSuffix = "_a",
            targetPartition = "init_boot",
            partitions = listOf(
                UltraSwitchPlanPartition("init_boot", "WRITE_CANDIDATE", "/dev/block/by-name/init_boot_a", h.size),
                UltraSwitchPlanPartition("boot", "RESTORE_BASELINE", "/dev/block/mmcblk0p9", h.size),
            ),
        )
        h.planFile(SWITCH_ID).writeText(ControlJsonCodec.encode(tampered))
        val result = runBlocking { h.client.snapshot(SWITCH_ID) }
        assertFalse(result.ok)
        assertEquals(UltraRootSwitchCodes.PARTITION_FORBIDDEN, result.code)
        assertTrue(h.runner.withPrefix(SNAPSHOT_PRE).isEmpty())
    }

    // ------------------------------------------------------------------ submitCandidate

    @Test
    fun submitCandidateRejectsShaMismatchBeforeAnyRootWrite() {
        val h = harness()
        beginOk(h)
        snapshotOk(h)
        val file = File(h.mirrorDir, "candidate.img").apply { writeBytes(ByteArray(4096) { 3 }) }
        val result = runBlocking {
            h.client.submitCandidate(SWITCH_ID, "init_boot", file, "f".repeat(64))
        }
        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.PRODUCE_CANDIDATE_CHANGED, result.code)
        assertTrue(h.runner.withMarker(SUBMIT_COPY).isEmpty())
    }

    @Test
    fun submitCandidateRejectsForbiddenPartition() {
        val h = harness()
        beginOk(h)
        snapshotOk(h)
        val file = File(h.mirrorDir, "candidate.img").apply { writeBytes(ByteArray(4096)) }
        val result = runBlocking {
            h.client.submitCandidate(SWITCH_ID, "boot", file, Hashes.sha256(file.readBytes()))
        }
        assertEquals(UltraRootSwitchCodes.PARTITION_FORBIDDEN, result.code)
    }

    @Test
    fun submitCandidateCopiesAndVerifiesStoredSha() {
        val h = harness()
        beginOk(h)
        snapshotOk(h)
        submitOk(h)
        val script = h.runner.withMarker(SUBMIT_COPY).single()
        assertContains(script, "cp -f")
        assertContains(script, "chmod 0600")
        assertContains(script, "sha256sum")
        assertContains(script, quoted(File(h.txDir(SWITCH_ID), "candidate-init_boot.img").absolutePath))
        // stored sha 回读被篡改 → 拒绝
        val h2 = harness()
        beginOk(h2)
        snapshotOk(h2)
        h2.runner.on(SUBMIT_COPY) { RootExecResult(RootBackend.ULTRA_ENV, 0, "f".repeat(64) + "  /c\n") }
        val candidate = File(h2.mirrorDir, "candidate.img").apply { writeBytes(ByteArray(4096) { 9 }) }
        val rejected = runBlocking {
            h2.client.submitCandidate(SWITCH_ID, "init_boot", candidate, Hashes.sha256(candidate.readBytes()))
        }
        assertFalse(rejected.ok)
        assertEquals(ModeSwitchCodes.PRODUCE_CANDIDATE_CHANGED, rejected.code)
    }

    // ------------------------------------------------------------------ commit（双分区）

    @Test
    fun commitRefusesWhenCandidateChangedBeforeWrite() {
        val h = harness()
        fullFlow(h)
        h.runner.on(COMMIT_CHECK + "candidate") {
            RootExecResult(RootBackend.ULTRA_ENV, 0, "${h.size}\n${"f".repeat(64)}  /c\n")
        }
        val result = runBlocking { h.client.commit(SWITCH_ID) }
        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.PRODUCE_CANDIDATE_CHANGED, result.code)
        assertTrue(h.runner.withMarker(COMMIT_WRITE).isEmpty())
        assertTrue(h.runner.withMarker(ROLLBACK_WRITE).isEmpty())
    }

    @Test
    fun commitRejectsChangedSlotBeforeAnyPartitionWriteAndKeepsPreparedState() {
        val h = harness()
        fullFlow(h)
        h.runner.on(SLOT, "_b\n")

        val result = runBlocking { h.client.commit(SWITCH_ID) }

        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.SLOT_INVALID, result.code)
        assertEquals("PRODUCE", h.persistedState()!!.state)
        assertTrue(h.runner.withMarker(COMMIT_WRITE).isEmpty())
        assertTrue(h.runner.withMarker(RESTORE_WRITE).isEmpty())
        assertTrue(h.runner.withMarker(ROLLBACK_WRITE).isEmpty())
    }

    @Test
    fun commitRejectsUnreadableSlotBeforeAnyPartitionWrite() {
        val h = harness()
        fullFlow(h)
        h.runner.fail(SLOT)

        val result = runBlocking { h.client.commit(SWITCH_ID) }

        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.SLOT_INVALID, result.code)
        assertEquals("PRODUCE", h.persistedState()!!.state)
        assertTrue(h.runner.withMarker(COMMIT_WRITE).isEmpty())
        assertTrue(h.runner.withMarker(RESTORE_WRITE).isEmpty())
        assertTrue(h.runner.withMarker(ROLLBACK_WRITE).isEmpty())
    }

    @Test
    fun preflightDoesNotTreatFailedSlotReadAsANonAbDevice() {
        val h = harness()
        h.runner.fail(SLOT)

        val result = runBlocking { h.client.preflight(SWITCH_ID, h.planFields()) }

        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.SLOT_INVALID, result.code)
        assertTrue(h.runner.withPrefix(DEVICE).isEmpty())
        assertTrue(h.runner.writeScripts().isEmpty())
    }

    @Test
    fun commitRefusesWhenSnapshotMissingBeforeWrite() {
        val h = harness()
        val candidate = File(h.txDir(SWITCH_ID), "candidate-init_boot.img")
        h.ensureTx(SWITCH_ID)
        candidate.writeBytes(ByteArray(h.size.toInt()))
        val sha = Hashes.sha256(candidate.readBytes())
        h.targetSha = sha
        writeState(
            h, SWITCH_ID, "COMMIT",
            images = mapOf("CANDIDATE:init_boot" to candidate.absolutePath),
            preSha = h.preSha, targetSha = sha,
        )
        val result = runBlocking { h.client.commit(SWITCH_ID) }
        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.PRE_IMAGE_INVALID, result.code)
        assertTrue(h.runner.withMarker(COMMIT_WRITE).isEmpty())
    }

    @Test
    fun commitWritesOnlyTargetPartitionAndVerifiesReadback() {
        val h = harness()
        fullFlow(h)
        val result = commitOk(h)
        val write = h.runner.withMarker(COMMIT_WRITE).single()
        assertEquals(1, Regex("dd if=").findAll(write).count())
        assertContains(write, "of=" + quoted("/dev/block/by-name/init_boot_a"))
        assertNotContains(write, "of=" + quoted("/dev/block/by-name/boot_a"))
        assertContains(write, "sync")
        assertContains(write, "sha256sum '/dev/block/by-name/init_boot_a'")
        val status = requireNotNull(result.status)
        assertEquals("REBOOT_REQUIRED", status.state)
        assertEquals(h.targetSha, status.partitions.first { it.name == "init_boot" }.observedSha256)
    }

    @Test
    fun commitWritesNormalInitBootThenRestoresUltraBootInOrder() {
        val h = harness(requireBaselineForCommit = true)
        baselineManifest(h, "b1", bootSha = "d".repeat(64), initBootSha = h.preSha)
        fullFlow(h, baselineId = "b1")
        val result = commitOk(h)
        // Normal init_boot is durable before removing the Ultra boot kernel.
        assertEquals(listOf("write", "restore"), writeOrderOf(h))
        val restore = h.runner.withMarker(RESTORE_WRITE).single()
        assertContains(restore, "dd if=" + quoted(File(h.txDir(SWITCH_ID), "base-boot.img").absolutePath))
        assertContains(restore, "of=" + quoted("/dev/block/by-name/boot_a"))
        assertContains(restore, "sync")
        assertContains(restore, "sha256sum '/dev/block/by-name/boot_a'")
        assertEquals(1, Regex("dd if=").findAll(restore).count())
        val write = h.runner.withMarker(COMMIT_WRITE).single()
        assertContains(write, "dd if=" + quoted(File(h.txDir(SWITCH_ID), "candidate-init_boot.img").absolutePath))
        assertContains(write, "of=" + quoted("/dev/block/by-name/init_boot_a"))
        assertContains(write, "sha256sum '/dev/block/by-name/init_boot_a'")
        val status = requireNotNull(result.status)
        assertEquals("REBOOT_REQUIRED", status.state)
        val bootRow = status.partitions.single { it.name == "boot" }
        assertEquals("d".repeat(64), bootRow.observedSha256)
        assertEquals("RESTORED", bootRow.state)
        val targetRow = status.partitions.single { it.name == "init_boot" }
        assertEquals(h.targetSha, targetRow.observedSha256)
        assertEquals("WRITTEN", targetRow.state)
    }

    @Test
    fun selectedNormalBootIsTheOnlyWrittenPartitionAndVerifiesAfterReboot() {
        val h = harness(requireBaselineForCommit = true).apply { requestedTarget = "boot" }
        val file = baselineManifest(h, "selected-input", bootSha = "d".repeat(64))
        val manifest = requireNotNull(ControlJsonCodec.decodeOrNull<BaselineManifest>(file.readText()))
        file.writeText(ControlJsonCodec.encode(manifest.copy(provenance = "USER_SELECTED", clean = false)))
        fullFlow(h, baselineId = "selected-input")
        val result = commitOk(h)
        assertEquals(listOf("write"), writeOrderOf(h))
        assertEquals(listOf("boot"), result.status?.partitions?.map { it.name })
        assertContains(h.runner.withMarker(COMMIT_WRITE).single(), "of=" + quoted("/dev/block/by-name/boot_a"))
        h.bootId = "boot-2"
        val verified = runBlocking { h.client.verify(SWITCH_ID) }
        assertTrue("${verified.code}: ${verified.detail}", verified.ok)
        assertEquals("VERIFIED", verified.status?.state)
    }

    @Test
    fun selectedUltraInputStillRestoresInitBootWhenBootAlreadyMatchesTheCandidate() {
        val h = harness(requireBaselineForCommit = true).apply { toMode = WorkMode.LITE }
        val candidate = ByteArray(4096) { 7 }
        h.sourceSha = Hashes.sha256(candidate)
        baselineManifest(h, "selected-input", bootSha = h.sourceSha, initBootSha = "d".repeat(64))
        beginOk(h, baselineId = "selected-input")
        snapshotOk(h)
        submitOk(h, bytes = candidate)
        val result = commitOk(h)
        assertEquals(listOf("restore", "write"), writeOrderOf(h))
        assertEquals("d".repeat(64), result.status?.partitions?.single { it.name == "init_boot" }?.observedSha256)
    }

    @Test
    fun normalToUltraRestoresStockInitBootThenWritesUltraBoot() {
        val h = harness(requireBaselineForCommit = true).apply { toMode = WorkMode.LITE }
        baselineManifest(h, "b1", bootSha = h.sourceSha, initBootSha = "d".repeat(64))
        fullFlow(h, baselineId = "b1")
        val result = commitOk(h)
        assertEquals(listOf("restore", "write"), writeOrderOf(h))
        val restore = h.runner.withMarker(RESTORE_WRITE).single()
        assertContains(restore, "dd if=" + quoted(File(h.txDir(SWITCH_ID), "base-init_boot.img").absolutePath))
        assertContains(restore, "of=" + quoted("/dev/block/by-name/init_boot_a"))
        val write = h.runner.withMarker(COMMIT_WRITE).single()
        assertContains(write, "dd if=" + quoted(File(h.txDir(SWITCH_ID), "candidate-boot.img").absolutePath))
        assertContains(write, "of=" + quoted("/dev/block/by-name/boot_a"))
        val status = requireNotNull(result.status)
        assertEquals("REBOOT_REQUIRED", status.state)
        assertEquals("d".repeat(64), status.partitions.single { it.name == "init_boot" }.observedSha256)
        assertEquals(h.targetSha, status.partitions.single { it.name == "boot" }.observedSha256)
        h.bootId = "boot-2"
        val verified = runBlocking { h.client.verify(SWITCH_ID) }
        assertTrue("verify: ${verified.code} ${verified.detail}", verified.ok)
        assertEquals("VERIFIED", verified.status?.state)
    }

    @Test
    fun normalToUltraInitBootFailureDoesNotWriteUltraBoot() {
        val h = harness(requireBaselineForCommit = true).apply { toMode = WorkMode.LITE }
        baselineManifest(h, "b1", bootSha = h.sourceSha, initBootSha = "d".repeat(64))
        fullFlow(h, baselineId = "b1")
        h.restoreWriteSha = "f".repeat(64)
        val result = runBlocking { h.client.commit(SWITCH_ID) }
        assertFalse(result.ok)
        assertEquals(UltraRootSwitchCodes.COMMIT_VERIFY_FAILED, result.code)
        assertTrue(h.runner.withMarker(COMMIT_WRITE).isEmpty())
        assertContains(h.runner.withMarker(ROLLBACK_WRITE).single(), "of=" + quoted("/dev/block/by-name/init_boot_a"))
        assertEquals("ROLLED_BACK", result.status?.state)
    }

    @Test
    fun normalToUltraBootFailureRestoresPreBootThenPreInitBoot() {
        val h = harness(requireBaselineForCommit = true).apply { toMode = WorkMode.LITE }
        baselineManifest(h, "b1", bootSha = h.sourceSha, initBootSha = "d".repeat(64))
        fullFlow(h, baselineId = "b1")
        h.runner.fail(COMMIT_WRITE)
        val result = runBlocking { h.client.commit(SWITCH_ID) }
        assertFalse(result.ok)
        assertEquals(UltraRootSwitchCodes.COMMIT_WRITE_FAILED, result.code)
        assertEquals(listOf("restore", "write"), writeOrderOf(h))
        val rollbacks = h.runner.withMarker(ROLLBACK_WRITE)
        assertEquals(2, rollbacks.size)
        assertContains(rollbacks[0], "of=" + quoted("/dev/block/by-name/boot_a"))
        assertContains(rollbacks[1], "of=" + quoted("/dev/block/by-name/init_boot_a"))
        assertEquals("ROLLED_BACK", result.status?.state)
    }

    @Test
    fun commitRejectsRestoreWhenBaselineImageMissingBeforeAnyDd() {
        // 基线证明 boot 需还原，但基线镜像复制被篡改 → 没有 BASE:boot。
        // 闸门之外的**无条件**镜像闸门：commit 必须在任何 dd 之前拒绝。
        val h = harness()
        baselineManifest(h, "b1", bootSha = "d".repeat(64), initBootSha = h.preSha)
        h.runner.on(BASELINE_COPY) { RootExecResult(RootBackend.ULTRA_ENV, 0, "f".repeat(64) + "  /img\n") }
        fullFlow(h, baselineId = "b1")
        assertNull(requireNotNull(h.persistedState()).images["BASE:boot"])
        val ddBefore = h.runner.scripts.count { it.contains("dd if=") }
        val result = runBlocking { h.client.commit(SWITCH_ID) }
        assertFalse(result.ok)
        assertEquals(UltraRootSwitchCodes.BASELINE_REQUIRED, result.code)
        // commit **零 dd**：脚本里的 dd 数量没有增加。
        assertEquals(ddBefore, h.runner.scripts.count { it.contains("dd if=") })
        assertTrue(h.runner.withMarker(RESTORE_WRITE).isEmpty())
        assertTrue(h.runner.withMarker(COMMIT_WRITE).isEmpty())
        assertTrue(h.runner.withMarker(ROLLBACK_WRITE).isEmpty())
    }

    @Test
    fun commitWithBaselineGateRejectsMissingBaselineShaBeforeAnyDd() {
        val h = harness(requireBaselineForCommit = true)
        fullFlow(h) // 没有基线清单：源分区 boot 没有 baselineSha256
        val ddBefore = h.runner.scripts.count { it.contains("dd if=") }
        val result = runBlocking { h.client.commit(SWITCH_ID) }
        assertFalse(result.ok)
        assertEquals(UltraRootSwitchCodes.BASELINE_REQUIRED, result.code)
        assertEquals(ddBefore, h.runner.scripts.count { it.contains("dd if=") })
        assertTrue(h.runner.withMarker(RESTORE_WRITE).isEmpty())
        assertTrue(h.runner.withMarker(COMMIT_WRITE).isEmpty())
        assertTrue(h.runner.withMarker(ROLLBACK_WRITE).isEmpty())
    }

    @Test
    fun commitWriteFailureRollsBackAndKeepsWriteFailedCode() {
        val h = harness()
        fullFlow(h)
        h.runner.on(COMMIT_WRITE) { RootExecResult(RootBackend.ULTRA_ENV, 1, "") }
        val result = runBlocking { h.client.commit(SWITCH_ID) }
        assertFalse(result.ok)
        assertEquals(UltraRootSwitchCodes.COMMIT_WRITE_FAILED, result.code)
        assertContains(result.detail, "write-failed")
        val status = requireNotNull(result.status)
        assertEquals("ROLLED_BACK", status.state)
        assertEquals(h.preSha, status.partitions.single { it.name == "init_boot" }.observedSha256)
        assertEquals(1, h.runner.withMarker(ROLLBACK_WRITE).size)
    }

    @Test
    fun commitRestoreReadbackMismatchRollsBackBootThenInitBoot() {
        val h = harness(requireBaselineForCommit = true)
        baselineManifest(h, "b1", bootSha = "d".repeat(64), initBootSha = h.preSha)
        fullFlow(h, baselineId = "b1")
        h.restoreWriteSha = "f".repeat(64)
        val result = runBlocking { h.client.commit(SWITCH_ID) }
        assertFalse(result.ok)
        assertEquals(UltraRootSwitchCodes.COMMIT_VERIFY_FAILED, result.code)
        assertEquals(1, h.runner.withMarker(COMMIT_WRITE).size)
        val rollbacks = h.runner.withMarker(ROLLBACK_WRITE)
        assertEquals(2, rollbacks.size)
        assertContains(rollbacks[0], "of=" + quoted("/dev/block/by-name/boot_a"))
        assertContains(rollbacks[1], "of=" + quoted("/dev/block/by-name/init_boot_a"))
        assertEquals("ROLLED_BACK", result.status?.state)
    }

    @Test
    fun commitTargetWriteFailureRollsBackOnlyInitBootWithoutRemovingUltraBoot() {
        val h = harness(requireBaselineForCommit = true)
        baselineManifest(h, "b1", bootSha = "d".repeat(64), initBootSha = h.preSha)
        fullFlow(h, baselineId = "b1")
        h.runner.on(COMMIT_WRITE) { RootExecResult(RootBackend.ULTRA_ENV, 0, "f".repeat(64) + "  /dev\n") }
        val result = runBlocking { h.client.commit(SWITCH_ID) }
        assertFalse(result.ok)
        assertEquals(UltraRootSwitchCodes.COMMIT_VERIFY_FAILED, result.code)
        assertTrue(h.runner.withMarker(RESTORE_WRITE).isEmpty())
        val rollback = h.runner.withMarker(ROLLBACK_WRITE).single()
        assertContains(rollback, "of=" + quoted("/dev/block/by-name/init_boot_a"))
        assertEquals("ROLLED_BACK", result.status?.state)
    }

    @Test
    fun commitRollbackFailureListsFailedPartitionsInDetail() {
        val h = harness(requireBaselineForCommit = true)
        baselineManifest(h, "b1", bootSha = "d".repeat(64), initBootSha = h.preSha)
        fullFlow(h, baselineId = "b1")
        h.restoreWriteSha = "f".repeat(64)
        h.runner.on(ROLLBACK_WRITE) { script ->
            // init_boot 回滚成功，boot 回滚回读不符 → 必须进入 RECOVERY_REQUIRED 并点名 boot。
            if (script.contains("of='/dev/block/by-name/boot_a'")) {
                RootExecResult(RootBackend.ULTRA_ENV, 0, "f".repeat(64) + "  /dev\n")
            } else {
                RootExecResult(RootBackend.ULTRA_ENV, 0, "${h.preSha}  /dev\n")
            }
        }
        val result = runBlocking { h.client.commit(SWITCH_ID) }
        assertFalse(result.ok)
        assertEquals(UltraRootSwitchCodes.ROLLBACK_VERIFY_FAILED, result.code)
        assertEquals("RECOVERY_REQUIRED", requireNotNull(result.status).state)
        assertContains(result.detail, "rollback failed partitions=")
        assertContains(result.detail, "boot:readback=")
    }

    @Test
    fun commitSkipsRestoreForSourceAlreadyAtBaseline() {
        val h = harness(requireBaselineForCommit = true)
        // 源分区内容已经是基线 → 不需要还原，也绝不写它。
        baselineManifest(h, "b1", bootSha = h.sourceSha, initBootSha = h.preSha)
        fullFlow(h, baselineId = "b1")
        commitOk(h)
        assertTrue(h.runner.withMarker(RESTORE_WRITE).isEmpty())
        assertEquals(1, h.runner.withMarker(COMMIT_WRITE).size)
        val state = requireNotNull(h.persistedState())
        assertFalse(state.partitions.single { it.name == "boot" }.restoreRequired)
        assertEquals("", state.partitions.single { it.name == "boot" }.observedSha256)
    }

    @Test
    fun explicitRollbackRestoresEveryWrittenPartitionInReverseOrder() {
        val h = harness(requireBaselineForCommit = true)
        baselineManifest(h, "b1", bootSha = "d".repeat(64), initBootSha = h.preSha)
        fullFlow(h, baselineId = "b1")
        commitOk(h)
        val result = runBlocking { h.client.rollback(SWITCH_ID) }
        assertTrue("${result.code} ${result.detail}", result.ok)
        val rollbacks = h.runner.withMarker(ROLLBACK_WRITE)
        assertEquals(2, rollbacks.size)
        assertContains(rollbacks[0], "of=" + quoted("/dev/block/by-name/boot_a"))
        assertContains(rollbacks[1], "of=" + quoted("/dev/block/by-name/init_boot_a"))
        assertEquals("ROLLED_BACK", requireNotNull(result.status).state)
    }

    @Test
    fun explicitRollbackRejectsChangedSlotAndPreservesTheRecoverableTask() {
        val h = harness()
        fullFlow(h)
        commitOk(h)
        h.runner.on(SLOT, "_b\n")

        val result = runBlocking { h.client.rollback(SWITCH_ID) }

        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.SLOT_INVALID, result.code)
        assertEquals("REBOOT_REQUIRED", h.persistedState()!!.state)
        assertTrue(h.runner.withMarker(ROLLBACK_WRITE).isEmpty())
    }

    @Test
    fun failedCommitDoesNotCompensateIntoAChangedSlot() {
        val h = harness(requireBaselineForCommit = true)
        baselineManifest(h, bootSha = "d".repeat(64), initBootSha = h.preSha)
        fullFlow(h, baselineId = "b1")
        h.runner.on(RESTORE_WRITE) {
            h.runner.on(SLOT, "_b\n")
            RootExecResult(RootBackend.ULTRA_ENV, 1, "")
        }

        val result = runBlocking { h.client.commit(SWITCH_ID) }

        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.SLOT_INVALID, result.code)
        assertEquals("COMMIT", h.persistedState()!!.state)
        assertEquals(1, h.runner.withMarker(COMMIT_WRITE).size)
        assertTrue(h.runner.withMarker(ROLLBACK_WRITE).isEmpty())
    }

    @Test
    fun hardenedBaselineGateRequiresBaselineShaForEverySourcePartition() {
        // 生产装配 requireBaselineForCommit=true 的判据：源分区（boot）没有基线 sha
        // 就不知道"该还原成什么"，必须在任何 dd 之前拒绝写目标分区。
        val boot = UltraSwitchPartitionState(
            name = "boot",
            role = "restore",
            device = "/dev/block/by-name/boot_a",
            size = 4096,
        )
        val target = UltraSwitchPartitionState(
            name = "init_boot",
            role = "write",
            device = "/dev/block/by-name/init_boot_a",
            size = 4096,
        )
        val state = UltraSwitchStateFile(
            switchId = "switch-1",
            state = "PRODUCE",
            fromMode = "LITE",
            toMode = "KSU",
            targetPartition = "init_boot",
            partitions = listOf(boot, target),
        )
        assertEquals(listOf("boot"), baselineMissingPartitions(state, "init_boot"))
        val withBaseline = state.copy(
            partitions = listOf(boot.copy(baselineSha256 = "b".repeat(64)), target),
        )
        assertTrue(baselineMissingPartitions(withBaseline, "init_boot").isEmpty())
        // 目标分区自己缺 baseline 不算（它本来就是要被覆盖的）。
        val targetOnly = state.copy(partitions = listOf(boot.copy(baselineSha256 = "b".repeat(64)), target))
        assertTrue(baselineMissingPartitions(targetOnly, "init_boot").isEmpty())
    }

    @Test
    fun commitReadbackMismatchRollsBackToSnapshot() {
        val h = harness()
        fullFlow(h)
        h.runner.on(COMMIT_WRITE) { RootExecResult(RootBackend.ULTRA_ENV, 0, "${h.sourceSha}  /dev/block/by-name/init_boot_a\n") }
        val result = runBlocking { h.client.commit(SWITCH_ID) }
        assertFalse(result.ok)
        assertEquals(UltraRootSwitchCodes.COMMIT_VERIFY_FAILED, result.code)
        val rollback = h.runner.withMarker(ROLLBACK_WRITE).single()
        assertContains(rollback, "dd if=" + quoted(File(h.txDir(SWITCH_ID), "pre-init_boot.img").absolutePath))
        assertContains(rollback, "of=" + quoted("/dev/block/by-name/init_boot_a"))
        val status = requireNotNull(result.status)
        assertEquals("ROLLED_BACK", status.state)
        assertEquals(h.preSha, status.partitions.first { it.name == "init_boot" }.observedSha256)
    }

    @Test
    fun commitRollbackFailureMarksRecoveryRequired() {
        val h = harness()
        fullFlow(h)
        h.runner.on(COMMIT_WRITE) { RootExecResult(RootBackend.ULTRA_ENV, 0, "${h.sourceSha}  /dev\n") }
        h.runner.on(ROLLBACK_WRITE) { RootExecResult(RootBackend.ULTRA_ENV, 0, "${h.sourceSha}  /dev\n") }
        val result = runBlocking { h.client.commit(SWITCH_ID) }
        assertFalse(result.ok)
        assertEquals(UltraRootSwitchCodes.ROLLBACK_VERIFY_FAILED, result.code)
        assertEquals("RECOVERY_REQUIRED", result.status!!.state)
    }

    // ------------------------------------------------------------------ exportImage

    @Test
    fun exportImageRejectsDestinationOutsideAllowedRoots() {
        val h = harness()
        beginOk(h)
        snapshotOk(h)
        val outside = File(h.workRoot, "outside.img")
        val exported = runBlocking {
            h.client.exportImage(SWITCH_ID, "PRE", "init_boot", outside)
        }
        assertFalse(exported)
        assertTrue(h.runner.withMarker(EXPORT).isEmpty())
    }

    @Test
    fun exportImageCopiesWithMode0644AndShaVerification() {
        val h = harness()
        beginOk(h)
        snapshotOk(h)
        val destination = File(h.outDir, "pre-init_boot.img")
        val exported = runBlocking {
            h.client.exportImage(SWITCH_ID, "PRE", "init_boot", destination)
        }
        assertTrue(exported)
        val script = h.runner.withMarker(EXPORT).single()
        assertContains(script, "cp -f")
        assertContains(script, "chmod 0644")
        assertContains(script, "sha256sum " + quoted(destination.absolutePath))
        assertContains(script, "mv -f")
    }

    @Test
    fun exportImageAllowsBaselineImageOfSourcePartition() {
        val h = harness()
        baselineManifest(h, "b1", bootSha = "d".repeat(64), initBootSha = h.preSha)
        beginOk(h, baselineId = "b1")
        snapshotOk(h)
        val destination = File(h.outDir, "base-boot.img")
        val exported = runBlocking {
            h.client.exportImage(SWITCH_ID, "BASE", "boot", destination)
        }
        assertTrue(exported)
        assertContains(h.runner.withMarker(EXPORT).single(), "sha256sum " + quoted(destination.absolutePath))
    }

    // ------------------------------------------------------------------ rollback / abort

    @Test
    fun rollbackUsesSnapshotAndVerifiesReadback() {
        val h = harness()
        fullFlow(h)
        commitOk(h)
        val result = runBlocking { h.client.rollback(SWITCH_ID) }
        assertTrue("${result.code} ${result.detail}", result.ok)
        val script = h.runner.withMarker(ROLLBACK_WRITE).single()
        assertContains(script, "dd if=" + quoted(File(h.txDir(SWITCH_ID), "pre-init_boot.img").absolutePath))
        assertEquals("ROLLED_BACK", result.status!!.state)
    }

    @Test
    fun rollbackRefusesWhenSnapshotMissing() {
        val h = harness()
        writeState(h, SWITCH_ID, "COMMIT")
        val result = runBlocking { h.client.rollback(SWITCH_ID) }
        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.PRE_IMAGE_INVALID, result.code)
        assertTrue(h.runner.withMarker(ROLLBACK_WRITE).isEmpty())
    }

    @Test
    fun abortOnlyCleansTransactionDirectory() {
        val h = harness()
        beginOk(h)
        val result = runBlocking { h.client.abort(SWITCH_ID) }
        assertTrue(result.ok)
        val script = h.runner.withMarker(ABORT).single()
        assertContains(script, "rm -rf " + quoted(h.txDir(SWITCH_ID).absolutePath))
        assertNotContains(script, "dd ")
        assertTrue(h.runner.withMarker(ROLLBACK_WRITE).isEmpty())
    }

    @Test
    fun abortRefusesAfterPartitionMayHaveBeenWritten() {
        val h = harness()
        writeState(h, SWITCH_ID, "REBOOT_REQUIRED")
        val result = runBlocking { h.client.abort(SWITCH_ID) }
        assertFalse(result.ok)
        assertEquals(UltraRootSwitchCodes.STATE_INVALID, result.code)
        assertTrue(h.runner.withMarker(ABORT).isEmpty())
    }

    // ------------------------------------------------------------------ verify / reboot / status

    @Test
    fun verifyRejectsChangedSlotBeforeAnyPartitionReadAndPreservesWaitingState() {
        val h = harness()
        fullFlow(h)
        commitOk(h)
        h.bootId = "boot-2"
        h.runner.on(SLOT, "_b\n")

        val result = runBlocking { h.client.verify(SWITCH_ID) }

        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.SLOT_INVALID, result.code)
        assertEquals("REBOOT_REQUIRED", h.persistedState()!!.state)
        assertTrue(h.runner.withMarker(VERIFY).isEmpty())
        assertTrue(h.runner.withMarker(ROLLBACK_WRITE).isEmpty())
    }

    @Test
    fun verifyRejectsUnreadableSlotBeforeAnyPartitionRead() {
        val h = harness()
        fullFlow(h)
        commitOk(h)
        h.bootId = "boot-2"
        h.runner.fail(SLOT)

        val result = runBlocking { h.client.verify(SWITCH_ID) }

        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.SLOT_INVALID, result.code)
        assertEquals("REBOOT_REQUIRED", h.persistedState()!!.state)
        assertTrue(h.runner.withMarker(VERIFY).isEmpty())
        assertTrue(h.runner.withMarker(ROLLBACK_WRITE).isEmpty())
    }

    @Test
    fun verifyRequiresObservedRebootThenComparesPartitionReadback() {
        val h = harness()
        fullFlow(h)
        commitOk(h)
        val unchanged = runBlocking { h.client.verify(SWITCH_ID) }
        assertFalse(unchanged.ok)
        assertEquals(ModeSwitchCodes.VERIFY_BOOT_NOT_OBSERVED, unchanged.code)
        assertTrue(h.runner.withMarker(VERIFY).isEmpty())
        h.bootId = "boot-2"
        val verified = runBlocking { h.client.verify(SWITCH_ID) }
        assertTrue("${verified.code} ${verified.detail}", verified.ok)
        assertTrue(h.runner.withMarker(VERIFY).any { it.contains("sha256sum '/dev/block/by-name/init_boot_a'") })
        assertEquals("VERIFIED", verified.status!!.state)
    }

    @Test
    fun verifyRestoredBootAndNormalCandidateBeforePublishingBothDigests() {
        val h = harness(requireBaselineForCommit = true)
        baselineManifest(h, bootSha = "d".repeat(64), initBootSha = h.preSha)
        fullFlow(h, baselineId = "b1")
        commitOk(h)
        h.bootId = "boot-2"

        val result = runBlocking { h.client.verify(SWITCH_ID) }

        assertTrue("${result.code} ${result.detail}", result.ok)
        val status = requireNotNull(result.status)
        assertEquals(listOf("init_boot", "boot"), status.partitions.map { it.name })
        val boot = status.partitions.single { it.name == "boot" }
        val initBoot = status.partitions.single { it.name == "init_boot" }
        assertEquals(h.bootBaselineSha, boot.targetSha256)
        assertEquals(h.bootBaselineSha, boot.observedSha256)
        assertEquals("VERIFIED", boot.state)
        assertEquals(h.targetSha, initBoot.targetSha256)
        assertEquals(h.targetSha, initBoot.observedSha256)
        assertEquals("VERIFIED", initBoot.state)
        assertEquals(2, h.runner.withMarker(VERIFY).size)
    }

    @Test
    fun verifyRejectsDamagedRestoredBootEvenWhenNormalCandidateStillMatches() {
        val h = harness(requireBaselineForCommit = true)
        baselineManifest(h, bootSha = "d".repeat(64), initBootSha = h.preSha)
        fullFlow(h, baselineId = "b1")
        commitOk(h)
        h.bootId = "boot-2"
        h.runner.on(VERIFY) { script ->
            val sha = if (script.contains("'/dev/block/by-name/boot_a'")) h.sourceSha else h.targetSha
            RootExecResult(RootBackend.ULTRA_ENV, 0, "$sha  /dev\n")
        }

        val result = runBlocking { h.client.verify(SWITCH_ID) }

        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.VERIFY_PARTITION_MISMATCH, result.code)
        assertEquals("RECOVERY_REQUIRED", result.status!!.state)
        assertContains(result.detail, "partition=boot")
    }

    @Test
    fun verifyRejectsUnreadableRestoredBoot() {
        val h = harness(requireBaselineForCommit = true)
        baselineManifest(h, bootSha = "d".repeat(64), initBootSha = h.preSha)
        fullFlow(h, baselineId = "b1")
        commitOk(h)
        h.bootId = "boot-2"
        h.runner.on(VERIFY) { script ->
            if (script.contains("'/dev/block/by-name/boot_a'")) RootExecResult(RootBackend.ULTRA_ENV, 1, "")
            else RootExecResult(RootBackend.ULTRA_ENV, 0, "${h.targetSha}  /dev\n")
        }

        val result = runBlocking { h.client.verify(SWITCH_ID) }

        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.VERIFY_PARTITION_MISMATCH, result.code)
        assertEquals("RECOVERY_REQUIRED", result.status!!.state)
        assertContains(result.detail, "partition=boot")
    }

    @Test
    fun verifyChecksAnUnwrittenSourceAgainstItsPreImage() {
        val h = harness()
        fullFlow(h)
        commitOk(h)
        assertTrue(h.runner.withMarker(RESTORE_WRITE).isEmpty())
        h.bootId = "boot-2"

        val result = runBlocking { h.client.verify(SWITCH_ID) }

        assertTrue("${result.code} ${result.detail}", result.ok)
        val boot = result.status!!.partitions.single { it.name == "boot" }
        assertEquals(h.sourceSha, boot.targetSha256)
        assertEquals(h.sourceSha, boot.observedSha256)
        assertEquals("VERIFIED", boot.state)
    }

    @Test
    fun verifyRejectsDamagedCandidateAfterTheRestoredSourcePassed() {
        val h = harness(requireBaselineForCommit = true)
        baselineManifest(h, bootSha = "d".repeat(64), initBootSha = h.preSha)
        fullFlow(h, baselineId = "b1")
        commitOk(h)
        h.bootId = "boot-2"
        h.runner.on(VERIFY) { script ->
            val sha = if (script.contains("'/dev/block/by-name/boot_a'")) h.bootBaselineSha else h.preSha
            RootExecResult(RootBackend.ULTRA_ENV, 0, "$sha  /dev\n")
        }

        val result = runBlocking { h.client.verify(SWITCH_ID) }

        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.VERIFY_PARTITION_MISMATCH, result.code)
        assertEquals("RECOVERY_REQUIRED", result.status!!.state)
        assertContains(result.detail, "partition=init_boot")
    }

    @Test
    fun verifyMismatchMarksRecoveryRequired() {
        val h = harness()
        fullFlow(h)
        commitOk(h)
        h.bootId = "boot-2"
        h.runner.on(VERIFY) { RootExecResult(RootBackend.ULTRA_ENV, 0, "${h.preSha}  /dev\n") }
        val result = runBlocking { h.client.verify(SWITCH_ID) }
        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.VERIFY_PARTITION_MISMATCH, result.code)
        assertEquals("RECOVERY_REQUIRED", result.status!!.state)
    }

    @Test
    fun markRebootRequestedOnlyInRebootRequiredState() {
        val h = harness()
        beginOk(h)
        snapshotOk(h)
        val early = runBlocking { h.client.markRebootRequested(SWITCH_ID) }
        assertFalse(early)
        submitOk(h)
        commitOk(h)
        val late = runBlocking { h.client.markRebootRequested(SWITCH_ID) }
        assertTrue(late)
        assertTrue(h.runner.withMarker(STATE_WRITE).isNotEmpty())
    }

    @Test
    fun statusReturnsNullWhenNothingReadable() {
        val h = harness()
        h.runner.fail(STATE_READ)
        h.runner.on(LIST_TX, "")
        assertNull(h.client.status(SWITCH_ID))
        assertNull(h.client.status(""))
        assertNull(h.client.status("bad id"))
    }

    @Test
    fun statusParsesStateFileAndLatestSwitchId() {
        val h = harness()
        writeState(h, "older", "BEGIN")
        h.stateFile("older").setLastModified(1_000L)
        writeState(h, SWITCH_ID, "REBOOT_REQUIRED", preSha = h.preSha, targetSha = h.targetSha)
        h.stateFile(SWITCH_ID).setLastModified(2_000L)
        val status = h.client.status("")
        assertNotNull(status)
        assertEquals(SWITCH_ID, status!!.switchId)
        assertEquals("REBOOT_REQUIRED", status.state)
        assertEquals("S4", status.stage)
        assertEquals(2, status.partitions.size)
        assertEquals(h.preSha, status.partitions.first { it.name == "init_boot" }.preSha256)
        assertEquals("REBOOT_REQUIRED", h.client.status(SWITCH_ID)!!.state)
    }

    @Test
    fun statusFallsBackToJournalHeadWhenStateMissing() {
        val h = harness()
        h.ensureTx(SWITCH_ID)
        val journal = UltraSwitchJournalRecord(
            op = "COMMIT_INTENT",
            state = "COMMIT",
            stage = "S4",
            step = "4d",
            partition = "init_boot",
        )
        h.journalFile(SWITCH_ID).writeText(ControlJsonCodec.encode(journal) + "\n")
        val status = h.client.status(SWITCH_ID)
        assertNotNull(status)
        assertEquals("COMMIT", status!!.state)
        assertEquals("4d", status.step)
        assertTrue(status.canRollback)
    }

    // ------------------------------------------------------------------ quoting / selector

    @Test
    fun everyDeviceAndImagePathIsSingleQuoted() {
        val h = harness(requireBaselineForCommit = true)
        baselineManifest(h, "b1", bootSha = "d".repeat(64), initBootSha = h.preSha)
        fullFlow(h, baselineId = "b1")
        commitOk(h)
        val targetDevice = "/dev/block/by-name/init_boot_a"
        val sourceDevice = "/dev/block/by-name/boot_a"
        val restore = h.runner.withMarker(RESTORE_WRITE).single()
        assertContains(restore, "dd if=" + quoted(File(h.txDir(SWITCH_ID), "base-boot.img").absolutePath))
        assertContains(restore, "of=" + quoted(sourceDevice))
        val commit = h.runner.withMarker(COMMIT_WRITE).single()
        assertContains(commit, "dd if=" + quoted(File(h.txDir(SWITCH_ID), "candidate-init_boot.img").absolutePath))
        assertContains(commit, "of=" + quoted(targetDevice))
        val bootSnapshot = h.runner.withMarker(SNAPSHOT_PRE + "boot").single()
        assertContains(bootSnapshot, "dd if=" + quoted(sourceDevice))
        assertContains(bootSnapshot, "of=" + quoted(File(h.txDir(SWITCH_ID), "pre-boot.img").absolutePath))
        val targetSnapshot = h.runner.withMarker(SNAPSHOT_PRE + "init_boot").single()
        assertContains(targetSnapshot, "dd if=" + quoted(targetDevice))
        assertContains(targetSnapshot, "of=" + quoted(File(h.txDir(SWITCH_ID), "pre-init_boot.img").absolutePath))
        h.runner.scripts.forEach { script ->
            assertFalse("unquoted sha256sum in:\n$script", Regex("sha256sum [^'\\n]").containsMatchIn(script))
        }
    }

    @Test
    fun shellEscapingHandlesSingleQuoteInWorkRoot() {
        val base = Files.createTempDirectory("maplesu-ultra-quote-").toFile()
        roots += base
        val quotedRoot = File(base, "work root's").apply { mkdirs() }
        val appRoot = File(base, "app").apply { mkdirs() }
        val runner = FakeRunner()
        runner.on(ROOT, "0\n")
        runner.on(SLOT, "_a\n")
        runner.on(DEVICE + "boot", "dev=/dev/block/by-name/boot_a\nsize=4096\n")
        runner.on(DEVICE + "init_boot", "dev=/dev/block/by-name/init_boot_a\nsize=4096\n")
        runner.on(FREE, "${64L * 1024 * 1024}\n")
        runner.on(WRITABLE, "1\n")
        val client = UltraRootModeSwitchClient(
            runner = runner,
            workRoot = quotedRoot,
            destinationRoots = listOf(appRoot),
        )
        val fields = mapOf("fromMode" to "LITE", "toMode" to "KSU", "baselineId" to "")
        assertTrue(runBlocking { client.preflight(SWITCH_ID, fields) }.ok)
        val superuser = File(base, "superuser.json").apply { writeText("{}") }
        val settings = File(base, "settings.json").apply { writeText("{}") }
        assertTrue(runBlocking { client.begin(SWITCH_ID, fields, superuser, settings) }.ok)
        val planPath = File(File(quotedRoot, "tx/$SWITCH_ID"), "plan.json").absolutePath
        val planScript = runner.withMarker(PLAN_WRITE).single()
        assertContains(planScript, quoted(planPath))
        assertContains(planScript, "'\\''")
        assertNotContains(planScript, "work root's/tx")
    }

    @Test
    fun concurrentStatusAndPreflightKeepTheSameClientForExecution() {
        for (target in listOf(WorkMode.KSU, WorkMode.LITE)) {
            val h = harness().also { it.toMode = target }
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val factories = AtomicInteger()
            val selecting = SelectingModeSwitchClient(RecordingClient("unused"), {
                if (factories.incrementAndGet() == 1) {
                    entered.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                }
                UltraRootModeSwitchClient(h.runner, h.workRoot, destinationRoots = listOf(h.appRoot))
            }, { true })
            val pool = Executors.newFixedThreadPool(2)
            try {
                val status = pool.submit<ClientStatus?> { selecting.status("") }
                assertTrue(entered.await(3, TimeUnit.SECONDS))
                val preflight = pool.submit<ClientResult> {
                    runBlocking { selecting.preflight(SWITCH_ID, h.planFields()) }
                }
                try { preflight.get(500, TimeUnit.MILLISECONDS) }
                catch (_: TimeoutException) { /* Correct serialization waits for the first factory. */ }
                finally { release.countDown() }
                status.get(3, TimeUnit.SECONDS)
                assertTrue(preflight.get(3, TimeUnit.SECONDS).ok)
                val (superuser, settings) = h.mirrors()
                val begun = runBlocking { selecting.begin(SWITCH_ID, h.planFields(), superuser, settings) }
                assertTrue("$target begin failed: ${begun.code}", begun.ok)
                assertEquals(1, factories.get())
            } finally {
                release.countDown()
                pool.shutdownNow()
            }
        }
    }

    @Test
    fun selectorKeepsServiceUntilLiteUltraAvailableAndPinsPro() {
        val service = RecordingClient("service")
        val ultra = RecordingClient("ultra")
        var usePro = false
        val selecting = SelectingModeSwitchClient(
            service = service,
            ultraFactory = { ultra },
            usePro = { usePro },
        )
        runBlocking { selecting.preflight(SWITCH_ID, mapOf("fromMode" to "LITE", "toMode" to "KSU")) }
        assertEquals(ModeSwitchClientKind.SERVICE, selecting.selectedKind())
        assertEquals(listOf("service"), RecordingClient.calls)
        RecordingClient.calls.clear()

        usePro = true
        runBlocking { selecting.preflight(SWITCH_ID, mapOf("fromMode" to "LITE", "toMode" to "KSU")) }
        assertEquals(ModeSwitchClientKind.ULTRA_ROOT, selecting.selectedKind())
        assertEquals(listOf("ultra"), RecordingClient.calls)
        RecordingClient.calls.clear()

        // 钉扎：即使探测暂时失败也不再回退到 SERVICE。
        usePro = false
        runBlocking { selecting.preflight(SWITCH_ID, mapOf("fromMode" to "LITE", "toMode" to "KSU")) }
        assertEquals(ModeSwitchClientKind.ULTRA_ROOT, selecting.selectedKind())
        assertEquals(listOf("ultra"), RecordingClient.calls)
    }

    @Test
    fun policyRequiresLiteModeAndUltraBackend() {
        assertEquals(
            ModeSwitchClientKind.ULTRA_ROOT,
            ModeSwitchClientPolicy.select(WorkMode.LITE, RootCapability(RootBackend.ULTRA_ENV, true)),
        )
        assertEquals(
            ModeSwitchClientKind.SERVICE,
            ModeSwitchClientPolicy.select(WorkMode.KSU, RootCapability(RootBackend.ULTRA_ENV, true)),
        )
        assertEquals(
            ModeSwitchClientKind.SERVICE,
            ModeSwitchClientPolicy.select(null, RootCapability(RootBackend.ULTRA_ENV, true)),
        )
        assertEquals(
            ModeSwitchClientKind.SERVICE,
            ModeSwitchClientPolicy.select(WorkMode.LITE, RootCapability(RootBackend.LITE_KERNEL, true)),
        )
        assertEquals(
            ModeSwitchClientKind.SERVICE,
            ModeSwitchClientPolicy.select(WorkMode.LITE, RootCapability.NONE),
        )
    }

    private class RecordingClient(private val name: String) : ModeSwitchClient {
        override suspend fun preflight(switchId: String, planFields: Map<String, String>): ClientResult {
            calls += name
            return ClientResult(true)
        }

        override suspend fun begin(
            switchId: String,
            planFields: Map<String, String>,
            superuserJson: File,
            settingsMirrorJson: File,
        ): ClientResult = error("not used")

        override suspend fun snapshot(switchId: String): ClientResult = error("not used")

        override suspend fun exportImage(
            switchId: String,
            kind: String,
            partition: String,
            destination: File,
        ): Boolean = error("not used")

        override suspend fun submitCandidate(
            switchId: String,
            partition: String,
            candidate: File,
            candidateSha256: String,
        ): ClientResult = error("not used")

        override suspend fun commit(switchId: String): ClientResult = error("not used")

        override suspend fun rollback(switchId: String): ClientResult = error("not used")

        override suspend fun abort(switchId: String): ClientResult = error("not used")

        override fun status(switchId: String): ClientStatus? = null

        override suspend fun verify(switchId: String): ClientResult = error("not used")

        override suspend fun markRebootRequested(switchId: String): Boolean = error("not used")

        override suspend fun exportLog(switchId: String, destination: File): File? = error("not used")

        companion object {
            val calls = mutableListOf<String>()
        }
    }
}
