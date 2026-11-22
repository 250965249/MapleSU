package dev.maplesu.manager.workmode.switch

import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.storage.FileMoveExecutor
import dev.maplesu.manager.workmode.storage.MoveEntry
import dev.maplesu.manager.workmode.storage.MoveFailure
import dev.maplesu.manager.workmode.storage.MoveKind
import dev.maplesu.manager.workmode.storage.MovePathRoots
import dev.maplesu.manager.workmode.storage.planSha256
import dev.maplesu.manager.workmode.storage.MovePlan
import dev.maplesu.manager.workmode.storage.MoveReport
import dev.maplesu.manager.workmode.storage.MoveSet
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption

/** S4 配置交换（4b/4e/4f）的一次计划：`MoveSet.plan` + 校验结论。 */
data class MoveStagePlan(
    val plan: MovePlan,
    val validationErrors: List<String>,
    val manifest: File,
) {
    val ok: Boolean get() = validationErrors.isEmpty()
}

data class MoveStageResult(
    val ok: Boolean,
    val code: String = "",
    val detail: String = "",
    val report: MoveReport? = null,
    val manifest: File? = null,
)

/**
 * S4「交换配置」端口（02 §5.4：4b 出仓 → 4c/4d 分区 → 4e 入仓 → 4f 物化）。
 *
 * 真实实现 [FileSwitchMoveStage] 只调用 `MoveSet` + `FileMoveExecutor`；
 * 分区写入不在这里（红线 4）。主机测试注入临时 roots；生产由 root 适配器注入
 * `MovePathRoots(liveRoot=File("/"), storeRoot=File(MoveSet.STORE_ROOT))`。
 */
interface SwitchMoveStage {
    fun plan(switchId: String, from: WorkMode, to: WorkMode): MoveStagePlan

    fun moveOut(plan: MoveStagePlan, journal: SwitchJournal): MoveStageResult

    fun moveIn(plan: MoveStagePlan, journal: SwitchJournal): MoveStageResult

    /** 逆序撤销（入仓→出仓），失败必须在 journal 留 MOVE_BACK/FAIL。 */
    fun rollback(plan: MoveStagePlan, journal: SwitchJournal): MoveStageResult

    /** 4f：目标预物化 + 备份证据写盘（manifest），并校验 live/store 不变量。 */
    fun materialize(plan: MoveStagePlan, journal: SwitchJournal): MoveStageResult

    /** S6/恢复：出仓后 live 消失、store 存在；入仓后 live 存在、store 消失。 */
    fun verify(plan: MoveStagePlan): MoveStageResult
}

/**
 * journal 适配：`FileMoveExecutor` 用 `MovePlan.planSha256()` 写行，而 `switch.json` 的权威
 * planSha 是 `SwitchPlan.planSha256`（02 §3.3 要求 journal 行与 switch.json 一致）。
 * 本适配器把 append 的 planSha 固定为切换计划摘要，并原样转发其余字段。
 */
internal class FixedPlanJournal(
    private val delegate: SwitchJournal,
    private val planSha256: String,
) : SwitchJournal {
    override fun append(
        switchId: String,
        planSha256: String,
        stage: String,
        step: String,
        op: SwitchOp,
        partition: String,
        expectedSha256: String,
        observedSha256: String,
        code: String,
    ): JournalLine = delegate.append(
        switchId, this.planSha256, stage, step, op, partition, expectedSha256, observedSha256, code,
    )

    override fun appendRaw(line: String): Long = delegate.appendRaw(line)
    override fun read(): JournalRead = delegate.read()
    override fun last(): JournalLine? = delegate.last()
    override fun replay(switchId: String?): JournalReplay = delegate.replay(switchId)
}

/**
 * 真实文件系统实现（只读调用 `MoveSet`/`FileMoveExecutor`）。
 *
 * 备份/还原证据链：每次 moveOut/moveIn/materialize 都在 `workRoot/<switchId>/move-manifest.json`
 * 追加一段结构快照（条目、owner、storePath、live/store 存在性、阶段结论）。
 * 因为 move 是 **rename（同挂载）** 或 **copy+读回+删源（跨挂载）**，出仓后离线仓即完整副本，
 * 回滚 = 入仓方向的逆操作；manifest 是"可逆与可还原"的持久证据（另见 01 §3.4 A1–A8）。
 */
class FileSwitchMoveStage(
    private val roots: MovePathRoots,
    private val dynamicFrom: List<MoveEntry> = emptyList(),
    private val dynamicTo: List<MoveEntry> = emptyList(),
) : SwitchMoveStage {

    private val executor = FileMoveExecutor(roots)

    override fun plan(switchId: String, from: WorkMode, to: WorkMode): MoveStagePlan {
        val plan = MoveSet.plan(switchId, from, to, dynamicFrom = dynamicFrom, dynamicTo = dynamicTo)
        // 出/入是两次独立的 move 子计划（同一 livePath 会在方向上重复出现，属正常切换语义），
        // 因此分别按 MoveSet 的路径规则校验，而不是把两段合并成一份 plan。
        val errors = (MoveSet.validate(plan.outbound, plan.owners) +
            MoveSet.validate(plan.inbound, plan.owners)).distinct()
        return MoveStagePlan(plan, errors, File(workRootOf(switchId), "move-manifest.json"))
    }

    private fun workRootOf(switchId: String): File {
        // manifest 写在 storeRoot 旁的 switch work 目录由调用方约定：liveRoot 无关；
        // 采用 storeRoot 下的 boot/work/<id>（设备 = /data/adb/maplesu-workmode/boot/work/<id>）。
        return File(roots.storeRoot, "boot/work/$switchId")
    }

    override fun moveOut(plan: MoveStagePlan, journal: SwitchJournal): MoveStageResult =
        run(plan, journal, "OUT", "MOVE_OUT_FAILED") {
            executor.execute(plan.plan.copy(inbound = emptyList()), fixed(plan, journal))
        }

    override fun moveIn(plan: MoveStagePlan, journal: SwitchJournal): MoveStageResult =
        run(plan, journal, "IN", "MOVE_IN_FAILED") {
            executor.execute(plan.plan.copy(outbound = emptyList()), fixed(plan, journal))
        }

    override fun rollback(plan: MoveStagePlan, journal: SwitchJournal): MoveStageResult =
        run(plan, journal, "ROLLBACK", "MOVE_ROLLBACK_FAILED") {
            executor.rollback(plan.plan, fixed(plan, journal))
        }

    override fun materialize(plan: MoveStagePlan, journal: SwitchJournal): MoveStageResult {
        val mismatch = verifyInvariants(plan.plan, requireInboundApplied = true)
        val detail = MoveSet.redactEvidence(if (mismatch.isEmpty()) "materialized" else mismatch.joinToString(","))
        appendManifest(plan, "MATERIALIZE", SwitchOp.MATERIALIZE_INTENT, mismatch.isEmpty(), detail)
        if (mismatch.isEmpty()) {
            journal.append(plan.plan.switchId, plan.planSha(), "S4", "4f", SwitchOp.MATERIALIZE_DONE)
        } else {
            journal.append(plan.plan.switchId, plan.planSha(), "S4", "4f", SwitchOp.FAIL, code = detail)
        }
        return MoveStageResult(mismatch.isEmpty(), if (mismatch.isEmpty()) "" else "MOVE_VERIFY_FAILED",
            detail, manifest = plan.manifest)
    }

    override fun verify(plan: MoveStagePlan): MoveStageResult {
        val mismatch = verifyInvariants(plan.plan, requireInboundApplied = true)
        return MoveStageResult(mismatch.isEmpty(), if (mismatch.isEmpty()) "" else "MOVE_VERIFY_FAILED",
            MoveSet.redactEvidence(mismatch.joinToString(",")), manifest = plan.manifest)
    }

    // ------------------------------------------------------------------ internals

    private fun fixed(plan: MoveStagePlan, journal: SwitchJournal): SwitchJournal =
        FixedPlanJournal(journal, plan.planSha())

    private fun MoveStagePlan.planSha(): String =
        plan.planSha256()

    private fun run(
        plan: MoveStagePlan,
        journal: SwitchJournal,
        phase: String,
        code: String,
        action: () -> MoveReport,
    ): MoveStageResult {
        if (!plan.ok) {
            return MoveStageResult(false, "MOVE_PLAN_INVALID", MoveSet.redactEvidence(plan.validationErrors.joinToString(",")),
                manifest = plan.manifest)
        }
        return try {
            val report = action()
            appendManifest(plan, phase, null, report.ok, report.failures.joinToString(";") {
                "${it.livePath}:${it.code}"
            })
            if (report.ok) {
                MoveStageResult(true, report = report, manifest = plan.manifest)
            } else {
                MoveStageResult(false, code, report.failures.joinToString(","), report, plan.manifest)
            }
        } catch (error: IOException) {
            appendManifest(plan, phase, null, false, error.message.orEmpty())
            MoveStageResult(false, code, MoveSet.redactEvidence(error.message.orEmpty()), null, plan.manifest)
        } catch (error: RuntimeException) {
            appendManifest(plan, phase, null, false, error.message.orEmpty())
            MoveStageResult(false, code, MoveSet.redactEvidence(error.message.orEmpty()), null, plan.manifest)
        }
    }

    /** 出仓后 live/store 不得同时存在（同一路径只允许一个真实副本）；入仓后 store 必须消失。 */
    private fun verifyInvariants(plan: MovePlan, requireInboundApplied: Boolean): List<String> {
        val failures = mutableListOf<String>()
        for (entry in plan.outbound) {
            // The target mode now owns shared live paths; the source mode belongs in its store.
            if (plan.inbound.any { it.livePath == entry.livePath }) continue
            val live = roots.live(entry.livePath)
            val store = roots.store(MoveSet.storePathFor(entry.owner, entry.livePath))
            if (exists(live) && exists(store) && !isSameFile(live, store)) {
                val preserved = MoveSet.preservedPathsUnder(entry.livePath).map { roots.live(it) }
                if (!live.isDirectory || live.listFiles().orEmpty().any { it !in preserved }) {
                    failures += "ambiguous:${entry.livePath}"
                }
            }
        }
        for (entry in plan.inbound) {
            val live = roots.live(entry.livePath)
            val store = roots.store(MoveSet.storePathFor(entry.owner, entry.livePath))
            if (exists(store)) failures += "store-remnant:${entry.livePath}"
            // 软链目标必须保留（MoveEntry.SYMLINK 的 target 校验）。
            if (entry.kind == MoveKind.SYMLINK) {
                val target = runCatching { Files.readSymbolicLink(live.toPath()) }.getOrNull()
                if (exists(live) && target == null) failures += "symlink-target-lost:${entry.livePath}"
            }
        }
        return failures
    }

    private fun isSameFile(a: File, b: File): Boolean =
        runCatching { a.canonicalPath == b.canonicalPath }.getOrDefault(false)

    private fun exists(file: File): Boolean =
        Files.exists(file.toPath(), LinkOption.NOFOLLOW_LINKS) || file.exists() || Files.isSymbolicLink(file.toPath())

    private fun appendManifest(
        plan: MoveStagePlan,
        phase: String,
        op: SwitchOp?,
        ok: Boolean,
        detail: String,
    ) {
        val file = plan.manifest
        file.parentFile?.mkdirs()
        val lines = buildList {
            add("{\"schema\":1,\"switchId\":\"${plan.plan.switchId}\",\"phase\":\"$phase\"," +
                "\"from\":\"${plan.plan.from.suffix}\",\"to\":\"${plan.plan.to.suffix}\"," +
                "\"ok\":$ok,\"detail\":\"${detail.replace('"', '\'')}\"," +
                "\"outbound\":${plan.plan.outbound.size},\"inbound\":${plan.plan.inbound.size}}")
            (plan.plan.outbound + plan.plan.inbound).forEach { entry ->
                val store = roots.store(MoveSet.storePathFor(entry.owner, entry.livePath))
                add("  entry live=${entry.livePath} owner=${entry.owner.suffix} kind=${entry.kind} " +
                    "mount=${entry.mount} expected=${entry.expectedShape} store=${store.path} " +
                    "storeExists=${exists(store)}")
            }
        }
        file.appendText(MoveSet.redactEvidence(lines.joinToString("\n")) + "\n")
    }
}
