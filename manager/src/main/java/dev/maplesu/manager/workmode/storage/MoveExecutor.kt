package dev.maplesu.manager.workmode.storage

import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.switch.SwitchJournal

/**
 * 出/入 rename 执行器。
 *
 * 实现：[FileMoveExecutor]（W04b）。接口相对 01 §3.4 有两处**有意调整**（已在交付报告登记）：
 * - `converge(plan, journal)` / `rollback(plan, journal)` 显式带 [MovePlan]：02 §3.3 的
 *   `journal.jsonl` 字段集里没有 livePath（路径在 `switch.json.moves[]` 中），仅凭 journal
 *   无法定位要收敛的路径；把 plan 作为参数传入才能做到 01 A6 的"四态收敛，绝不猜"。
 * - journal 行仍按 02 §3.3 的固定字段写入（`op=MOVE_*`），不新增字段。
 */
interface MoveExecutor {
    /** 一次调用内完成出+入；失败时返回 failures，调用方据此决定回滚。 */
    fun execute(plan: MovePlan, journal: SwitchJournal): MoveReport

    /** 逆序撤销一次 [execute]（出/入的反向）；返回已回滚路径。 */
    fun rollback(plan: MovePlan, journal: SwitchJournal): MoveReport

    /** 按 plan 逐项四态收敛（崩溃恢复）：源在/目标在/都在/都不在，绝不猜。 */
    fun converge(plan: MovePlan, journal: SwitchJournal): MoveReport
}

data class MovePlan(
    val switchId: String,
    val from: WorkMode,
    val to: WorkMode,
    /** 逆序执行（见 MoveSet.outboundOrder）。 */
    val outbound: List<MoveEntry>,
    /** 正序执行（见 MoveSet.inboundOrder）。 */
    val inbound: List<MoveEntry>,
    val owners: Map<String, WorkMode>,
)

data class MoveReport(
    val movedOut: List<String>,
    val movedIn: List<String>,
    /** 源不存在 / 已收敛。 */
    val skipped: List<String>,
    val failures: List<MoveFailure>,
) {
    val ok: Boolean get() = failures.isEmpty()

    override fun toString(): String = MoveSet.redactEvidence(
        "MoveReport(movedOut=$movedOut, movedIn=$movedIn, skipped=$skipped, failures=$failures)",
    )

    companion object {
        fun empty(): MoveReport = MoveReport(emptyList(), emptyList(), emptyList(), emptyList())
    }
}

data class MoveFailure(val livePath: String, val code: String, val detail: String) {
    override fun toString(): String = MoveSet.redactEvidence(
        "MoveFailure(livePath=$livePath, code=$code, detail=$detail)",
    )
}
