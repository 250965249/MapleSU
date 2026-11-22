package dev.maplesu.manager.workmode.switch

import dev.maplesu.installer.SwitchEvent
import dev.maplesu.installer.SwitchJournalSink
import java.io.IOException

/**
 * `installer-core` 的 journal 屏障 → Manager WAL 的适配器（02 §4.7）。
 *
 * 多分区事务只认 `SwitchJournalSink`（Java）。Manager 的 `SwitchJournal` 是唯一 WAL 写入口
 * （含 seq/prev 链与 fsync），本类负责字段映射，**不**另立 journal。
 */
class ModeSwitchJournalSink(
    private val journal: SwitchJournal,
    private val switchId: String,
    private val onLine: ((JournalLine) -> Unit)? = null,
) : SwitchJournalSink {

    override fun append(event: SwitchEvent) {
        if (event.switchId != switchId) throw IOException("SWITCH_PLAN_CONFLICT: journal switchId")
        val op = SwitchOp.fromWire(event.op.name)
            ?: throw IOException("JOURNAL_PARSE_FAILED: ${event.op.name}")
        val line = journal.append(
            switchId = event.switchId,
            planSha256 = event.planSha256,
            stage = event.stage,
            step = event.step,
            op = op,
            partition = event.partition,
            expectedSha256 = event.expectedSha256,
            observedSha256 = event.observedSha256,
            code = event.code,
        )
        onLine?.invoke(line)
    }
}
