package dev.maplesu.manager.parasite

import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.control.ControlPaths
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.WallClock
import kotlinx.serialization.Serializable
import java.io.File
import java.io.IOException

/** 控制面路径（/data/adb/maplesu-workmode/parasite；root 0700）。 */
object ParasitePaths {
    const val ROOT: String = "${ControlPaths.ROOT}/parasite"
    const val JOURNAL: String = "$ROOT/journal.jsonl"
    const val RECOVERY: String = "$ROOT/recovery"

    /** 备份/日志必须位于控制面（普通 App 不可读）；主机测试用注入目录绕过。 */
    fun isControlPlanePath(file: File): Boolean {
        val path = runCatching { file.canonicalPath }.getOrElse { file.absolutePath }
        return path.startsWith(ControlPaths.ROOT + "/") || path == ControlPaths.ROOT
    }

    fun journal(root: File = File(ROOT)): File = File(root, "journal.jsonl")
    fun recovery(root: File = File(ROOT)): File = File(root, "recovery")
}

/** journal 行：每次状态/事件追加一行（append-only + fsync），用于断点重建。 */
@Serializable
data class ParasiteJournalLine(
    val schema: Int = SCHEMA,
    val seq: Long,
    val at: Long,
    val state: String,
    val event: String,
    val code: String = "",
    val detail: String = "",
    /** 完整记录快照（可选；有它即可重建宿主记录）。 */
    val record: ParasiteHostRecord? = null,
) {
    companion object { const val SCHEMA = 1 }
}

object ParasiteJournalCodes {
    const val PARSE_FAILED = "PARASITE_JOURNAL_PARSE_FAILED"
    const val SEQ_GAP = "PARASITE_JOURNAL_SEQ_GAP"
    const val WRITE_FAILED = "PARASITE_JOURNAL_WRITE_FAILED"
}

sealed interface ParasiteJournalRead {
    data class Ok(val lines: List<ParasiteJournalLine>, val truncatedTail: Boolean) : ParasiteJournalRead
    data class Corrupt(val code: String, val detail: String, val lines: List<ParasiteJournalLine>) :
        ParasiteJournalRead
}

/**
 * 寄生 journal：控制面 JSONL（0600，append + fd.sync）。
 *
 * 崩溃语义：末行无 '\n' → 丢弃半行；下一次 append 前先重写修复（不会把半行与新行粘住）。
 * seq 断号 → Corrupt（调用方进恢复流程，不猜状态）；解析失败同样 Corrupt。
 */
class ParasiteJournal(
    private val file: File = ParasitePaths.journal(),
    private val clock: Clock = WallClock,
) {
    fun append(
        state: ParasiteState,
        event: String,
        record: ParasiteHostRecord? = null,
        code: String = "",
        detail: String = "",
    ): ParasiteJournalLine {
        val raw = readRaw()
        raw.corruptCode?.let { throw IllegalStateException(it) }
        repairTruncatedTail(raw)
        val line = ParasiteJournalLine(
            seq = (raw.lines.lastOrNull()?.seq ?: 0L) + 1,
            at = clock.nowMillis(),
            state = state.name,
            event = event,
            code = code,
            detail = detail,
            record = record?.copy(state = state.name, updatedAt = clock.nowMillis()),
        )
        ensureParent()
        AtomicControlFile.appendLine(file, ControlJsonCodec.encode(line))
        return line
    }

    fun read(): ParasiteJournalRead {
        val raw = readRaw()
        return if (raw.corruptCode != null) {
            ParasiteJournalRead.Corrupt(raw.corruptCode, raw.detail, raw.lines)
        } else {
            ParasiteJournalRead.Ok(raw.lines, raw.truncatedTail)
        }
    }

    /** 断点重建：最后一条带 record 的快照 + 最新 state；无记录 → null。 */
    fun rebuild(): ParasiteHostRecord? {
        val lines = when (val read = read()) {
            is ParasiteJournalRead.Ok -> read.lines
            is ParasiteJournalRead.Corrupt -> read.lines
        }
        val last = lines.lastOrNull() ?: return null
        val base = lines.asReversed().firstNotNullOfOrNull { it.record } ?: return null
        return base.copy(state = last.state, updatedAt = last.at)
    }

    fun lastState(): ParasiteState? = when (val read = read()) {
        is ParasiteJournalRead.Ok -> read.lines.lastOrNull()?.let { line ->
            ParasiteState.entries.firstOrNull { it.name == line.state }
        }
        is ParasiteJournalRead.Corrupt -> null
    }

    fun history(): List<ParasiteJournalLine> = when (val read = read()) {
        is ParasiteJournalRead.Ok -> read.lines
        is ParasiteJournalRead.Corrupt -> read.lines
    }

    private data class RawRead(
        val lines: List<ParasiteJournalLine>,
        val truncatedTail: Boolean,
        val corruptCode: String?,
        val detail: String,
    )

    private fun readRaw(): RawRead {
        if (!file.isFile) return RawRead(emptyList(), false, null, "")
        val text = runCatching { file.readText(Charsets.UTF_8) }.getOrElse {
            return RawRead(emptyList(), false, ParasiteJournalCodes.PARSE_FAILED, "unreadable")
        }
        if (text.isEmpty()) return RawRead(emptyList(), false, null, "")
        val truncatedTail = !text.endsWith("\n")
        val completeLines = text.split('\n').dropLast(1)
        val lines = mutableListOf<ParasiteJournalLine>()
        for ((index, rawText) in completeLines.withIndex()) {
            val raw = rawText.trimEnd('\r')
            if (raw.isEmpty()) continue
            val parsed = ControlJsonCodec.decodeOrNull<ParasiteJournalLine>(raw)
                ?: return RawRead(
                    lines, truncatedTail, ParasiteJournalCodes.PARSE_FAILED, "line=${index + 1}",
                )
            val expected = (lines.lastOrNull()?.seq ?: 0L) + 1
            if (parsed.seq != expected) {
                return RawRead(
                    lines, truncatedTail, ParasiteJournalCodes.SEQ_GAP,
                    "expected=$expected actual=${parsed.seq}",
                )
            }
            lines += parsed
        }
        return RawRead(lines, truncatedTail, null, "")
    }

    private fun repairTruncatedTail(raw: RawRead) {
        if (!raw.truncatedTail) return
        ensureParent()
        val content = if (raw.lines.isEmpty()) ByteArray(0) else {
            (raw.lines.joinToString("\n") { ControlJsonCodec.encode(it) } + "\n").toByteArray(Charsets.UTF_8)
        }
        AtomicControlFile.writeUtf8(file, content)
    }

    private fun ensureParent() {
        val parent = file.parentFile ?: return
        if (!parent.exists() && !parent.mkdirs() && !parent.isDirectory) {
            throw IOException(ParasiteJournalCodes.WRITE_FAILED)
        }
    }
}
