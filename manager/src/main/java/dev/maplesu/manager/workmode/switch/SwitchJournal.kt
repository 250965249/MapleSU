package dev.maplesu.manager.workmode.switch

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.ProcBootIdSource
import dev.maplesu.manager.workmode.detect.WallClock
import kotlinx.serialization.Serializable
import java.io.File
import java.io.IOException

/**
 * `boot/work/<switchId>/journal.jsonl`（WAL）字段级 schema。
 *
 * 两层持久化：`control/switch.json` 是权威状态（原子替换）；本文件是追证 WAL
 * （append + fd.sync() + prev 链），用于 `switch.json` 损坏/丢失时重建最近已知状态。
 * 任何实现不得同时写两处状态。
 */
@Serializable
data class JournalLine(
    val schema: Int = SCHEMA,
    /** 从 1 单调 +1；断号 → RECOVERY_JOURNAL_CORRUPT。 */
    val seq: Long,
    val switchId: String,
    val planSha256: String,
    val atUptimeMs: Long,
    val bootId: String,
    val stage: String,
    val step: String,
    val partition: String = "",
    val op: String,
    val expectedSha256: String = "",
    val observedSha256: String = "",
    val code: String = "",
    /** 上一行字节的 sha256，首行为 64 个 0。 */
    val prev: String,
) {
    companion object {
        const val SCHEMA = 1
        val ZERO_PREV = "0".repeat(64)
    }
}

/** WAL 操作集合（02 §3.3）。 */
enum class SwitchOp(val wire: String) {
    PREPARED("PREPARED"),
    INTENT("INTENT"),
    DONE("DONE"),
    FAIL("FAIL"),
    SKIP("SKIP"),
    ROLLBACK_INTENT("ROLLBACK_INTENT"),
    ROLLBACK_DONE("ROLLBACK_DONE"),
    MOVE_INTENT("MOVE_INTENT"),
    MOVE_DONE("MOVE_DONE"),
    MOVE_BACK("MOVE_BACK"),
    MATERIALIZE_INTENT("MATERIALIZE_INTENT"),
    MATERIALIZE_DONE("MATERIALIZE_DONE"),
    COMMIT_INTENT("COMMIT_INTENT"),
    REBOOT_PENDING("REBOOT_PENDING"),
    VERIFIED("VERIFIED"),
    RECOVERY_REQUIRED("RECOVERY_REQUIRED");

    companion object {
        fun fromWire(value: String?): SwitchOp? = entries.firstOrNull { it.wire == value }
    }
}

object JournalErrors {
    const val PARSE_FAILED = "JOURNAL_PARSE_FAILED"
    const val SEQ_GAP = "RECOVERY_JOURNAL_CORRUPT"
    const val PREV_CHAIN_BROKEN = "JOURNAL_PREV_CHAIN_BROKEN"
    const val WRITE_FAILED = "JOURNAL_WRITE_FAILED"
}

sealed interface JournalRead {
    /** [truncatedTail] = 末行没有 '\n'（半写）；半写行已被丢弃，其余可用。 */
    data class Ok(val lines: List<JournalLine>, val truncatedTail: Boolean) : JournalRead

    data class Corrupt(val code: String, val detail: String, val lines: List<JournalLine>) : JournalRead
}

sealed interface JournalReplay {
    data object Empty : JournalReplay

    data class Known(
        val seq: Long,
        val state: String,
        val stage: String,
        val step: String,
        val lastOp: String,
        val rebootRequested: Boolean,
        val recoveryRequired: Boolean,
    ) : JournalReplay

    /** 只降级为"取证不可信"，**不**据此判定分区状态（分区状态永远靠读回）。 */
    data class Degraded(val code: String, val hint: JournalReplay?) : JournalReplay
}

/**
 * WAL 门面（01 §3.4 的 `MoveExecutor` 参数类型；写侧由切换服务在 S4 内使用）。
 * 只保证：append + fsync、seq 单调、prev 链、末行截断可判定。
 */
interface SwitchJournal {
    fun append(
        switchId: String,
        planSha256: String,
        stage: String,
        step: String,
        op: SwitchOp,
        partition: String = "",
        expectedSha256: String = "",
        observedSha256: String = "",
        code: String = "",
    ): JournalLine

    /** 服务端自己组装 wire 行（格式由 02 定稿）；返回追加后的 seq。 */
    fun appendRaw(line: String): Long

    fun read(): JournalRead

    fun last(): JournalLine?

    /** 由 WAL 重放"最近已知状态"；损坏时返回 [JournalReplay.Degraded]。 */
    fun replay(switchId: String? = null): JournalReplay
}

/** WAL 重放规则（纯函数，主机可测）。 */
object JournalReplayRules {
    fun derive(lines: List<JournalLine>): JournalReplay {
        if (lines.isEmpty()) return JournalReplay.Empty
        var state = SwitchStateNames.BEGIN
        for (line in lines) {
            state = when (line.op) {
                SwitchOp.ROLLBACK_DONE.wire -> SwitchStateNames.ROLLED_BACK
                SwitchOp.RECOVERY_REQUIRED.wire -> SwitchStateNames.RECOVERY_REQUIRED
                SwitchOp.VERIFIED.wire -> SwitchStateNames.VERIFIED
                SwitchOp.ROLLBACK_INTENT.wire -> SwitchStateNames.ROLLING_BACK
                SwitchOp.REBOOT_PENDING.wire ->
                    if (state == SwitchStateNames.VERIFIED || state == SwitchStateNames.ROLLED_BACK) {
                        state
                    } else {
                        SwitchStateNames.REBOOT_REQUIRED
                    }
                SwitchOp.COMMIT_INTENT.wire,
                SwitchOp.MOVE_INTENT.wire,
                SwitchOp.MOVE_DONE.wire,
                SwitchOp.MOVE_BACK.wire,
                SwitchOp.MATERIALIZE_INTENT.wire,
                SwitchOp.MATERIALIZE_DONE.wire ->
                    if (state in SwitchStateNames.TERMINAL) state else SwitchStateNames.COMMIT
                SwitchOp.PREPARED.wire -> SwitchStateNames.BEGIN
                else -> state
            }
        }
        val last = lines.last()
        return JournalReplay.Known(
            seq = last.seq,
            state = state,
            stage = last.stage,
            step = last.step,
            lastOp = last.op,
            rebootRequested = state == SwitchStateNames.REBOOT_REQUIRED,
            recoveryRequired = state == SwitchStateNames.RECOVERY_REQUIRED,
        )
    }
}

/**
 * 文件实现（主机可测）。
 *
 * 崩溃语义：末行无 '\n' → 丢弃末行（半写），其余保留并记 `JOURNAL_TRUNCATED_TAIL`；
 * 下一次 append 前先修复文件（重写完整行），保证不会把半行与新行粘在一起。
 * seq 断号 → `RECOVERY_JOURNAL_CORRUPT`；`prev` 失配只降级取证可信度。
 */
class FileSwitchJournal(
    private val file: File,
    private val clock: Clock = WallClock,
    private val bootIdSource: BootIdSource = ProcBootIdSource,
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
    ): JournalLine {
        val raw = readRaw()
        raw.corruptCode?.let { throw IllegalStateException(it) }
        repairTruncatedTail(raw)
        val lastLine = raw.lines.lastOrNull()
        val lastRaw = raw.raws.lastOrNull()
        val line = JournalLine(
            seq = (lastLine?.seq ?: 0L) + 1,
            switchId = switchId,
            planSha256 = planSha256,
            atUptimeMs = clock.nowMillis(),
            bootId = bootIdSource.read(),
            stage = stage,
            step = step,
            partition = partition,
            op = op.wire,
            expectedSha256 = expectedSha256,
            observedSha256 = observedSha256,
            code = code,
            prev = lastRaw?.let { Hashes.sha256(it.toByteArray(Charsets.UTF_8)) }
                ?: JournalLine.ZERO_PREV,
        )
        ensureParent()
        AtomicControlFile.appendLine(file, ControlJsonCodec.encode(line))
        return line
    }

    override fun appendRaw(line: String): Long {
        // 02 §3.3 的格式由服务端拥有；本方法只保证 append + fsync + seq 单调，
        // 因此不解析整行（未知格式不得阻断写侧），只修掉半写末行并统计完整行数。
        val raw = readRaw()
        repairTruncatedTail(raw)
        ensureParent()
        AtomicControlFile.appendLine(file, line.trim())
        return countCompleteLines()
    }

    /** 完整行数（以 '\n' 计；末行半写不计）。 */
    private fun countCompleteLines(): Long {
        if (!file.isFile) return 0
        val bytes = runCatching { file.readBytes() }.getOrNull() ?: return 0
        return bytes.count { it == '\n'.code.toByte() }.toLong()
    }

    override fun read(): JournalRead {
        val raw = readRaw()
        val code = raw.corruptCode
        return if (code != null) {
            JournalRead.Corrupt(code, raw.detail, raw.lines)
        } else {
            JournalRead.Ok(raw.lines, raw.truncatedTail)
        }
    }

    override fun last(): JournalLine? = when (val read = read()) {
        is JournalRead.Ok -> read.lines.lastOrNull()
        is JournalRead.Corrupt -> read.lines.lastOrNull()
    }

    override fun replay(switchId: String?): JournalReplay {
        val read = read()
        val lines = when (read) {
            is JournalRead.Ok -> read.lines
            is JournalRead.Corrupt -> read.lines
        }.filter { switchId == null || it.switchId == switchId }
        return when (read) {
            is JournalRead.Ok -> JournalReplayRules.derive(lines)
            is JournalRead.Corrupt -> JournalReplay.Degraded(read.code, JournalReplayRules.derive(lines))
        }
    }

    private data class RawRead(
        val raws: List<String>,
        val lines: List<JournalLine>,
        val truncatedTail: Boolean,
        val corruptCode: String?,
        val detail: String,
    )

    private fun readRaw(): RawRead {
        if (!file.isFile) return RawRead(emptyList(), emptyList(), false, null, "")
        val bytes = runCatching { file.readBytes() }.getOrElse {
            return RawRead(emptyList(), emptyList(), false, JournalErrors.PARSE_FAILED, "unreadable")
        }
        if (bytes.isEmpty()) return RawRead(emptyList(), emptyList(), false, null, "")
        val text = bytes.toString(Charsets.UTF_8)
        val truncatedTail = !text.endsWith("\n")
        // 对于 "a\nb\n" → ["a","b",""]；对于 "a\nb"（半写）→ ["a","b"]。统一 dropLast(1)。
        val completeLines = text.split('\n').dropLast(1)
        val raws = mutableListOf<String>()
        val lines = mutableListOf<JournalLine>()
        for ((index, rawText) in completeLines.withIndex()) {
            val raw = rawText.trimEnd('\r')
            if (raw.isEmpty()) continue
            val parsed = ControlJsonCodec.decodeOrNull<JournalLine>(raw)
                ?: return RawRead(
                    raws, lines, truncatedTail, JournalErrors.PARSE_FAILED, "line=${index + 1}",
                )
            val expectedSeq = (lines.lastOrNull()?.seq ?: 0L) + 1
            if (parsed.seq != expectedSeq) {
                return RawRead(
                    raws, lines, truncatedTail, JournalErrors.SEQ_GAP,
                    "expected=$expectedSeq actual=${parsed.seq}",
                )
            }
            val expectedPrev = raws.lastOrNull()
                ?.let { Hashes.sha256(it.toByteArray(Charsets.UTF_8)) }
                ?: JournalLine.ZERO_PREV
            if (!parsed.prev.equals(expectedPrev, ignoreCase = true)) {
                return RawRead(
                    raws, lines, truncatedTail, JournalErrors.PREV_CHAIN_BROKEN,
                    "seq=${parsed.seq}",
                )
            }
            raws += raw
            lines += parsed
        }
        return RawRead(raws, lines, truncatedTail, null, "")
    }

    private fun repairTruncatedTail(raw: RawRead) {
        if (!raw.truncatedTail) return
        ensureParent()
        val content = if (raw.raws.isEmpty()) {
            ByteArray(0)
        } else {
            (raw.raws.joinToString("\n") + "\n").toByteArray(Charsets.UTF_8)
        }
        AtomicControlFile.writeUtf8(file, content)
    }

    private fun ensureParent() {
        val parent = file.parentFile ?: return
        if (!parent.exists() && !parent.mkdirs() && !parent.isDirectory) {
            throw IOException(JournalErrors.WRITE_FAILED)
        }
    }
}
