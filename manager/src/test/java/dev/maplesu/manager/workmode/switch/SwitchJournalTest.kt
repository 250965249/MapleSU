package dev.maplesu.manager.workmode.switch

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.TestFixtures
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.io.FileOutputStream

/** 01 §7.2 + 02 §3.3：journal（WAL）持久化、seq/prev 链、末行截断、重放。 */
class SwitchJournalTest {
    private val clock = Clock { 5_000L }
    private val boot = BootIdSource { "boot-1" }

    private fun journalFile(): File = File(TestFixtures.tempDir("journal").toFile(), "journal.jsonl")

    private fun journal(file: File = journalFile()) = FileSwitchJournal(file, clock, boot)

    private fun append(journal: FileSwitchJournal, op: SwitchOp, step: String = "4d"): JournalLine =
        journal.append(
            switchId = "sw-1",
            planSha256 = "a".repeat(64),
            stage = "S4",
            step = step,
            op = op,
        )

    private fun rawLine(
        seq: Long,
        prev: String,
        op: SwitchOp = SwitchOp.PREPARED,
    ): String = ControlJsonCodec.encode(
        JournalLine(
            seq = seq,
            switchId = "sw-1",
            planSha256 = "a".repeat(64),
            atUptimeMs = 1,
            bootId = "boot-1",
            stage = "S4",
            step = "4a",
            op = op.wire,
            prev = prev,
        ),
    )

    @Test
    fun appendSeqStartsAtOneAndIncrements() {
        val journal = journal()
        assertEquals(1L, append(journal, SwitchOp.PREPARED).seq)
        assertEquals(2L, append(journal, SwitchOp.MOVE_INTENT).seq)
        assertEquals(3L, append(journal, SwitchOp.MOVE_DONE).seq)
        val lines = (journal.read() as JournalRead.Ok).lines
        assertEquals(listOf(1L, 2L, 3L), lines.map { it.seq })
    }

    @Test
    fun prevChainLinksRawPreviousLine() {
        val file = journalFile()
        val journal = journal(file)
        val first = append(journal, SwitchOp.PREPARED)
        val second = append(journal, SwitchOp.MOVE_INTENT)
        assertEquals(JournalLine.ZERO_PREV, first.prev)
        val rawFirst = file.readLines().first()
        assertEquals(Hashes.sha256(rawFirst.toByteArray(Charsets.UTF_8)), second.prev)
        assertTrue(journal.read() is JournalRead.Ok)
    }

    @Test
    fun readDetectsTruncatedTail() {
        val file = journalFile()
        val journal = journal(file)
        append(journal, SwitchOp.PREPARED)
        append(journal, SwitchOp.MOVE_INTENT)
        // 模拟掉电：半行没有 '\n'。
        FileOutputStream(file, true).use { it.write("{\"schema\":1,\"seq\":3".toByteArray(Charsets.UTF_8)) }
        val read = journal.read()
        assertTrue(read is JournalRead.Ok)
        val ok = read as JournalRead.Ok
        assertTrue(ok.truncatedTail)
        assertEquals(2, ok.lines.size)
    }

    @Test
    fun appendAfterTruncatedTailRepairsFile() {
        val file = journalFile()
        val journal = journal(file)
        append(journal, SwitchOp.PREPARED)
        FileOutputStream(file, true).use { it.write("{\"partial\":".toByteArray(Charsets.UTF_8)) }
        val third = append(journal, SwitchOp.PREPARED)
        assertEquals(2L, third.seq)
        val read = journal.read()
        assertTrue(read is JournalRead.Ok)
        val ok = read as JournalRead.Ok
        assertFalse(ok.truncatedTail)
        assertEquals(2, ok.lines.size)
        assertTrue(file.readText().endsWith("\n"))
    }

    @Test
    fun seqGapIsCorrupt() {
        val file = journalFile()
        file.writeText(rawLine(1, JournalLine.ZERO_PREV) + "\n" + rawLine(3, "b".repeat(64)) + "\n")
        val read = journal(file).read()
        assertTrue(read is JournalRead.Corrupt)
        val corrupt = read as JournalRead.Corrupt
        assertEquals(JournalErrors.SEQ_GAP, corrupt.code)
        assertEquals(1, corrupt.lines.size)
    }

    @Test
    fun prevChainBrokenIsCorrupt() {
        val file = journalFile()
        file.writeText(rawLine(1, JournalLine.ZERO_PREV) + "\n" + rawLine(2, "b".repeat(64)) + "\n")
        val read = journal(file).read()
        assertTrue(read is JournalRead.Corrupt)
        assertEquals(JournalErrors.PREV_CHAIN_BROKEN, (read as JournalRead.Corrupt).code)
    }

    @Test
    fun parseFailureIsCorrupt() {
        val file = journalFile()
        file.writeText("not json\n")
        val read = journal(file).read()
        assertTrue(read is JournalRead.Corrupt)
        assertEquals(JournalErrors.PARSE_FAILED, (read as JournalRead.Corrupt).code)
    }

    @Test
    fun replayEmptyIsEmpty() {
        val journal = journal()
        assertEquals(JournalReplay.Empty, journal.replay())
        assertNull(journal.last())
    }

    @Test
    fun replayDerivesForwardStates() {
        val journal = journal()
        append(journal, SwitchOp.PREPARED)
        assertEquals(SwitchStateNames.BEGIN, (journal.replay() as JournalReplay.Known).state)
        append(journal, SwitchOp.MOVE_INTENT)
        assertEquals(SwitchStateNames.COMMIT, (journal.replay() as JournalReplay.Known).state)
        append(journal, SwitchOp.REBOOT_PENDING)
        val reboot = journal.replay() as JournalReplay.Known
        assertEquals(SwitchStateNames.REBOOT_REQUIRED, reboot.state)
        assertTrue(reboot.rebootRequested)
        append(journal, SwitchOp.VERIFIED)
        assertEquals(SwitchStateNames.VERIFIED, (journal.replay() as JournalReplay.Known).state)
    }

    @Test
    fun replayDerivesRollbackStates() {
        val journal = journal()
        append(journal, SwitchOp.COMMIT_INTENT)
        append(journal, SwitchOp.ROLLBACK_INTENT)
        assertEquals(SwitchStateNames.ROLLING_BACK, (journal.replay() as JournalReplay.Known).state)
        append(journal, SwitchOp.ROLLBACK_DONE)
        assertEquals(SwitchStateNames.ROLLED_BACK, (journal.replay() as JournalReplay.Known).state)
    }

    @Test
    fun replayDegradedOnCorruptJournal() {
        val file = journalFile()
        file.writeText(rawLine(1, JournalLine.ZERO_PREV) + "\n" + rawLine(3, "b".repeat(64)) + "\n")
        val replay = journal(file).replay()
        assertTrue(replay is JournalReplay.Degraded)
        assertEquals(JournalErrors.SEQ_GAP, (replay as JournalReplay.Degraded).code)
    }

    @Test
    fun appendRefusesCorruptJournal() {
        val file = journalFile()
        file.writeText(rawLine(1, JournalLine.ZERO_PREV) + "\n" + rawLine(3, "b".repeat(64)) + "\n")
        try {
            append(journal(file), SwitchOp.MOVE_INTENT)
            fail("append must refuse a corrupt journal")
        } catch (_: IllegalStateException) {
        }
    }

    @Test
    fun appendRawReturnsSeq() {
        val journal = journal()
        assertEquals(1L, journal.appendRaw("{\"seq\":1}"))
        assertEquals(2L, journal.appendRaw("{\"seq\":2}"))
    }
}
