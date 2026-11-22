package dev.maplesu.manager.parasite

import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.detect.Clock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files

/** journal：append/fsync、seq 单调、半行截断、断点重建、损坏不猜。 */
class ParasiteJournalTest {
    private fun tempFile(): File =
        File(Files.createTempDirectory("maplesu-parasite-journal-").toFile(), "journal.jsonl")

    private fun journal(file: File = tempFile(), clock: Clock = Clock { 1_000L }) =
        ParasiteJournal(file, clock)

    private fun record(state: ParasiteState = ParasiteState.N0_IDLE) = ParasiteHostRecord(
        registrationId = "reg-1",
        hostPackage = "com.example.host",
        hostUid = 10_200,
        targetPidCmdline = "com.example.host",
        originalSoPath = "/data/app/lib/libfoo.so",
        state = state.name,
    )

    @Test
    fun appendReadAndRebuildKeepsLastState() {
        val journal = journal()
        journal.append(ParasiteState.N0_IDLE, "RESET", record(), )
        journal.append(ParasiteState.N1_PRECHECKED, "PRECHECK_OK", record())
        journal.append(ParasiteState.N2_IMPLANTED, "IMPLANT_OK", record())

        val read = journal.read()
        assertTrue(read is ParasiteJournalRead.Ok)
        val lines = (read as ParasiteJournalRead.Ok).lines
        assertEquals(listOf(1L, 2L, 3L), lines.map { it.seq })
        assertEquals(ParasiteState.N2_IMPLANTED, journal.lastState())
        val rebuilt = journal.rebuild()!!
        assertEquals(ParasiteState.N2_IMPLANTED, rebuilt.stateEnum())
        assertEquals("com.example.host", rebuilt.hostPackage)
    }

    @Test
    fun rebuildWithoutRecordSnapshotsIsNull() {
        val journal = journal()
        journal.append(ParasiteState.N1_PRECHECKED, "PRECHECK_OK")
        assertNull(journal.rebuild())
        assertEquals(ParasiteState.N1_PRECHECKED, journal.lastState())
    }

    @Test
    fun truncatedTailIsDroppedAndRepairedOnAppend() {
        val file = tempFile()
        val journal = journal(file)
        journal.append(ParasiteState.N0_IDLE, "RESET", record())
        FileOutputStream(file, true).use { it.write("{\"schema\":1,\"seq\":2".toByteArray()) }

        val read = journal.read()
        assertTrue(read is ParasiteJournalRead.Ok)
        val truncated = read as ParasiteJournalRead.Ok
        assertTrue(truncated.truncatedTail)
        assertEquals(1, truncated.lines.size)

        journal.append(ParasiteState.N1_PRECHECKED, "PRECHECK_OK", record())
        val repaired = journal.read() as ParasiteJournalRead.Ok
        assertEquals(2, repaired.lines.size)
        assertTrue(file.readText().endsWith("\n"))
    }

    @Test
    fun seqGapIsCorrupt() {
        val file = tempFile()
        val first = ParasiteJournalLine(
            seq = 1, at = 1, state = ParasiteState.N0_IDLE.name, event = "RESET",
        )
        val gap = first.copy(seq = 3, state = ParasiteState.N1_PRECHECKED.name)
        file.parentFile?.mkdirs()
        file.writeText(
            ControlJsonCodec.encode(first) + "\n" + ControlJsonCodec.encode(gap) + "\n",
        )
        val read = journal(file).read()
        assertTrue(read is ParasiteJournalRead.Corrupt)
        assertEquals(
            ParasiteJournalCodes.SEQ_GAP,
            (read as ParasiteJournalRead.Corrupt).code,
        )
    }

    @Test
    fun parseFailureIsCorrupt() {
        val file = tempFile()
        file.parentFile?.mkdirs()
        file.writeText("not-json\n")
        val read = journal(file).read()
        assertTrue(read is ParasiteJournalRead.Corrupt)
        assertEquals(
            ParasiteJournalCodes.PARSE_FAILED,
            (read as ParasiteJournalRead.Corrupt).code,
        )
    }

    @Test
    fun appendRefusesCorruptJournal() {
        val file = tempFile()
        file.parentFile?.mkdirs()
        file.writeText("broken\n")
        try {
            journal(file).append(ParasiteState.N0_IDLE, "RESET")
            fail("append must refuse a corrupt journal")
        } catch (_: IllegalStateException) {
        }
    }

    @Test
    fun historyIsOrderedAndEventCodesPersist() {
        val journal = journal()
        journal.append(ParasiteState.N0_IDLE, "RESET")
        journal.append(ParasiteState.N1_PRECHECKED, "PRECHECK_OK", code = "")
        journal.append(
            ParasiteState.N1_PRECHECKED, "IMPLANT_FAILED",
            code = ParasiteCodes.IMPLANT_FAILED, detail = "rejected",
        )
        val lines = journal.history()
        assertEquals(
            listOf("RESET", "PRECHECK_OK", "IMPLANT_FAILED"),
            lines.map { it.event },
        )
        assertEquals(ParasiteCodes.IMPLANT_FAILED, lines.last().code)
    }
}
