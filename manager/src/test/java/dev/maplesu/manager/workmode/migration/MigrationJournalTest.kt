package dev.maplesu.manager.workmode.migration

import dev.maplesu.manager.workmode.control.AtomicControlFile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** 05 §4.3/§4.4/§4.8：状态机 / intent-done / pending / 崩溃恢复判定（T-20、T-22）。 */
class MigrationJournalTest {
    @get:Rule val tmp = TemporaryFolder()

    private var now = 1_793_260_800_000L

    private fun journal(): FileMigrationJournal =
        FileMigrationJournal(tmp.root, clock = { now++ }, bootIdSource = { "boot-1" })

    private fun journalWithPartition(journal: FileMigrationJournal): MigrationJournalFile {
        val created = journal.begin(
            Fixtures.MIGRATION_ID,
            source = JournalSource(family = "KSU_UPSTREAM", restoreStrategy = "KSU_STOCK_COPY"),
            target = JournalTarget(mode = "LITE", targetSet = listOf("boot")),
            restoreSet = listOf("init_boot"),
        )
        return journal.setPlan(
            journal = created,
            partitions = listOf(
                JournalPartition(
                    name = "init_boot",
                    action = PartitionAction.RESTORE_EXTERNAL.name,
                    pre = JournalImage("backup/images/pre-init_boot.img", 100, Fixtures.sha("pre-init")),
                    final = JournalImage("backup/images/clean-init_boot.img", 100, Fixtures.sha("clean-init")),
                ),
                JournalPartition(
                    name = "boot",
                    action = PartitionAction.WRITE_CANDIDATE.name,
                    pre = JournalImage("backup/images/pre-boot.img", 100, Fixtures.sha("pre-boot")),
                    final = JournalImage("backup/our/candidate-boot.img", 100, Fixtures.sha("candidate")),
                ),
            ),
            restoreSet = listOf("init_boot"),
        )
    }

    @Test
    fun beginWritesDetectedState() {
        val file = journal()
        val created = file.begin(Fixtures.MIGRATION_ID)
        assertEquals(MigrationState.M0_DETECTED.wire, created.state)
        assertEquals("boot-1", created.bootId)
        assertEquals(1, created.history.size)
        val read = file.read(Fixtures.MIGRATION_ID)
        assertNotNull(read)
        assertEquals(created.migrationId, read!!.migrationId)
    }

    @Test
    fun legalTransitionsArePersisted() {
        val file = journal()
        var current = file.begin(Fixtures.MIGRATION_ID)
        current = file.transition(current, MigrationState.M1_BACKED_UP)
        current = file.transition(current, MigrationState.M2_PLANNED)
        assertEquals(MigrationState.M2_PLANNED.wire, file.read(Fixtures.MIGRATION_ID)!!.state)
        assertEquals(3, current.history.size)
    }

    @Test
    fun illegalTransitionIsRejected() {
        val file = journal()
        val created = file.begin(Fixtures.MIGRATION_ID)
        val failure = assertThrows(MigrationFailure::class.java) {
            file.transition(created, MigrationState.M9_VERIFIED)
        }
        assertEquals(MigrationCodes.JOURNAL_STATE_INVALID, failure.code)
        assertEquals(MigrationState.M0_DETECTED.wire, file.read(Fixtures.MIGRATION_ID)!!.state)
    }

    @Test
    fun intentAndDoneTrackPartitionWrites() {
        val file = journal()
        val created = journalWithPartition(file)
        var current = file.recordIntent(created, "boot", Fixtures.sha("pre-boot"))
        val pending = file.read(Fixtures.MIGRATION_ID)!!.partitionOrNull("boot")!!
        assertTrue(pending.writeIntent)
        assertFalse(pending.writeDone)
        current = file.recordDone(current, "boot", Fixtures.sha("candidate"))
        val done = file.read(Fixtures.MIGRATION_ID)!!.partitionOrNull("boot")!!
        assertTrue(done.writeDone)
        assertEquals(Fixtures.sha("candidate"), done.readBackSha256)
        assertEquals("INTENT", file.read(Fixtures.MIGRATION_ID)!!.history[1].event)
        assertEquals("DONE", file.read(Fixtures.MIGRATION_ID)!!.history[2].event)
    }

    @Test
    fun nonTerminalJournalKeepsMigrationPending() {
        val file = journal()
        val created = journalWithPartition(file)
        file.transition(created, MigrationState.M1_BACKED_UP)
        assertTrue(file.isPending())
        assertEquals(listOf(Fixtures.MIGRATION_ID), file.pendingIds())
        val failed = file.transition(file.read(Fixtures.MIGRATION_ID)!!, MigrationState.FAILED)
        assertFalse(file.isPending())
        assertTrue(failed.isTerminal())
    }

    @Test
    fun recoveryClassifiesIntentWithoutDoneByReadBack() {
        val file = journal()
        var current = journalWithPartition(file)
        current = file.recordIntent(current, "boot", Fixtures.sha("pre-boot"))
        val journal = file.read(Fixtures.MIGRATION_ID)!!
        val finalSha = Fixtures.sha("candidate")
        val preSha = Fixtures.sha("pre-boot")

        val stillWritten = RecoveryRules.classify(
            journal, mapOf("boot" to finalSha), mapOf("boot" to preSha),
        ) { finalSha }
        assertEquals(RecoveryRules.Action.MARK_DONE, stillWritten.single().action)

        val stillPre = RecoveryRules.classify(
            journal, mapOf("boot" to finalSha), mapOf("boot" to preSha),
        ) { preSha }
        assertEquals(RecoveryRules.Action.NOT_EXECUTED, stillPre.single().action)

        val unknown = RecoveryRules.classify(
            journal, mapOf("boot" to finalSha), mapOf("boot" to preSha),
        ) { Fixtures.sha("other") }
        assertEquals(RecoveryRules.Action.RECOVERY_REQUIRED, unknown.single().action)

        val unreadable = RecoveryRules.classify(
            journal, mapOf("boot" to finalSha), mapOf("boot" to preSha),
        ) { null }
        assertEquals(RecoveryRules.Action.RECOVERY_REQUIRED, unreadable.single().action)
    }

    @Test
    fun backupVerificationAndResiduesAreRecorded() {
        val file = journal()
        val created = journalWithPartition(file)
        var current = file.recordBackupVerified(created, Fixtures.sha("manifest"))
        assertTrue(current.backup.verified)
        current = file.recordResidue(
            current,
            ResidueRecord("EXTERNAL_RESIDUE", "/data/adb/ksu", "7K_COMPAT_SYMLINK"),
        )
        current = file.recordExternalRestoreUnavailable(current, "init_boot", "P0_AND_P2_UNAVAILABLE")
        current = file.recordError(current, "MIGRATION_BACKUP_VERIFY_FAILED")
        val read = file.read(Fixtures.MIGRATION_ID)!!
        assertEquals(1, read.residues.size)
        assertEquals("/data/adb/ksu", read.residues.single().path)
        assertTrue(read.history.any { it.event == "EXTERNAL_RESTORE_UNAVAILABLE" })
        assertTrue(read.history.any { it.event == "ERROR" && it.code == "MIGRATION_BACKUP_VERIFY_FAILED" })
    }

    @Test
    fun rollbackPathRecordsReverseStepsAndEndsTerminal() {
        val file = journal()
        var current = journalWithPartition(file)
        current = file.transition(current, MigrationState.M1_BACKED_UP)
        current = file.transition(current, MigrationState.M2_PLANNED)
        current = file.transition(current, MigrationState.M3_PRODUCED)
        current = file.transition(current, MigrationState.M4_WRITING)
        current = file.beginRollingBack(current, "WRITE_READBACK_MISMATCH")
        assertEquals(MigrationState.ROLLING_BACK.wire, current.state)
        // 逆序：先撤 boot 候选，再撤 init_boot 还原
        current = file.recordRollbackIntent(current, "boot")
        current = file.recordRollbackDone(current, "boot", Fixtures.sha("pre-boot"))
        current = file.recordRollbackIntent(current, "init_boot")
        current = file.recordRollbackDone(current, "init_boot", Fixtures.sha("pre-init"))
        current = file.finalizeRolledBack(current)
        assertEquals(MigrationState.ROLLED_BACK, current.stateValue())
        assertTrue(current.isTerminal())
        assertFalse(file.isPending())
        val history = current.history
        assertEquals("ROLLBACK_INTENT", history[history.size - 3].event)
        assertEquals("ROLLBACK_DONE", history[history.size - 2].event)
        assertTrue(history.any { it.event == "TRANSITION" && it.state == MigrationState.ROLLED_BACK.wire })
    }

    @Test
    fun corruptJournalIsReportedNotIgnored() {
        val file = journal()
        file.begin(Fixtures.MIGRATION_ID)
        val path = MigrationPaths.journal(tmp.root, Fixtures.MIGRATION_ID)
        AtomicControlFile.writeUtf8(path, "{not json".toByteArray(Charsets.UTF_8))
        val failure = assertThrows(MigrationFailure::class.java) { file.read(Fixtures.MIGRATION_ID) }
        assertEquals(MigrationCodes.JOURNAL_INVALID, failure.code)
        // fail-safe：损坏的 journal 仍算 pending，绝不静默放行新事务。
        assertEquals(listOf(Fixtures.MIGRATION_ID), file.pendingIds())
    }

    @Test
    fun finalizeVerifiedMovesToTerminalState() {
        val file = journal()
        var current = journalWithPartition(file)
        current = file.transition(current, MigrationState.M1_BACKED_UP)
        current = file.transition(current, MigrationState.M2_PLANNED)
        current = file.transition(current, MigrationState.M3_PRODUCED)
        current = file.transition(current, MigrationState.M4_WRITING)
        current = file.transition(current, MigrationState.M5_DEPLOYING)
        current = file.transition(current, MigrationState.M6_CLEANUP)
        current = file.transition(current, MigrationState.M7_FINALIZED)
        current = file.transition(current, MigrationState.M8_REBOOT_REQUESTED)
        current = file.finalizeVerified(
            current,
            residues = listOf(ResidueRecord("EXTERNAL_RESIDUE", "/data/adb/ksu", "LEFTOVER")),
            residual = true,
        )
        assertEquals(MigrationState.M9_VERIFIED, current.stateValue())
        assertTrue(current.history.any { it.event == "VERIFIED" && it.code == "RESIDUAL" })
        assertFalse(file.isPending())
    }

    @Test
    fun recoveryRequiredIsNotTerminalAndStillBlocks() {
        val file = journal()
        var current = journalWithPartition(file)
        current = file.transition(current, MigrationState.ROLLING_BACK)
        current = file.transition(current, MigrationState.RECOVERY_REQUIRED)
        assertFalse(current.isTerminal())
        assertTrue(file.isPending())
    }

    @Test
    fun transportBindingRequiresSamePidAndChain() {
        val transport = JournalTransport("/debug_ramdisk/su", "magiskd", 1234)
        assertTrue(transport.matches(listOf("init", "magiskd", "su"), 1234))
        assertFalse(transport.matches(listOf("init", "magiskd", "su"), 999))
        assertFalse(transport.matches(listOf("init", "ksud"), 1234))
        assertFalse(JournalTransport("/su", "magiskd", 0).matches(listOf("magiskd", "su"), 0))
    }
}
