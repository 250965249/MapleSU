package dev.maplesu.manager.recovery

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class RecoveryRestoreProgressTest {
    @get:Rule val temp = TemporaryFolder()
    private fun handover() = ManagerRestoreHandover(File(temp.root, "ticket"))

    @Test fun installationDoesNotBlockStatusAndDuplicateRequestsDoNotReinstall() {
        val progress = RecoveryRestoreProgress(handover()) { false }
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val worker = thread {
            progress.restore {
                entered.countDown()
                check(release.await(5, TimeUnit.SECONDS))
                RecoveryRestoreReport(false, "RECOVERY_DATA_VERIFY_FAILED")
            }
        }
        try {
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            assertTrue(progress.status().restoring)
            assertTrue(progress.restore { error("duplicate installation") }.restoring)
        } finally {
            release.countDown()
            worker.join(5000)
        }
        assertFalse(worker.isAlive)
        assertFalse(progress.status().restoring)
        assertEquals("RECOVERY_DATA_VERIFY_FAILED", progress.status().code)
    }

    @Test fun lostInstallReplyKeepsTheRealFailureAndAllowsRetry() {
        val progress = RecoveryRestoreProgress(handover()) { false }
        progress.restore { RecoveryRestoreReport(false, "RECOVERY_DATA_VERIFY_FAILED", listOf("data:failed(DATA_UID_MISMATCH)")) }
        assertFalse(progress.status().ok)
        assertEquals("data:failed(DATA_UID_MISMATCH)", progress.status().steps.single())
        progress.restore { RecoveryRestoreReport(true, completed = true) }
        assertTrue(progress.status().completed)
    }

    @Test fun confirmedTicketSurvivesDaemonRestartWithoutExposingNonce() {
        val handover = handover()
        handover.prepare()
        val nonce = File(temp.root, "ticket").readText().trim().substringAfter(':')
        val progress = RecoveryRestoreProgress(handover) { true }
        assertTrue(progress.status().awaitingConfirmation)
        assertFalse(progress.status().completed)
        assertTrue(handover.confirm(nonce, { true }) { RecoveryCleanupResult(true) }.ok)
        val restarted = RecoveryRestoreProgress(handover()) { true }
        assertTrue(restarted.status().completed)
        assertFalse(restarted.status().awaitingConfirmation)
        assertFalse(restarted.status().toString().contains(nonce))
    }

    @Test fun oldConfirmedTicketDoesNotCompleteANewHiddenSessionOrHideItsFailure() {
        val handover = handover()
        handover.prepare()
        val nonce = File(temp.root, "ticket").readText().trim().substringAfter(':')
        handover.confirm(nonce, { true }) { RecoveryCleanupResult(true) }
        val progress = RecoveryRestoreProgress(handover) { false }
        assertFalse(progress.status().completed)
        progress.restore { RecoveryRestoreReport(false, "RECOVERY_DATA_VERIFY_FAILED") }
        assertFalse(progress.status().completed)
        assertFalse(progress.status().ok)
    }

    @Test fun exceptionEndsProgressAndRetainsRetryCapability() {
        val progress = RecoveryRestoreProgress(handover()) { false }
        assertEquals("RECOVERY_RESTORE_EXCEPTION", progress.restore { error("fixture") }.code)
        assertFalse(progress.status().restoring)
        assertTrue(progress.restore { RecoveryRestoreReport(true) }.ok)
    }
}
