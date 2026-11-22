package dev.maplesu.manager.installer

import com.maplesu.core.ui.util.FlashOutcome
import org.junit.Assert.*
import org.junit.Test

class InstallerTaskResultTest {
    @Test fun lostCommitReplyResumesAsWritten() {
        for (state in listOf("REBOOT_REQUIRED", "REBOOT_REQUESTED", "BOOT_IMAGE_VERIFIED", "BOOT_VERIFIED", "VERIFIED")) {
            val result = installerTaskResult(state, rebootRequired = state != "VERIFIED")
            assertEquals(state, 0, result.code)
            assertEquals(FlashOutcome.WRITTEN, result.outcome)
            assertEquals(state != "VERIFIED", result.showReboot)
        }
    }

    @Test fun incompleteModeSwitchOffersRecoveryRatherThanWrittenSuccess() {
        for (state in listOf("BEGIN", "SNAPSHOT", "PRODUCE", "COMMIT", "ROLLING_BACK", "VERIFYING", "WRITING", "RESTORING", "RECOVERY_REQUIRED")) {
            val result = installerTaskResult(state, false)
            assertEquals(state, 1, result.code)
            assertEquals(FlashOutcome.RECOVERY_REQUIRED, result.outcome)
        }
    }

    @Test fun automaticRollbackDoesNotReportInstallationSuccess() {
        for (state in listOf("RESTORED", "ROLLED_BACK")) {
            val result = installerTaskResult(state, true, "write failed")
            assertEquals(1, result.code)
            assertEquals(FlashOutcome.RESTORED, result.outcome)
            assertEquals("write failed", result.err)
            assertTrue(result.showReboot)
        }
    }

    @Test fun explicitRestoreReportsRestoredAndKeepsRebootAction() {
        for (state in listOf("RESTORED", "ROLLED_BACK")) {
            val result = installerTaskResult(state, true, restoring = true)
            assertEquals(0, result.code)
            assertEquals(FlashOutcome.RESTORED, result.outcome)
            assertTrue(result.showReboot)
        }
    }

    @Test fun oldInstallSuccessIsNotProofOfRestore() {
        assertEquals(1, installerTaskResult("REBOOT_REQUIRED", true, restoring = true).code)
    }

    @Test fun verifiedStockWriteFollowedByRebootDoesNotRequireMapleSuRoot() {
        val result = installerTaskResult("STOCK_RESTORED", false)
        assertEquals(0, result.code)
        assertEquals(FlashOutcome.RESTORED, result.outcome)
        assertFalse(result.showReboot)
        assertEquals(1, installerTaskResult("STOCK_RESTORED", false, restoring = true).code)
    }

    @Test fun cancelledPreparationNeverLooksLikeAWrite() {
        for (state in listOf("NONE", "CANCELLED", "ABORTED", "FAILED_BEFORE_WRITE", "PREPARED")) {
            val result = installerTaskResult(state, false)
            assertEquals(state, 1, result.code)
            assertEquals(FlashOutcome.FAILED, result.outcome)
            assertFalse(result.showReboot)
        }
    }
}
