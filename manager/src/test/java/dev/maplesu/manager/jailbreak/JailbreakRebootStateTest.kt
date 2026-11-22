package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class JailbreakRebootStateTest {
    @Test fun onlyConfirmedReadyOutcomeOffersSoftRestart() {
        assertTrue(JailbreakSelectionState(outcome = JailbreakController.Outcome(
            JailbreakStatus.STAGE_DAEMON_READY, "", null)).succeeded)
    }

    @Test fun rejectedAndIncompleteAttemptsKeepTheirOriginalActions() {
        assertFalse(JailbreakSelectionState().succeeded)
        listOf(JailbreakStatus.STAGE_FAILED, JailbreakStatus.STAGE_EXPIRED,
            JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED).forEach { stage ->
            assertFalse(JailbreakSelectionState(outcome = JailbreakController.Outcome(stage, "", null)).succeeded)
        }
    }

    @Test fun failureOnReadyRecordDoesNotOfferSoftRestart() {
        assertFalse(JailbreakSelectionState(outcome = JailbreakController.Outcome(
            JailbreakStatus.STAGE_DAEMON_READY, "", "JAILBREAK_ATTEMPT_NOT_CONFIRMED")).succeeded)
    }
}
