package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class JailbreakAutomaticRebootTest {
    private var saved: String? = null
    private var calls = 0
    private fun policy() = JailbreakAutomaticReboot({ saved }, { saved = it; true })
    private fun ready() = JailbreakController.Outcome(JailbreakStatus.STAGE_DAEMON_READY, "", null, "attempt-1")
    private fun reboot(): Boolean { calls++; return true }

    @Test fun checkedHookSuccessRestartsExactlyOnceAcrossOwners() {
        assertEquals(true, policy().onSuccess(true, JailbreakRequest.BACKEND_HOOK, ready(), ::reboot))
        assertNull(policy().onSuccess(true, JailbreakRequest.BACKEND_HOOK, ready(), ::reboot))
        assertEquals(1, calls)
    }
    @Test fun uncheckedHookDoesNotRestart() {
        assertNull(policy().onSuccess(false, JailbreakRequest.BACKEND_HOOK, ready(), ::reboot))
        assertEquals(0, calls)
    }
    @Test fun checkedNormalSuccessRestartsExactlyOnceAcrossOwners() {
        assertEquals(true, policy().onSuccess(true, JailbreakRequest.BACKEND_KSU, ready(), ::reboot))
        assertNull(policy().onSuccess(true, JailbreakRequest.BACKEND_KSU, ready(), ::reboot))
        assertEquals(1, calls)
    }
    @Test fun nativeIrActivationIsNeverReplayedByUi() {
        assertNull(policy().onSuccess(true, JailbreakRequest.BACKEND_IR, ready(), ::reboot))
        assertEquals(0, calls)
    }
    @Test fun failuresAndIncompleteProofsDoNotRestart() {
        for (outcome in listOf(ready().copy(failure = "failed"), ready().copy(stage = JailbreakStatus.STAGE_FAILED), ready().copy(attemptId = null))) {
            assertNull(policy().onSuccess(true, JailbreakRequest.BACKEND_HOOK, outcome, ::reboot))
        }
        assertEquals(0, calls)
    }
    @Test fun rejectedAutomaticRequestIsConsumedButManualSuccessActionRemains() {
        assertEquals(false, policy().onSuccess(true, JailbreakRequest.BACKEND_HOOK, ready()) { calls++; false })
        assertNull(policy().onSuccess(true, JailbreakRequest.BACKEND_HOOK, ready(), ::reboot))
        assertTrue(JailbreakSelectionState(outcome = ready()).succeeded)
        assertEquals(1, calls)
    }
    @Test fun failedPersistenceDoesNotRestart() {
        assertEquals(false, JailbreakAutomaticReboot({ null }, { false }).onSuccess(true, JailbreakRequest.BACKEND_HOOK, ready(), ::reboot))
        assertEquals(0, calls)
    }
}
