package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.*
import org.junit.Test

class UltraRecoveryFingerprintTest {
    @Test fun removingTheKeyDiscardsProofAndExplicitlyResolvesTheNoKeyIdentity() {
        for (state in UltraEnvironmentProbe.State.entries) {
            val old = UltraEnvironmentProbe.Snapshot(state, kernelRootVerified = true)
            val observed = UltraEnvironmentProbe.scopeSnapshot(old, null, "old-key", "boot-1", "boot-1", false)
            assertEquals(UltraEnvironmentProbe.State.NoKey, observed.state)
            assertFalse(observed.kernelRootVerified)
            assertFalse(observed.rootAvailable)
            assertNull(UltraEnvironmentProbe.recoveryFingerprint(observed.state, false, observed.kernelRootVerified))
        }
    }

    @Test fun proofRequiresTheSameKeyBootAndAnUnsuspendedIdentity() {
        val running = UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running, kernelRootVerified = true)
        assertEquals(running, UltraEnvironmentProbe.scopeSnapshot(running, "key", "key", "boot-1", "boot-1", false))
        for ((key, boot, paused) in listOf(Triple("other-key", "boot-1", false),
            Triple("key", "boot-2", false), Triple("key", "", false), Triple("key", "boot-1", true))) {
            val observed = UltraEnvironmentProbe.scopeSnapshot(running, key, "key", boot, "boot-1", paused)
            assertEquals(UltraEnvironmentProbe.State.Unknown, observed.state)
            assertFalse(observed.kernelRootVerified)
            assertFalse(observed.rootAvailable)
        }
    }

    @Test fun noBootIsDefinitiveAbsenceWhereasBusyAndTimeoutRemainUnknown() {
        assertNull(UltraEnvironmentProbe.recoveryFingerprint(UltraEnvironmentProbe.State.Unknown, false,
            kernelChannelAbsent = true))
        for (detail in listOf("MAPLESU_SDK_BUSY", "MAPLESU_SDK_INTERRUPTED", "TIMEOUT", "BAD_KEY")) {
            val unknown = UltraEnvironmentProbe.Snapshot(detail = detail)
            assertFalse(unknown.rootAvailable)
            assertThrows(IllegalStateException::class.java) {
                UltraEnvironmentProbe.recoveryFingerprint(unknown.state, false, unknown.kernelRootVerified, unknown.kernelChannelAbsent)
            }
        }
    }

    @Test fun failedSdkChannelStaysUnknownInsteadOfBeingReportedAsNotInstalled() {
        assertThrows(IllegalStateException::class.java) {
            UltraEnvironmentProbe.recoveryFingerprint(UltraEnvironmentProbe.State.Unknown, false)
        }
    }
    @Test fun onlyLiveRunningOrApplicableFaultIdentifiesUltra() {
        assertEquals("ultra:running", UltraEnvironmentProbe.recoveryFingerprint(UltraEnvironmentProbe.State.Running, false))
        assertEquals("ultra:fault", UltraEnvironmentProbe.recoveryFingerprint(UltraEnvironmentProbe.State.Fault, true))
        for (state in listOf(UltraEnvironmentProbe.State.NotInstalled, UltraEnvironmentProbe.State.NoKey,
            UltraEnvironmentProbe.State.Fault)) assertNull(UltraEnvironmentProbe.recoveryFingerprint(state, false))
    }

    @Test fun verifiedKernelIdentifiesUltraWithoutChangingTheUnknownHelperState() {
        for (state in listOf(UltraEnvironmentProbe.State.Unknown, UltraEnvironmentProbe.State.NotInstalled)) {
            val verified = UltraEnvironmentProbe.verifyKernelRoot(state, true) { 0 }
            assertTrue(verified)
            assertEquals("ultra:kernel", UltraEnvironmentProbe.recoveryFingerprint(state, false, verified))
            assertEquals(if (state == UltraEnvironmentProbe.State.Unknown) null else false,
                UltraEnvironmentProbe.suEnabledState(state))
        }
    }

    @Test fun noBootBadKeyMissingUidAndFailedReceiptsNeverProveTheKernel() {
        for (uid in listOf(null, -1, 2000)) {
            assertFalse(UltraEnvironmentProbe.verifyKernelRoot(UltraEnvironmentProbe.State.Unknown, true) { uid })
        }
        assertFalse(UltraEnvironmentProbe.verifyKernelRoot(UltraEnvironmentProbe.State.Unknown, true) {
            error("ERR_MODULE_NO_BOOT")
        })
        assertFalse(UltraEnvironmentProbe.verifyKernelRoot(UltraEnvironmentProbe.State.Unknown, false) {
            error("A failed receipt must not start another SDK command")
        })
        for (state in listOf(UltraEnvironmentProbe.State.Running, UltraEnvironmentProbe.State.Fault,
            UltraEnvironmentProbe.State.NoKey)) {
            assertFalse(UltraEnvironmentProbe.verifyKernelRoot(state, true) { error("No probe for $state") })
        }
    }
}
