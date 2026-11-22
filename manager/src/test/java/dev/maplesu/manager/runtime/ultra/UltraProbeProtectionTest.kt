package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.*
import org.junit.Test

class UltraProbeProtectionTest {
    private val probe = UltraEnvironmentProbe

    @Test fun runningStatusRequiresIndependentKernelRootProof() {
        assertFalse(UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running).rootAvailable)
        assertTrue(UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running, kernelRootVerified = true).rootAvailable)
        assertTrue(UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Unknown, kernelRootVerified = true).rootAvailable)
        assertTrue(UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.NotInstalled, kernelRootVerified = true).rootAvailable)
        assertFalse(UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.NoKey, kernelRootVerified = true).rootAvailable)
    }

    @Test fun faultKeepsItsProtectionWithoutGrantingKernelRoot() {
        assertFalse(UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Fault, kernelRootVerified = true).rootAvailable)
        assertFalse(probe.verifyKernelRoot(UltraEnvironmentProbe.State.Fault, true) {
            fail("protected environment must not submit a root verification")
            0
        })
    }

    @Test fun faultUsesTheExistingShortCacheTtl() {
        assertTrue(probe.canReuse(UltraEnvironmentProbe.State.Fault, 0))
        assertTrue(probe.canReuse(UltraEnvironmentProbe.State.Fault, 2_999))
        assertFalse(probe.canReuse(UltraEnvironmentProbe.State.Fault, 3_000))
        assertFalse(probe.canReuse(UltraEnvironmentProbe.State.Fault, -1))
    }

    @Test fun invalidationRetainsFaultUntilFreshEvidenceButExpiresItsTimestamp() {
        val previous = probe.currentSnapshot()
        try {
            probe.publishSnapshot(UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Fault, observedAtElapsedMs = 5))
            probe.invalidateAvailability()
            val invalidated = probe.currentSnapshot()
            assertEquals(UltraEnvironmentProbe.State.Fault, invalidated.state)
            assertEquals(-1L, invalidated.observedAtElapsedMs)
            assertFalse(invalidated.rootAvailable)
        } finally { probe.publishSnapshot(previous) }
    }

    @Test fun freshSdkEvidenceCanReplaceFaultAfterRepair() {
        assertEquals(UltraEnvironmentProbe.State.Running,
            probe.stateAfterAdmission(UltraEnvironmentProbe.State.Fault, UltraEnvironmentProbe.State.Running, "OK", true))
    }

    @Test fun aDifferentOrSuspendedIdentityMustNotInheritProtection() {
        val fault = UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Fault)
        assertEquals(UltraEnvironmentProbe.State.NoKey,
            probe.scopeSnapshot(fault, null, "key-a", "boot-a", "boot-a", false).state)
        assertEquals(UltraEnvironmentProbe.State.Unknown,
            probe.scopeSnapshot(fault, "key-b", "key-a", "boot-a", "boot-a", false).state)
        assertEquals(UltraEnvironmentProbe.State.Unknown,
            probe.scopeSnapshot(fault, "key-a", "key-a", "boot-b", "boot-a", false).state)
        assertEquals(UltraEnvironmentProbe.State.Unknown,
            probe.scopeSnapshot(fault, "key-a", "key-a", null, "boot-a", false).state)
        assertEquals(UltraEnvironmentProbe.State.Unknown,
            probe.scopeSnapshot(fault, "key-a", "key-a", "boot-a", "boot-a", true).state)
        assertEquals(UltraEnvironmentProbe.State.Unknown,
            probe.scopeSnapshot(fault, "key-a", "key-a", "boot-a", "boot-a", false, true).state)
    }
}
