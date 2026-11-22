package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.*
import org.junit.Test

class UltraAutoPairReadinessTest {
    @Test fun sdkRootWithoutActualManagerSuDoesNotPair() {
        var verified = 0
        val result = UltraAutoPair.complete(
            UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running, kernelRootVerified = true),
            current = { true }, alreadyPaired = { true }, persist = { fail("already paired") },
            verifyManagerSu = { verified++; false }, maintain = {})
        assertFalse(result.paired)
        assertEquals("MANAGER_SU_UNVERIFIED", result.reason)
        assertEquals(1, verified)
    }

    @Test fun ownerSessionPairsWithoutWritingPermanentKeyOrRunningMaintenance() {
        val result = UltraAutoPair.complete(
            UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running, kernelRootVerified = true),
            current = { true }, alreadyPaired = { true }, persist = { fail("owner has no permanent key") },
            verifyManagerSu = { true }, maintain = {}, keyState = UltraAutoPair.KeyState.Absent)
        assertTrue(result.paired)
        assertEquals(UltraAutoPair.KeyState.Absent, result.keyState)
    }

    @Test fun revocationDuringManagerSuVerificationDiscardsTheResult() {
        var current = true
        val result = UltraAutoPair.complete(
            UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running, kernelRootVerified = true),
            current = { current }, alreadyPaired = { true }, persist = { fail("already paired") },
            verifyManagerSu = { current = false; true }, maintain = { fail("revoked session") })
        assertFalse(result.paired)
        assertEquals("ULTRA_KEY_CHANGED", result.reason)
    }

    @Test fun runningHelperWithoutRootNeverStartsAuthorizationOrManagerSu() {
        val result = UltraAutoPair.complete(
            UltraEnvironmentProbe.Snapshot(UltraEnvironmentProbe.State.Running),
            current = { fail("no Root proof"); false }, alreadyPaired = { false }, persist = { fail() },
            verifyManagerSu = { fail("no Root proof"); true }, maintain = { fail() })
        assertFalse(result.paired)
        assertEquals("SDK_ROOT_UNVERIFIED", result.reason)
    }
}
