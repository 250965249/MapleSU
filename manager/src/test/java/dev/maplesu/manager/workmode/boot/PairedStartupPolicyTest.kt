package dev.maplesu.manager.workmode.boot

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PairedStartupPolicyTest {
    @Test
    fun verifiedExistingIdentityCanStartAfterFirstFrame() {
        assertTrue(PairedStartupPolicy.shouldExpedite(false, true, 48, false))
    }

    @Test
    fun newIdentityRetainsTheDelayedPath() {
        assertFalse(PairedStartupPolicy.shouldExpedite(false, false, 48, false))
    }

    @Test
    fun missingOrMalformedKeyDoesNotUsePairingHint() {
        for (length in listOf(null, 0, 47, 49)) {
            assertFalse(PairedStartupPolicy.shouldExpedite(false, true, length, false))
        }
    }

    @Test
    fun suspendedEnvironmentDoesNotResumeImplicitly() {
        assertFalse(PairedStartupPolicy.shouldExpedite(false, true, 48, true))
    }

    @Test
    fun resolvedModeDoesNotNeedAnotherDetection() {
        assertFalse(PairedStartupPolicy.shouldExpedite(true, true, 48, false))
    }

    @Test
    fun resolvedNormalDoesNotCallUltraSdk() {
        assertFalse(PairedStartupPolicy.refreshEnvironmentIfEligible(true, false) {
            error("resolved mode must not probe")
        })
    }

    @Test
    fun existingOrUnknownKsuEvidenceDoesNotCallUltraSdk() {
        for (responded in listOf(true, null)) {
            assertFalse(PairedStartupPolicy.refreshEnvironmentIfEligible(false, responded) {
                error("KSU must be excluded first")
            })
        }
    }

    @Test
    fun stalePairingWithUnknownOrStoppedEnvironmentDoesNotProveRunning() {
        var probes = 0
        assertFalse(PairedStartupPolicy.refreshEnvironmentIfEligible(false, false) {
            probes++
            false
        })
        assertTrue(probes == 1)
    }

    @Test
    fun onlyActualRunningResultIsReportedAsReady() {
        var probes = 0
        assertTrue(PairedStartupPolicy.refreshEnvironmentIfEligible(false, false) {
            probes++
            true
        })
        assertTrue(probes == 1)
    }

    @Test
    fun sdkFailureFallsBackWithoutPretendingReady() {
        assertFalse(PairedStartupPolicy.refreshEnvironmentIfEligible(false, false) {
            error("SDK_UNAVAILABLE")
        })
    }
}
