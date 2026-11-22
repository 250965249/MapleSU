package dev.maplesu.manager.runtime

import dev.maplesu.manager.jailbreak.CarrierProof
import dev.maplesu.manager.jailbreak.JailbreakStatus
import dev.maplesu.manager.jailbreak.ProbeResult
import org.junit.Assert.*
import org.junit.Test

class TrustedRuntimeBootTest {
    private fun record() = JailbreakStatus(
        method = "dirtyfrag", stage = JailbreakStatus.STAGE_DAEMON_READY, message = "",
        startedAtMillis = 1, updatedAtMillis = 2, bootId = "boot-a", attemptId = "attempt",
        rootBackend = "hook",
        carrier = CarrierProof("l3-gate", "attempt", "boot-a", 2,
            probe = ProbeResult("id -u", 0, "0", 0)),
    )

    private fun live(attempt: String = "attempt") =
        TrustedRuntime.State(TrustedRuntime.Origin.JAILBREAK, true, attempt)

    @Test fun aFullRebootRejectsBothTheCarrierAndTheLegacyProbeWithoutDeletingHistory() {
        val old = record()
        val result = TrustedRuntime.jailbreakState(old, "boot-b") {
            fail("A previous boot must never start or trust the provider")
            live()
        }
        assertFalse(result.ready)
        assertFalse(result.jailbreak)
        assertEquals(JailbreakStatus.STAGE_DAEMON_READY, old.stage)
        assertEquals("boot-a", old.carrier?.bootId)
    }

    @Test fun anOldLegacyRecordAlsoExpiresOnFullReboot() {
        val result = TrustedRuntime.jailbreakState(record().copy(carrier = null), "boot-b") {
            fail("Legacy provider evidence also needs the current boot")
            live()
        }
        assertFalse(result.ready)
    }

    @Test fun aUserspaceRestartKeepsTheCurrentKernelCarrier() {
        val result = TrustedRuntime.jailbreakState(record(), "boot-a") {
            fail("The current carrier already proves the attempt")
            live()
        }
        assertTrue(result.ready)
        assertTrue(result.jailbreak)
    }

    @Test fun missingBootAttemptAndFailedClaimsNeverProbe() {
        val original = record()
        for ((status, boot) in listOf(
            original to null, original to "", original.copy(bootId = null) to "boot-a",
            original.copy(attemptId = null) to "boot-a",
            original.copy(failure = "failed") to "boot-a",
            original.copy(stage = JailbreakStatus.STAGE_FAILED) to "boot-a",
        )) {
            assertFalse(TrustedRuntime.jailbreakState(status, boot) {
                fail("Incomplete or failed evidence must never probe")
                live()
            }.ready)
        }
    }

    @Test fun aCurrentLegacyLeaseMustMatchItsAttemptAndBeLive() {
        val legacy = record().copy(carrier = null)
        assertTrue(TrustedRuntime.jailbreakState(legacy, "boot-a") { live() }.ready)
        assertFalse(TrustedRuntime.jailbreakState(legacy, "boot-a") { live("other") }.ready)
        assertFalse(TrustedRuntime.jailbreakState(legacy, "boot-a") {
            live().copy(ready = false)
        }.ready)
    }

    @Test fun aCarrierForAnotherAttemptNeedsIndependentConfirmation() {
        val mismatched = record().let { it.copy(carrier = it.carrier!!.copy(attemptId = "other")) }
        var calls = 0
        assertTrue(TrustedRuntime.jailbreakState(mismatched, "boot-a") {
            calls++
            live()
        }.ready)
        assertEquals(1, calls)
    }
}
