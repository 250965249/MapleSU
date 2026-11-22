package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * T11 host tests (§7 T11): the soft reboot belongs to the UI's explicit action or the
 * root-side `--phase post`, never to the provider that just proved the carrier. A lease
 * root cannot survive its own soft reboot, so it must not offer the switch.
 */
class RebootOwnershipTest {
    private fun root(): File =
        sequenceOf(File("."), File("..")).first { File(it, "manager").isDirectory }

    private fun source(relative: String): String = File(root(), relative).readText()

    @Test
    fun theProviderNeverRebootsItself() {
        val provider = source(
            "manager/src/main/java/dev/maplesu/manager/runtime/NativeSuDirectoryProvider.kt")
        assertFalse("the provider must not issue a soft reboot",
            provider.contains("setprop sys.powerctl reboot,soft_reboot"))
        assertFalse("the provider must not spawn a reboot thread",
            provider.contains("maplesu-soft-reboot"))
        assertFalse(provider.contains("svc power reboot soft"))
    }

    @Test
    fun theRebootPathRequiresABoundCarrierProof() {
        val reboot = source("manager/src/main/java/com/maplesu/core/ui/util/SystemReboot.kt")
        assertTrue("requestSystemReboot must consult the carrier binding",
            reboot.contains("carrierBindsAttempt"))
        assertTrue("the gate record must be read for the proof's attempt",
            reboot.contains("hook?.carrier?.attemptId"))
    }

    @Test
    fun onlyKernelCarriersOfferTheSwitch() {
        val dialog = source(
            "manager/src/main/java/dev/maplesu/manager/jailbreak/JailbreakSelectionDialog.kt")
        assertTrue("the switch must be gated by softRebootAvailable",
            dialog.contains("ui.softRebootAvailable"))
        assertTrue(dialog.contains("BACKEND_HOOK") && dialog.contains("BACKEND_KSU"))
    }

    @Test
    fun aProofForAnotherBootDoesNotAuthorizeAnything() {
        val record = JailbreakStatus(
            method = "dirtyfrag", stage = JailbreakStatus.STAGE_DAEMON_READY, message = "test",
            startedAtMillis = 1L, updatedAtMillis = 2L, bootId = "boot-a", attemptId = "attempt-1",
            carrier = CarrierProof(
                kind = "l3-gate", attemptId = "attempt-1", bootId = "boot-b",
                provenAtMillis = 3L, probe = ProbeResult("id -u", 0, "0", 0)))

        assertFalse("a proof from another boot must not bind", carrierBindsAttempt(record))
        assertTrue("the record without a proof stays the legacy path",
            carrierBindsAttempt(record.copy(carrier = null)))
    }
}
