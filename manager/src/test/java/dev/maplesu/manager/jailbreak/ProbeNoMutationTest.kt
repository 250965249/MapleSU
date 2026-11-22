package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * T5 host tests (§5 C2, §7 T5): the status probe observes, it never mutates. Polling
 * must not write `status.json`, must not revoke the published su endpoint, and must
 * not turn a live stage into EXPIRED.
 */
class ProbeNoMutationTest {
    private fun root(): File =
        sequenceOf(File("."), File("..")).first { File(it, "manager").isDirectory }

    private fun source(relative: String): String = File(root(), relative).readText()

    private fun providerStatusBlock(): String {
        val source = source("manager/src/main/java/dev/maplesu/manager/runtime/NativeSuDirectoryProvider.kt")
        val start = source.indexOf("if (method == \"status\")")
        val end = source.indexOf("if (method == \"deploySu\")")
        assertTrue("status block not found", start >= 0 && end > start)
        return source.substring(start, end)
    }

    @Test
    fun providerStatusProbeDoesNotWrite() {
        val block = providerStatusBlock()
        assertFalse("the probe must not persist a derived stage", block.contains(".write("))
    }

    @Test
    fun providerStatusProbeDoesNotRevokeThePublication() {
        val block = providerStatusBlock()
        assertFalse("polling must not tear down the su endpoint",
            block.contains("clearRestrictedSu()"))
    }

    @Test
    fun controllerStatusStopsFabricatingExpired() {
        val controller = source(
            "manager/src/main/java/dev/maplesu/manager/jailbreak/JailbreakController.kt")
        assertFalse("the UI-side probe must not synthesise EXPIRED",
            controller.contains("STAGE_EXPIRED"))
        assertFalse("the expired-session token factory is gone",
            controller.contains("jailbreakExpiredSessionCode"))
    }

    @Test
    fun aDeadTransportIsAPresentationFact() {
        val record = JailbreakStatus(
            method = "dirtyfrag", stage = JailbreakStatus.STAGE_DAEMON_READY, message = "test",
            startedAtMillis = 1L, updatedAtMillis = 2L, bootId = "boot-a", attemptId = "attempt-1")

        val observed = record.withDerived(Derived(carrierLive = false))

        assertEquals("the stage is a fact and must survive the probe",
            JailbreakStatus.STAGE_DAEMON_READY, observed.stage)
        assertEquals(false, observed.derived?.carrierLive)
    }
}
