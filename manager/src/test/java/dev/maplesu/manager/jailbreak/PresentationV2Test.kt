package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * T2 host tests (§7 T2): presentation and derived views are separate from the record.
 * No owner-death text, no synthetic failure, and a carrier proof only counts for the
 * attempt/boot it was written for.
 */
class PresentationV2Test {
    private fun record(
        stage: String = JailbreakStatus.STAGE_DAEMON_READY,
        attemptId: String = "attempt-1",
        bootId: String = "boot-a",
        carrier: CarrierProof? = null,
    ): JailbreakStatus = JailbreakStatus(
        method = "dirtyfrag",
        stage = stage,
        message = "test",
        startedAtMillis = 1L,
        updatedAtMillis = 2L,
        bootId = bootId,
        attemptId = attemptId,
        carrier = carrier,
    )

    private fun proof(attemptId: String = "attempt-1", bootId: String = "boot-a"): CarrierProof =
        CarrierProof(kind = "l3-gate", attemptId = attemptId, bootId = bootId,
            provenAtMillis = 3L, probe = ProbeResult("sh -c id -u", 0, "0", 0))

    @Test
    fun ownerExitedIsNoLongerAFailureText() {
        // The token may still be read from a legacy file; it must not be presented as
        // this attempt's failure any more (§7 T2).
        assertEquals(jailbreakFailureText("JAILBREAK_ATTEMPT_FAILED"), jailbreakFailureText("JAILBREAK_OWNER_EXITED"))
    }

    @Test
    fun supersededExplainsRebootAndCarrierLoss() {
        val text = jailbreakFailureText("JAILBREAK_SUPERSEDED")
        assertTrue("must explain the old session is unusable: $text", text.contains("失效"))
        assertTrue("must mention the reboot: $text", text.contains("重启"))
    }

    @Test
    fun sessionActiveSaysRestartOrEndTheSession() {
        val text = jailbreakFailureText("JAILBREAK_SESSION_ACTIVE")
        assertTrue(text.contains("会话"))
        assertTrue(text.contains("重启"))
        assertTrue(text.contains("结束"))
    }

    @Test
    fun kmiMismatchNamesDeviceAndArtifact() {
        val text = jailbreakFailureText("MAPLESU_TARGET_KMI_MISMATCH:6.6.118/6.6.89")
        assertTrue("device KMI missing: $text", text.contains("6.6.118"))
        assertTrue("artifact KMI missing: $text", text.contains("6.6.89"))
        assertTrue("must say it was refused: $text", text.contains("拒绝"))
    }

    @Test
    fun handoverTokensAreNotGeneric() {
        val tokens = listOf(
            "MAPLESU_HANDOVER_LOAD_FAILED",
            "MAPLESU_HANDOVER_KSU_LATE_LOAD_FAILED",
            "MAPLESU_HANDOVER_RESTORE_UNVERIFIED",
            "MAPLESU_HANDOVER_EVIDENCE_UNREADABLE",
        )
        tokens.forEach { token ->
            assertFalse("$token fell through to the generic text", jailbreakFailureText(token) == "操作未能完成")
        }
    }

    @Test
    fun ownerExitBecomesAHintAndNeverChangesTheStage() {
        val status = record().withDerived(Derived(ownerAlive = false))

        val hint = jailbreakDerivedHint(status)

        assertNotNull("a derived owner exit must surface as a hint", hint)
        assertTrue("hint must explain the process exited: $hint", hint!!.contains("退出"))
        assertEquals("a hint never rewrites the stage", JailbreakStatus.STAGE_DAEMON_READY, status.stage)
        assertNull(status.failure)
    }

    @Test
    fun derivedHintIsSilentWhenEverythingIsAlive() {
        assertNull(jailbreakDerivedHint(record().withDerived(Derived(ownerAlive = true))))
    }

    @Test
    fun carrierProofOnlyBindsItsOwnAttemptAndBoot() {
        assertTrue(carrierBindsAttempt(record(carrier = proof())))
        assertFalse("another attempt's proof must not bind",
            carrierBindsAttempt(record(carrier = proof(attemptId = "attempt-2"))))
        assertFalse("another boot's proof must not bind",
            carrierBindsAttempt(record(carrier = proof(bootId = "boot-b"))))
        assertTrue("a record without a proof is the legacy path", carrierBindsAttempt(record()))
    }

    @Test
    fun presentationSourceNoLongerProducesOwnerExited() {
        val root = sequenceOf(File("."), File("..")).first { File(it, "manager").isDirectory }
        val source = File(root,
            "manager/src/main/java/dev/maplesu/manager/jailbreak/JailbreakFailurePresentation.kt").readText()
        assertFalse("the presentation table still mentions JAILBREAK_OWNER_EXITED",
            source.contains("JAILBREAK_OWNER_EXITED"))
    }
}
