package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GhostlockRestoreObservationTest {
    private val request = JailbreakRequest("ghostlock", "attempt", "boot",
        softReboot = false, rootBackend = JailbreakRequest.BACKEND_HOOK)
    private val identity = LeaseProtocol.Identity(LeaseProtocol.Provider.GHOSTLOCK, 1234, 0,
        "boot", "u:r:shell:s0", 1, 0, 100L, true)

    @Test
    fun `failed restore observations survive the terminal status merge`() {
        val restore = LeaseProtocol.Restore(0, LeaseProtocol.Origin.BASELINE, 1, 255, 2, -1)
        val observation = ghostlockRestoreObservation(request, "6.6.118", identity, restore)
        val failed = observation.advance(JailbreakStatus(method = "ghostlock",
            stage = JailbreakStatus.STAGE_FAILED, message = observation.message,
            startedAtMillis = 0, updatedAtMillis = 0, bootId = "boot",
            failure = "GHOSTLOCK_RESTORE_UNVERIFIED:FAILED"))
        assertEquals("FAILED", failed.restoreState)
        assertEquals("BASELINE", failed.restoreOrigin)
        assertEquals(1, failed.restoreEnforcing)
        assertEquals(255, failed.restoreCheckreqprot)
        assertEquals(2, failed.restorePolicy)
        assertEquals(1, failed.restoreFailures)
        assertTrue(failed.message.contains("checkreqprot=255"))
        assertFalse(failed.message.contains("restore verified"))
        assertEquals(request.attemptId, failed.attemptId)
        assertEquals(request.rootBackend, failed.rootBackend)
    }

    @Test
    fun `authenticated restore observations do not claim daemon readiness`() {
        for (restore in listOf(
            LeaseProtocol.Restore(1, LeaseProtocol.Origin.OBSERVED, 1, 0, 2, -1),
            LeaseProtocol.Restore(3, LeaseProtocol.Origin.BASELINE, 1, 2, 2, -1))) {
            val observation = ghostlockRestoreObservation(request, "6.6.118", identity, restore)
            assertTrue(restore.verified())
            assertEquals(JailbreakStatus.STAGE_HANDOFF_AUTHENTICATED, observation.stage)
            assertEquals(restore.state(), observation.restoreState)
            assertEquals(restore.checkreqprot(), observation.restoreCheckreqprot)
            assertEquals(0, observation.restoreFailures)
            assertEquals(1234, observation.workerPid)
        }
    }
}
