package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertEquals
import org.junit.Test

class JailbreakCancellationStatusTest {
    private fun status(stage: String, failure: String? = null) = JailbreakStatus(
        method = "dirtyfrag", stage = stage, message = "cancel requested",
        startedAtMillis = 1L, updatedAtMillis = 2L, bootId = "boot",
        attemptId = "attempt", failure = failure,
    )

    @Test fun cancellationIsAllowedWhileTheProviderIsRunning() {
        val cancelled = status(JailbreakStatus.STAGE_PROVIDER_RUNNING)
            .advance(status(JailbreakStatus.STAGE_CANCELLED, "JAILBREAK_CANCELLED"))
        assertEquals(JailbreakStatus.STAGE_CANCELLED, cancelled.stage)
    }

    @Test fun lateProviderProgressDoesNotTurnCancellationIntoSuccess() {
        val cancelled = status(JailbreakStatus.STAGE_CANCELLED, "JAILBREAK_CANCELLED")
        listOf(JailbreakStatus.STAGE_HANDOFF_AUTHENTICATED,
            JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED,
            JailbreakStatus.STAGE_DAEMON_READY,
            JailbreakStatus.STAGE_FAILED).forEach { lateStage ->
            val observed = cancelled.advance(status(lateStage))
            assertEquals(JailbreakStatus.STAGE_CANCELLED, observed.stage)
            assertEquals("JAILBREAK_CANCELLED", observed.failure)
        }
    }
}
