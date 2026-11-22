package dev.maplesu.manager.runtime

import dev.maplesu.manager.jailbreak.JailbreakRequest
import dev.maplesu.manager.jailbreak.JailbreakStatus
import dev.maplesu.manager.jailbreak.preparedJailbreakOutcome
import org.junit.Assert.*
import org.junit.Test

class HookPublicationResultTest {
    private val ready = ClaimResult(JailbreakStatus.STAGE_DAEMON_READY, null, "ucred")

    @Test fun aFailedClaimNeverPublishes() {
        var calls = 0
        val failed = ready.copy(failure = "gate_not_armed")
        assertEquals(failed, publishConfirmedHook(failed) { calls++ })
        assertEquals(0, calls)
    }

    @Test fun successfulPublicationPreservesTheClaim() {
        var calls = 0
        assertEquals(ready, publishConfirmedHook(ready) { calls++ })
        assertEquals(1, calls)
    }

    @Test fun failedPublicationCannotBecomeAControllerSuccessFromHistoricalReady() {
        val request = JailbreakRequest("dirtyfrag", "attempt", "boot", rootBackend = JailbreakRequest.BACKEND_HOOK)
        val historical = JailbreakStatus(
            method = request.method, stage = ready.stage, message = "carrier proven",
            startedAtMillis = 1, updatedAtMillis = 2, bootId = request.bootId,
            attemptId = request.attemptId, rootBackend = request.rootBackend,
        )
        val publication = publishConfirmedHook(ready) { error("broker failed") }
        assertFalse(publication.ok)
        val reply = hookPreparationFailure(historical, request, requireNotNull(publication.failure), "publish failed", 3, 42)
        val outcome = preparedJailbreakOutcome(request, reply)
        assertEquals(JailbreakStatus.STAGE_FAILED, outcome.stage)
        assertEquals(publication.failure, outcome.failure)
        assertNull("A failed reply must not rewrite historical evidence", historical.failure)
    }
}
