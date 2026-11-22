package dev.maplesu.manager.runtime

import dev.maplesu.manager.jailbreak.JailbreakStatus
import org.junit.Assert.*
import org.junit.Test

class HookReproofResultTest {
    private val ready = HookReproofResult(true, true, "attempt", "boot", null)

    @Test fun absentCarrierAllowsFreshPreparation() {
        assertNull(ready.copy(eligible = false, reproved = false).outcome("attempt", "boot"))
    }

    @Test fun aProvedAndPublishedCarrierReusesItsAttempt() {
        val result = requireNotNull(ready.outcome("attempt", "boot"))
        assertEquals(JailbreakStatus.STAGE_DAEMON_READY, result.stage)
        assertEquals("attempt", result.attemptId)
        assertNull(result.failure)
    }

    @Test fun publicationFailureNeverRequestsFreshEscalation() {
        val token = "HOOK_BACKEND_NOT_READY:su_publication_failed"
        val result = requireNotNull(ready.copy(reproved = false, failure = token).outcome("attempt", "boot"))
        assertEquals(JailbreakStatus.STAGE_FAILED, result.stage)
        assertEquals(token, result.failure)
    }

    @Test fun failedCarrierProbeNeverRequestsFreshEscalation() {
        val result = requireNotNull(ready.copy(reproved = false).outcome("attempt", "boot"))
        assertEquals(JailbreakStatus.STAGE_FAILED, result.stage)
    }

    @Test fun aMalformedReplyIsNotAnAbsentCarrier() {
        val result = requireNotNull(ready.copy(eligible = null, reproved = false).outcome("attempt", "boot"))
        assertEquals(JailbreakStatus.STAGE_FAILED, result.stage)
    }

    @Test fun foreignAttemptOrBootDoesNotBecomeSuccess() {
        assertNotNull(ready.copy(attemptId = "other").outcome("attempt", "boot")?.failure)
        assertNotNull(ready.copy(bootId = "old").outcome("attempt", "boot")?.failure)
        assertNotNull(ready.outcome("attempt", null)?.failure)
    }

    @Test fun aContradictoryReplyPreservesTheFailure() {
        val result = requireNotNull(ready.copy(failure = "publication_failed").outcome("attempt", "boot"))
        assertEquals(JailbreakStatus.STAGE_FAILED, result.stage)
        assertEquals("publication_failed", result.failure)
    }
}
