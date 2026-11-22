package dev.maplesu.manager.runtime.ultra

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class UltraAuthorizationResultTest {
    private fun receipt(phase: Long, code: String = "-19999") = JSONObject()
        .put("schemaVersion", 1).put("operationResultAvailable", true)
        .put("operation", 4).put("resultCode", code).put("primaryErrorCode", code)
        .put("primaryPhase", phase).put("diagnosticsComplete", true)
        .put("commitState", 1).put("restoreState", 2).put("deliveryState", 1)
        .put("recoveryCount", 0).put("recoveryTotal", 0).put("recovery", org.json.JSONArray())
        .put("transport", JSONObject().put("status", 1).put("errno", 0)
            .put("childWaitStatus", 0).put("valid", true))

    @Test fun indexPreparationFailureKeepsItsErrorAndPhase() {
        val value = requireNotNull(UltraAuthorizationResult.parse(receipt(43)))
        assertEquals(43L, value.primaryPhase)
        assertEquals("-19999", value.resultCode)
        assertEquals("-19999", value.primaryErrorCode)
        assertFalse(value.deliveryConfirmed)
    }

    @Test fun everyExistingPrimaryPhaseRemainsAccepted() {
        for (phase in listOf(0L, 1L, 2L, *LongRange(10, 15).toList().toTypedArray(),
            *LongRange(20, 25).toList().toTypedArray(), *LongRange(30, 42).toList().toTypedArray(), 50L)) {
            assertNotNull("phase=$phase", UltraAuthorizationResult.parse(receipt(phase, if (phase == 0L) "0" else "-19999")))
        }
    }

    @Test fun unknownPhasesRemainRejected() {
        for (phase in listOf(-1L, 3L, 9L, 16L, 26L, 29L, 44L, 49L, 51L, 0xffffffffL)) {
            assertNull("phase=$phase", UltraAuthorizationResult.parse(receipt(phase)))
        }
    }

    @Test fun indexFailureDoesNotBecomeSuccessfulReceipt() {
        assertNull(UltraAuthorizationResult.parse(receipt(43).put("resultCode", "0")))
        assertNull(UltraAuthorizationResult.parse(receipt(43).put("primaryErrorCode", "0")))
    }
}
