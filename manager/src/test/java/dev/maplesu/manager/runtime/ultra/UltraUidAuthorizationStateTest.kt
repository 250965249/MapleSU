package dev.maplesu.manager.runtime.ultra

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class UltraUidAuthorizationStateTest {
    private fun receipt(code: Int = 0, delivery: Int = 2, operation: Int = 1): NativeReceipt {
        val error = if (code == 0) "OK" else "ERR_SU_DELIVERY_INCOMPLETE"
        val detail = JSONObject().put("schemaVersion", 1).put("operationResultAvailable", true)
            .put("operation", operation).put("resultCode", code.toString()).put("diagnosticsComplete", true)
            .put("commitState", 2).put("restoreState", 1).put("deliveryState", delivery)
            .put("primaryErrorCode", code.toString()).put("primaryPhase", if (code == 0) 0 else 50)
            .put("recoveryCount", 0).put("recoveryTotal", 0).put("recovery", JSONArray())
            .put("transport", JSONObject().put("status", 1).put("errno", 0).put("childWaitStatus", 0).put("valid", true))
        return NativeReceipt(1, "maplesu_ultra", 1, "set_su_uid_profile", code == 0, error, code,
            null, JSONObject().put("authorizationResult", detail), "")
    }

    private class Port(var result: NativeReceipt) : SuAuthPort {
        override val supportsUidProfiles = true
        var profiles: List<SuUidProfile>? = emptyList()
        var applyWrite = true
        var reads = 0
        val writes = mutableListOf<SuUidProfile>()
        override fun uidProfiles(): List<SuUidProfile>? { reads++; return profiles }
        override fun setUidProfile(uid: Int, packageName: String, allow: Boolean): NativeReceipt {
            val profile = SuUidProfile(uid, allow, packageName)
            writes += profile
            if (applyWrite) profiles = profiles?.filterNot { it.uid == uid }?.plus(profile)
            return result
        }
        override fun snapshot(): List<String>? = error("UID path must not consult package projection")
        override fun add(packageName: String): NativeReceipt = error("legacy package write")
        override fun remove(packageName: String): NativeReceipt = error("legacy package write")
    }

    @Test fun samePackageInTwoUsersAndSharedUidUseExactUidDecisions() {
        val port = Port(receipt(operation = 2)).apply { profiles = listOf(SuUidProfile(10123, true, "example.one")) }
        val state = UltraAuthorizationState()
        assertTrue(state.setUidGranted(port, 110123, "example.one", false).succeeded)
        assertEquals(true, state.snapshot.profiles[10123]?.allow)
        assertEquals(false, state.snapshot.profiles[110123]?.allow)
        assertTrue(state.setUidGranted(port, 10123, "example.shared", false).succeeded)
        assertEquals(false, state.snapshot.profiles[10123]?.allow)
        assertEquals(2, state.snapshot.profiles.size)
    }

    @Test fun fileCommitWithoutDeliveryOrMatchingFreshUidReadbackStaysPending() {
        val port = Port(receipt()).apply { applyWrite = false }
        val state = UltraAuthorizationState()
        val mismatched = state.setUidGranted(port, 110123, "example.one", true)
        assertFalse(mismatched.succeeded)
        assertTrue(mismatched.decisionCommitted)
        assertTrue(mismatched.pendingApply)
        port.applyWrite = true
        port.result = receipt(-21001, 1)
        val closed = state.setUidGranted(port, 110123, "example.one", true)
        assertEquals(-21001, closed.receipt?.sdkErrorCode)
        assertTrue(closed.pendingApply)
        assertFalse(closed.succeeded)
        assertEquals(2, port.writes.size)
    }

    @Test fun profileReadFailureRetainsFailureAndDoesNotReplayMutation() {
        val port = Port(receipt()).apply { profiles = null }
        val attempt = UltraAuthorizationState().setUidGranted(port, 110123, "example.one", false)
        assertFalse(attempt.succeeded)
        assertTrue(attempt.pendingApply)
        assertEquals(1, port.writes.size)
        assertEquals(1, port.reads)
    }

    @Test fun uidListReadDoesNotClearPendingStandardSuDelivery() {
        val state = UltraAuthorizationState()
        val port = Port(receipt(-21001, 1))
        assertTrue(state.setUidGranted(port, 110123, "example.one", true).pendingApply)
        assertTrue(state.snapshot.deliveryIncomplete)
        assertNull(state.refresh(port))
        assertTrue("Membership alone does not establish standard-su delivery", state.snapshot.deliveryIncomplete)
        assertEquals(1, port.writes.size)
        port.result = receipt()
        assertTrue(state.setUidGranted(port, 110123, "example.one", true).succeeded)
        assertFalse(state.snapshot.deliveryIncomplete)
    }

    @Test fun legacyPackageProjectionUsesTheManagersOwnAndroidUser() {
        val state = UltraAuthorizationState(currentUserId = 1)
        val port = Port(receipt()).apply { profiles = listOf(
            SuUidProfile(10123, true, "example.primary"),
            SuUidProfile(110123, true, "example.secondary")) }
        assertNull(state.refresh(port))
        assertEquals(setOf("example.secondary"), state.snapshot.packages)
        assertEquals(setOf(10123, 110123), state.snapshot.profiles.keys)
    }

    @Test fun ownerSyncRetainsUnknownCommitWithoutItsDurableAuthorityFact() {
        val sync = receipt().let { original ->
            val data = JSONObject(original.data.toString())
            data.getJSONObject("authorizationResult").put("commitState", 0)
            original.copy(data = data)
        }
        val port = Port(sync)
        val state = UltraAuthorizationState()
        val unconfirmed = state.setUidGranted(port, 110123, "example.one", true)
        assertEquals("SU_UID_COMMIT_UNCONFIRMED", unconfirmed.error)
        val confirmed = state.setUidGranted(port, 110123, "example.one", true, durableDecisionCommitted = true)
        assertTrue(confirmed.succeeded)
        assertFalse(confirmed.decisionCommitted)
        assertTrue(confirmed.commitUnknown)
    }
}
