package dev.maplesu.manager.runtime

import org.junit.Assert.*
import org.junit.Test

class NativeSuDiscoveryAdmissionTest {
    @Test fun anUnlistedUidCannotInspectOrStartTheRootTransport() {
        for (ready in listOf(false, true)) {
            val calls = mutableListOf<String>()
            assertNull(discoverNativeSuEndpoint(10002, 10001,
                eligible = { calls += "admission"; false },
                authorized = { error("unlisted UID reached authority") },
                endpoint = { calls += "endpoint"; if (ready) Any() else null }))
            assertEquals(listOf("admission"), calls)
        }
    }

    @Test fun revocationDoesNotRevealWhetherAnExecutorExists() {
        assertNull(discoverNativeSuEndpoint(10002, 10001,
            eligible = { true }, authorized = { false },
            endpoint = { error("revoked UID inspected executor") }))
    }

    @Test fun anAuthorizedCallerReceivesTheOriginalObjectAfterPolicy() {
        val original = Any()
        val calls = mutableListOf<String>()
        assertSame(original, discoverNativeSuEndpoint(10002, 10001,
            eligible = { calls += "admission"; true },
            authorized = { calls += "policy"; true },
            endpoint = { calls += "endpoint"; original }))
        assertEquals(listOf("admission", "policy", "endpoint"), calls)
    }

    @Test fun theManagerCanRecoverWithoutAProjectedGrant() {
        val original = Any()
        assertSame(original, discoverNativeSuEndpoint(10001, 10001,
            eligible = { error("manager grant projection") },
            authorized = { error("manager policy transport") }, endpoint = { original }))
    }

    @Test fun thePrivatePrefilterTracksTheExistingSwitchAndRevocations() {
        val identity = dev.maplesu.manager.runtime.authorization.ApplicationIdentity(
            10002, "example.app", listOf("example.app"), setOf("a".repeat(64)),
            1, 1, "/data/app/example.app/base.apk")
        val snapshot = dev.maplesu.manager.runtime.authorization.AuthorizationSnapshot(
            enabled = true, grants = mapOf(10002 to identity), rev = 2, uidRev = mapOf(10002 to 2L))
        NativeSuAdmission.accept(snapshot)
        assertTrue(NativeSuAdmission.eligible(10002))
        assertFalse(NativeSuAdmission.eligible(10003))
        NativeSuAdmission.accept(snapshot.copy(enabled = false))
        assertFalse(NativeSuAdmission.eligible(10002))
        NativeSuAdmission.accept(snapshot.copy(corrupt = true))
        assertFalse(NativeSuAdmission.eligible(10002))
        NativeSuAdmission.accept(snapshot.copy(tombs = listOf(
            dev.maplesu.manager.runtime.authorization.SuperuserTomb(10002, "example.app", 3, 1))))
        assertFalse(NativeSuAdmission.eligible(10002))
        NativeSuAdmission.accept(null)
        assertFalse(NativeSuAdmission.eligible(10002))
    }

    @Test fun aTransientAuthorityReadDoesNotEraseAnExistingGrantPrefilter() {
        val identity = dev.maplesu.manager.runtime.authorization.ApplicationIdentity(
            10042, "example.recovery", listOf("example.recovery"), setOf("b".repeat(64)),
            1, 1, "/data/app/example.recovery/base.apk")
        val snapshot = dev.maplesu.manager.runtime.authorization.AuthorizationSnapshot(
            enabled = true, grants = mapOf(10042 to identity), rev = 3, uidRev = mapOf(10042 to 3L))
        try {
            NativeSuAdmission.accept(snapshot)
            NativeSuAdmission.accept(null)
            assertTrue("temporary transport failure must not strand an existing grant",
                NativeSuAdmission.eligible(10042))
            assertNull(discoverNativeSuEndpoint<Any>(10042, 10001,
                eligible = { NativeSuAdmission.eligible(10042) }, authorized = { false },
                endpoint = { error("unverified policy reached executor") }))
        } finally { NativeSuAdmission.accept(snapshot.copy(enabled = false)) }
    }

    @Test fun noLiveEndpointStillMeansNotReadyAfterAuthorization() {
        assertNull(discoverNativeSuEndpoint<Any>(10002, 10001,
            eligible = { true }, authorized = { true }, endpoint = { null }))
    }
}
