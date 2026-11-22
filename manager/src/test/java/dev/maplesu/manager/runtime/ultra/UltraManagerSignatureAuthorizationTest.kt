package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.runtime.authorization.ApplicationIdentity
import org.junit.Assert.*
import org.junit.Test

class UltraManagerSignatureAuthorizationTest {
    private val name = "dev.maplesu.manager"
    private val signers = setOf("a".repeat(64))
    private val trust = UltraReinstallTrust(name, 0, signers)
    private fun identity(uid: Int = 10999, signer: String = "a") =
        ApplicationIdentity(uid, name, listOf(name), setOf(signer.repeat(64)), 10, 11, "/data/app/new/base.apk")

    private class State(var packages: List<String>?) {
        val events = mutableListOf<String>()
        var grantError = "OK"
        var revokeError = "OK"
        fun refresh(trust: UltraReinstallTrust, current: () -> ApplicationIdentity?) =
            UltraManagerSignatureAuthorization.refresh(trust, current,
                { events += "read"; packages },
                { events += "grant"; if (grantError == "OK") packages = (packages.orEmpty() + trust.packageName).distinct(); grantError },
                { events += "revoke"; if (revokeError == "OK") packages = packages.orEmpty() - trust.packageName; revokeError },
                { events += "refresh"; "OK" })
    }

    @Test fun sameSignerReinstallGetsTheCurrentUidAndRetainsOtherGrants() {
        val state = State(listOf("other.app", name))
        assertEquals("OK", state.refresh(trust) { identity() })
        assertEquals(listOf("read", "grant", "read"), state.events)
        assertTrue("other.app" in state.packages.orEmpty())
    }

    @Test fun differentlySignedOrOtherUserManagerIsRevokedBeforeAnyUidRefresh() {
        for (current in listOf(identity(signer = "b"), identity(uid = 110999))) {
            val state = State(listOf("other.app", name))
            assertEquals("OK", state.refresh(trust) { current })
            assertEquals(listOf("read", "revoke", "read"), state.events)
            assertEquals(listOf("other.app"), state.packages)
        }
    }

    @Test fun unknownIdentityRevokesOnceAndRemainsPendingWithoutRebuildingTheTable() {
        val state = State(listOf("other.app", name))
        repeat(4) {
            assertEquals("MANAGER_IDENTITY_PENDING", state.refresh(trust) { null })
        }
        assertEquals(listOf("read", "revoke", "read", "read", "read", "read"), state.events)
        assertEquals(listOf("other.app"), state.packages)
        assertEquals("OK", state.refresh(trust) { identity() })
        assertEquals(1, state.events.count { it == "grant" })
        assertEquals(1, state.events.count { it == "revoke" })
        assertFalse("refresh" in state.events)
    }

    @Test fun unknownIdentityWithoutAManagerGrantOnlyReads() {
        val state = State(listOf("other.app"))
        repeat(20) {
            assertEquals("MANAGER_IDENTITY_PENDING", state.refresh(trust) { null })
        }
        assertEquals(List(20) { "read" }, state.events)
    }

    @Test fun absentManagerGrantNeverGetsReaddedByName() {
        val state = State(listOf("other.app"))
        assertEquals("OK", state.refresh(trust) { identity(signer = "b") })
        assertEquals(listOf("read", "refresh"), state.events)
    }

    @Test fun failedRevocationDoesNotPublishAnUntrustedUidTable() {
        val state = State(listOf(name)).apply { revokeError = "WRITE_FAILED" }
        assertEquals("WRITE_FAILED", state.refresh(trust) { identity(signer = "b") })
        assertEquals(listOf("read", "revoke"), state.events)
    }

    @Test fun unreadableListAndFailedGrantAreNotAcceptedAsRestored() {
        val unreadable = State(null)
        assertEquals("MANAGER_AUTH_LIST_UNREADABLE", unreadable.refresh(trust) { identity() })
        assertEquals(listOf("read"), unreadable.events)
        val denied = State(listOf(name)).apply { grantError = "ADD_FAILED" }
        assertEquals("ADD_FAILED", denied.refresh(trust) { identity() })
        assertEquals(listOf("read", "grant"), denied.events)
    }

    @Test fun replacementDuringGrantIsRevokedAndDoesNotTriggerAnotherNameRemap() {
        val state = State(listOf(name))
        var reads = 0
        assertEquals("MANAGER_IDENTITY_CHANGED", state.refresh(trust) {
            if (++reads == 1) identity() else identity(signer = "b")
        })
        assertEquals(listOf("read", "grant", "read", "revoke"), state.events)
        assertFalse(name in state.packages.orEmpty())
    }

    @Test fun backupNeedsThePinnedSignerEvenWhenNoKeySuAlreadyWorks() {
        for (anchor in listOf(null, trust)) {
            for (current in listOf(null, identity(), identity(signer = "b"), identity(uid = 110999))) {
                var reads = 0
                val recovered = UltraManagerSignatureAuthorization.recover(anchor, { current }) { reads++; "secret" }
                val valid = anchor != null && current == identity()
                assertEquals(if (valid) "secret" else null, recovered)
                assertEquals(if (valid) 1 else 0, reads)
            }
        }
    }

    @Test fun backupDiscardsTheCandidateWhenInstallationChangesDuringRead() {
        var reads = 0
        assertNull(UltraManagerSignatureAuthorization.recover(trust,
            { if (++reads == 1) identity() else identity(signer = "b") }, { "secret" }))
    }

    @Test fun savedTrustConfigRequiresTheFixedPackageAndACompleteSigningSet() {
        val config = """{"schema":1,"userId":0,"packageName":"$name","signers":["${"a".repeat(64)}"]}"""
        assertTrue(requireNotNull(UltraReinstallTrust.fromConfig(config)).allows(10999, identity()))
        for (invalid in listOf("{}", config.replace("$name", "other.app"),
            config.replace("${"a".repeat(64)}", "bad"), config.replace("[\"${"a".repeat(64)}\"]", "[]"),
            config.replace("\"userId\":0", "\"userId\":-1"), config.replace("\"schema\":1", "\"schema\":2"))) {
            assertNull(invalid, UltraReinstallTrust.fromConfig(invalid))
        }
    }
}
