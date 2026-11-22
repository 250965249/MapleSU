package com.maplesu.core.data.repository

import dev.maplesu.manager.runtime.authorization.ApplicationIdentity
import dev.maplesu.manager.runtime.authorization.AuthorizationSnapshot
import dev.maplesu.manager.runtime.authorization.SuperuserTomb
import org.junit.Assert.*
import org.junit.Test

class HookAppListSnapshotTest {
    private fun identity(uid: Int = 10123, updated: Long = 2, installed: Long = 1) = ApplicationIdentity(
        uid, "example.$uid", listOf("example.$uid"), setOf("a".repeat(64)), installed, updated, "/data/app/$uid/base.apk",
    )
    private fun authority(enabled: Boolean = true) = AuthorizationSnapshot(
        enabled, listOf(identity(), identity(10456)).associateBy { it.uid },
    )

    @Test fun hundredsOfRowsUseOneAuthorityReadAndOnlyValidateGrantedIdentities() {
        var reads = 0
        val identities = mutableListOf<Int>()
        val list = HookAppListSnapshot.read({ reads++; authority() }) { identities += it; identity(it) }
        repeat(500) { list.isGranted("example.${10000 + it}", 10000 + it); list.isStale("example.${10000 + it}", 10000 + it) }
        assertEquals(1, reads)
        assertEquals(listOf(10123, 10456), identities)
        assertTrue(list.isGranted("example.10123", 10123))
        assertFalse(list.isStale("example.10123", 10123))
    }

    @Test fun aNewPageAlwaysReadsANewRevision() {
        var reads = 0
        val before = HookAppListSnapshot.read({ reads++; authority() }, ::identity)
        val after = HookAppListSnapshot.read({ reads++; AuthorizationSnapshot.empty() }, ::identity)
        assertTrue(before.isGranted("example.10123", 10123))
        assertFalse(after.isGranted("example.10123", 10123))
        assertEquals(2, reads)
    }

    @Test fun unavailableOrCorruptAuthorityNeverBecomesASuccessfulEmptyList() {
        for (authority in listOf(null, AuthorizationSnapshot.unreadable())) {
            val failure = runCatching { HookAppListSnapshot.read({ authority }) { error("No identity reads") } }
            assertTrue(failure.isFailure)
            assertTrue(failure.exceptionOrNull()?.message?.startsWith("HOOK_AUTHORITY_") == true)
        }
    }

    @Test fun failedSdkMirrorIsVisibleWhileTheAuthorityGrantIsRetained() {
        val snapshot = authority().copy(rev = 3, applied = listOf(
            dev.maplesu.manager.runtime.authorization.SuperuserApplied("ULTRA_ALLOWLIST", 3, 1000, false),
        ))
        val list = HookAppListSnapshot.read({ snapshot }, ::identity)
        assertTrue(list.isGranted("example.10123", 10123))
        assertTrue(list.pendingApply)
    }

    @Test fun masterSwitchDoesNotEraseStoredGrantsFromDisplay() {
        val list = HookAppListSnapshot.read({ authority(false) }, ::identity)
        assertTrue(list.isGranted("example.10123", 10123))
    }

    @Test fun tombstonesNeverResurrectARevokedGrant() {
        val tombs = listOf(SuperuserTomb(10123, "example.10123", 3, 10))
        val list = HookAppListSnapshot.read({ authority().copy(tombs = tombs) }) {
            check(it != 10123); identity(it)
        }
        assertFalse(list.isGranted("example.10123", 10123))
        assertFalse(list.isStale("example.10123", 10123))
    }

    @Test fun sameSignerUpdateKeepsInstalledUidGrant() {
        val list = HookAppListSnapshot.read({ authority() }) { identity(it, updated = 3) }
        assertTrue(list.isGranted("example.10123", 10123))
        assertFalse(list.isStale("example.10123", 10123))
    }

    @Test fun changedOrMissingIdentityStaysVisibleAsStaleRatherThanWired() {
        for (live in listOf(identity(updated = 3, installed = 2), null)) {
            val list = HookAppListSnapshot.read({ authority() }) { if (it == 10123) live else identity(it) }
            assertTrue(list.isStale("example.10123", 10123))
            assertFalse(list.isGranted("other.package", 10123))
            assertFalse(list.isStale("other.package", 10123))
        }
    }
}
