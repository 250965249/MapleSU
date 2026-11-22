package dev.maplesu.manager.runtime.authorization

import dev.maplesu.manager.runtime.ultra.UltraAuthorizationAttempt
import dev.maplesu.manager.runtime.ultra.SuUidProfile
import org.junit.Assert.*
import org.junit.Test

class UltraAllowlistMirrorTest {
    private val uid = 10123
    private val pkg = "com.example.host"
    private fun identity(path: String = "/data/app/host/base.apk", identityUid: Int = uid,
                         installedAt: Long = 1000L) = ApplicationIdentity(
        identityUid, pkg, listOf(pkg), setOf("a".repeat(64)), installedAt, 2000L, path,
    )
    private fun snapshot(enabled: Boolean = true) = AuthorizationSnapshot(
        enabled, mapOf(uid to identity()), rev = 4, uidRev = mapOf(uid to 4L),
    )

    private class Port : UltraAllowlistPort {
        var packages: Set<String>? = emptySet()
        var identity: ApplicationIdentity? = null
        var reject = false
        val writes = mutableListOf<Pair<String, Boolean>>()
        val publishedUids = mutableMapOf<String, Int>()
        override fun packages() = packages
        override fun identity(uid: Int) = identity?.takeIf { it.uid == uid }
        override fun setAllowed(packageName: String, allowed: Boolean): UltraAuthorizationAttempt {
            writes += packageName to allowed
            if (reject) return UltraAuthorizationAttempt.local("APPLY_REJECTED")
            packages = if (allowed) packages.orEmpty() + packageName else packages.orEmpty() - packageName
            if (allowed) {
                identity?.takeIf { it.packageName == packageName }?.let { publishedUids[packageName] = it.uid }
            } else {
                publishedUids.remove(packageName)
            }
            return UltraAuthorizationAttempt.local()
        }
    }

    private class UidPort : UltraAllowlistPort {
        override val supportsUidProfiles = true
        var profiles: Map<Int, SuUidProfile>? = emptyMap()
        var identities: Map<Int, ApplicationIdentity> = emptyMap()
        var identityReadRevision = 4L
        var identityReadOk = true
        var uidReads = 0
        val writes = arrayListOf<SuUidProfile>()
        override fun beginIdentityRead(revision: Long) = identityReadOk && revision == identityReadRevision
        override fun uidProfiles(): Map<Int, SuUidProfile>? { uidReads++; return profiles }
        override fun identity(uid: Int) = identities[uid]
        override fun setAllowed(uid: Int, packageName: String, allowed: Boolean): UltraAuthorizationAttempt {
            val profile = SuUidProfile(uid, allowed, packageName)
            writes += profile
            profiles = profiles.orEmpty() + (uid to profile)
            return UltraAuthorizationAttempt.local().withReadback(true)
        }
        override fun packages(): Set<String>? = error("legacy package projection")
        override fun setAllowed(packageName: String, allowed: Boolean): UltraAuthorizationAttempt = error("legacy package write")
    }

    @Test fun grantAndRevokeFollowTheSameAuthorityRevision() {
        val port = Port().apply { identity = identity() }
        val mirror = UltraAllowlistMirror(port)
        assertTrue(mirror.apply(snapshot()).ok)
        assertEquals(setOf(pkg), port.packages)
        val revoked = AuthorizationSnapshot(true, emptyMap(), rev = 5,
            uidRev = mapOf(uid to 4L), tombs = listOf(SuperuserTomb(uid, pkg, 5, 1000)))
        assertTrue(mirror.apply(revoked).ok)
        assertEquals(emptySet<String>(), port.packages)
        assertEquals(listOf(pkg to true, pkg to false), port.writes)
    }

    @Test fun existingGrantRefreshesChangedUidWithoutRevoking() {
        val newUid = uid + 1
        val current = identity(identityUid = newUid)
        val port = Port().apply {
            identity = current
            packages = setOf(pkg)
            publishedUids[pkg] = uid
        }
        val authority = snapshot().copy(grants = mapOf(newUid to current), uidRev = mapOf(newUid to 4L))
        assertTrue(UltraAllowlistMirror(port).apply(authority).ok)
        assertEquals(listOf(pkg to true), port.writes)
        assertEquals(newUid, port.publishedUids[pkg])
    }

    @Test fun repeatedExplicitGrantRefreshesCurrentUid() {
        val port = Port().apply { identity = identity(); packages = setOf(pkg) }
        val mirror = UltraAllowlistMirror(port)
        repeat(2) { assertTrue(mirror.apply(snapshot()).ok) }
        assertEquals(listOf(pkg to true, pkg to true), port.writes)
        assertEquals(uid, port.publishedUids[pkg])
    }

    @Test fun revocationsPrecedeExistingGrantRefresh() {
        val revokedPackage = "com.example.revoked"
        val port = Port().apply {
            identity = identity()
            packages = setOf(pkg, revokedPackage)
            publishedUids[revokedPackage] = uid + 1
        }
        val authority = snapshot().copy(rev = 5,
            tombs = listOf(SuperuserTomb(uid + 1, revokedPackage, 5, 1000)))
        assertTrue(UltraAllowlistMirror(port).apply(authority).ok)
        assertEquals(listOf(revokedPackage to false, pkg to true), port.writes)
        assertEquals(mapOf(pkg to uid), port.publishedUids)
    }

    @Test fun existingGrantRefreshFailureRemainsUnconfirmed() {
        val oldUid = uid + 1
        val port = Port().apply {
            identity = identity()
            packages = setOf(pkg)
            publishedUids[pkg] = oldUid
            reject = true
        }
        assertTrue(UltraAllowlistMirror(port).apply(snapshot()).detail.startsWith("SDK_APPLY_FAILED:$pkg error=APPLY_REJECTED "))
        assertEquals(listOf(pkg to true), port.writes)
        assertEquals(oldUid, port.publishedUids[pkg])
    }

    @Test fun lostReadbackAfterExistingGrantRefreshRemainsUnconfirmed() {
        val delegate = Port().apply { identity = identity(); packages = setOf(pkg) }
        var reads = 0
        val port = object : UltraAllowlistPort by delegate {
            override fun packages(): Set<String>? = if (++reads == 1) delegate.packages() else null
        }
        assertTrue(UltraAllowlistMirror(port).apply(snapshot()).detail.startsWith("SDK_READBACK_UNREADABLE "))
        assertEquals(listOf(pkg to true), delegate.writes)
        assertEquals(uid, delegate.publishedUids[pkg])
        assertEquals(2, reads)
    }

    @Test fun staleCacheOrLostReadbackNeverConfirmsSynchronization() {
        val port = Port().apply { identity = identity(); packages = null }
        assertFalse(UltraAllowlistMirror(port).apply(snapshot()).ok)
        assertTrue(port.writes.isEmpty())
        port.packages = emptySet()
        port.reject = true
        assertFalse(UltraAllowlistMirror(port).apply(snapshot()).ok)
    }

    @Test fun disabledRevokedAndChangedIdentitiesNeverStayInTheSdkList() {
        for (state in listOf("disabled", "revoked", "identity")) {
            val port = Port().apply {
                identity = if (state == "identity") identity("/data/app/reinstalled/base.apk", installedAt = 1500L) else identity()
                packages = setOf(pkg, "dev.maplesu.manager")
            }
            val authority = when (state) {
                "disabled" -> snapshot(enabled = false)
                "revoked" -> snapshot().copy(tombs = listOf(SuperuserTomb(uid, pkg, 5, 1000)))
                else -> snapshot()
            }
            assertTrue(UltraAllowlistMirror(port).apply(authority).ok)
            assertEquals(setOf("dev.maplesu.manager"), port.packages)
            assertEquals(listOf(pkg to false), port.writes)
        }
    }

    @Test fun freshReadbackMustMatchEvenIfWriteReturnsTrue() {
        val delegate = Port().apply { identity = identity() }
        val port = object : UltraAllowlistPort by delegate {
            override fun setAllowed(packageName: String, allowed: Boolean) = UltraAuthorizationAttempt.local()
        }
        assertFalse(UltraAllowlistMirror(port).apply(snapshot()).ok)
    }

    @Test fun corruptAuthorityDoesNotMutateTheSdk() {
        val port = Port().apply { packages = setOf(pkg) }
        assertFalse(UltraAllowlistMirror(port).apply(AuthorizationSnapshot.unreadable()).ok)
        assertTrue(port.writes.isEmpty())
    }

    @Test fun packageGlobalAuthorizationRejectsMultipleUserMappings() {
        val delegate = Port().apply { identity = identity(); packages = setOf(pkg) }
        val port = object : UltraAllowlistPort by delegate {
            override fun uniquelyMapped(packageName: String, uid: Int) = false
        }
        assertTrue(UltraAllowlistMirror(port).apply(snapshot()).detail.startsWith("SDK_PACKAGE_GLOBAL_UID_AMBIGUOUS "))
        assertEquals(emptySet<String>(), delegate.packages)
    }

    @Test fun obsoleteIdentityCannotOverrideTheOneCurrentGrantForAPackage() {
        val oldUid = 10456
        val old = ApplicationIdentity(oldUid, pkg, listOf(pkg), setOf("a".repeat(64)),
            1000L, 2000L, "/data/app/obsolete/base.apk")
        val port = Port().apply { identity = identity() }
        val state = snapshot().copy(grants = linkedMapOf(uid to identity(), oldUid to old))
        assertTrue(UltraAllowlistMirror(port).apply(state).ok)
        assertEquals(setOf(pkg), port.packages)
    }

    @Test fun unexpectedExtraReadbackEntryIsNotACompleteMirror() {
        val delegate = Port().apply { identity = identity() }
        var reads = 0
        val port = object : UltraAllowlistPort by delegate {
            override fun packages(): Set<String>? {
                reads++
                return delegate.packages()?.let { if (reads == 1) it else it + "com.example.unexpected" }
            }
        }
        assertTrue(UltraAllowlistMirror(port).apply(snapshot()).detail.startsWith("SDK_READBACK_MISMATCH "))
    }

    @Test fun unreadableOrDifferentRevisionIdentityBatchDoesNotWriteTheSdk() {
        for (readable in listOf(false, true)) {
            val port = UidPort().apply {
                identityReadOk = readable
                identityReadRevision = 3
            }
            assertEquals("SDK_CURRENT_IDENTITY_UNREADABLE", UltraAllowlistMirror(port).apply(snapshot()).detail)
            assertTrue(port.writes.isEmpty())
            assertEquals(0, port.uidReads)
        }
    }

    @Test fun fullUidMirrorKeepsAnotherUsersGrantWhenOneInstallIdentityChanged() {
        val otherUid = 110123
        val primary = identity()
        val other = identity(identityUid = otherUid)
        val authority = snapshot().copy(grants = mapOf(uid to primary, otherUid to other),
            uidRev = mapOf(uid to 4L, otherUid to 4L))
        val port = UidPort().apply {
            identities = mapOf(uid to identity("/data/app/updated/base.apk").let {
                ApplicationIdentity(it.uid, it.packageName, listOf(it.packageName), setOf("b".repeat(64)),
                    it.firstInstallTime, it.lastUpdateTime, it.apkPath)
            }, otherUid to other)
            profiles = mapOf(uid to SuUidProfile(uid, true, pkg), otherUid to SuUidProfile(otherUid, true, pkg))
        }
        assertTrue(UltraAllowlistMirror(port).apply(authority).ok)
        assertEquals(listOf(SuUidProfile(uid, false, pkg), SuUidProfile(otherUid, true, pkg)), port.writes)
        assertEquals(false, port.profiles?.get(uid)?.allow)
        assertEquals(true, port.profiles?.get(otherUid)?.allow)
    }

    @Test fun absentCurrentIdentityRevokesTheRecordedUid() {
        val port = UidPort().apply { profiles = mapOf(uid to SuUidProfile(uid, true, pkg)) }
        assertTrue(UltraAllowlistMirror(port).apply(snapshot()).ok)
        assertEquals(listOf(SuUidProfile(uid, false, pkg)), port.writes)
    }

    @Test fun typedManagerGrantAlsoFollowsDisableAndRevocation() {
        val manager = ApplicationIdentity(uid, "dev.maplesu.manager", listOf("dev.maplesu.manager"),
            setOf("a".repeat(64)), 1000, 2000, "/data/app/manager/base.apk")
        val enabled = snapshot().copy(grants = mapOf(uid to manager))
        for (state in listOf(enabled.copy(enabled = false),
                enabled.copy(tombs = listOf(SuperuserTomb(uid, manager.packageName, 5, 3000))))) {
            val port = UidPort().apply {
                identities = mapOf(uid to manager)
                profiles = mapOf(uid to SuUidProfile(uid, true, manager.packageName))
            }
            assertTrue(UltraAllowlistMirror(port).apply(state).ok)
            assertEquals(listOf(SuUidProfile(uid, false, manager.packageName)), port.writes)
        }
    }

}
