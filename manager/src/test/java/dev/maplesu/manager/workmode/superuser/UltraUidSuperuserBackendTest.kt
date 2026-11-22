package dev.maplesu.manager.workmode.superuser

import dev.maplesu.manager.runtime.ultra.SuUidProfile
import org.junit.Assert.*
import org.junit.Test

class UltraUidSuperuserBackendTest {
    private class Port : UltraSuperuserPort {
        override val supportsUidProfiles = true
        var profiles: Map<Int, SuUidProfile>? = emptyMap()
        var applyWrite = true
        var writeOk = true
        val writes = arrayListOf<SuUidProfile>()
        override fun isActive() = true
        override fun uidProfiles() = profiles
        override fun setUidAllowed(uid: Int, packageName: String, allowed: Boolean): Boolean {
            val profile = SuUidProfile(uid, allowed, packageName)
            writes += profile
            if (applyWrite && writeOk) profiles = profiles.orEmpty() + (uid to profile)
            return writeOk
        }
        override fun grantedPackages(): Set<String> = error("legacy package projection")
        override fun isGranted(packageName: String): Boolean = error("cached grant bit")
        override fun uidForPackage(packageName: String): Int? = error("current-user UID projection")
        override fun packagesForUid(uid: Int) = listOf("example.app")
        override fun identity(packageName: String, uid: Int) = IdentitySnapshot(uid, packageName,
            listOf("a".repeat(64)), 1, 2, "b".repeat(32))
        override fun grant(packageName: String): Boolean = error("legacy grant")
        override fun revoke(packageName: String): Boolean = error("legacy revoke")
    }

    private fun view(uid: Int, allow: Boolean = true) =
        GrantView(uid, "example.app", allow, Granularity.UID_PACKAGE_PROFILE, null)

    @Test fun samePackageInTwoUsersIsEnumeratedByFullUid() {
        val port = Port().apply { profiles = mapOf(
            10123 to SuUidProfile(10123, true, "example.app"),
            110123 to SuUidProfile(110123, true, "example.app")) }
        val views = UltraSuperuserBackend(port).enumerate()
        assertEquals(listOf(10123, 110123), views.map { it.uid })
    }

    @Test fun cachedGrantNeverSkipsIdentityAndDeliverySynchronization() {
        val port = Port().apply { profiles = mapOf(110123 to SuUidProfile(110123, true, "example.app")) }
        assertTrue(UltraSuperuserBackend(port).apply(listOf(view(110123)), emptyList(), 2).succeeded)
        assertEquals(listOf(SuUidProfile(110123, true, "example.app")), port.writes)
    }

    @Test fun acknowledgedWriteWithoutFreshMatchingReadbackFails() {
        val port = Port().apply { applyWrite = false }
        val report = UltraSuperuserBackend(port).apply(listOf(view(110123)), emptyList(), 2)
        assertEquals("A_ULTRA_UID_READBACK_MISMATCH", report.failed.single().code)
        assertEquals(110123, report.failed.single().uid)
    }

    @Test fun revokeOfOtherUserPreservesFirstUsersGrant() {
        val port = Port().apply { profiles = mapOf(
            10123 to SuUidProfile(10123, true, "example.app"),
            110123 to SuUidProfile(110123, true, "example.app")) }
        assertTrue(UltraSuperuserBackend(port).apply(listOf(view(110123, false)), emptyList(), 3).succeeded)
        assertEquals(true, port.profiles?.get(10123)?.allow)
        assertEquals(false, port.profiles?.get(110123)?.allow)
    }

    @Test fun unreadableUidStateDoesNotAcknowledgeOrWriteGrant() {
        val port = Port().apply { profiles = null }
        val report = UltraSuperuserBackend(port).apply(listOf(view(110123)), emptyList(), 4)
        assertEquals("A_ULTRA_UID_READ_FAILED", report.failed.single().code)
        assertTrue(port.writes.isEmpty())
    }

    @Test fun failedRevocationRemainsDangerousDespiteReadback() {
        val port = Port().apply {
            profiles = mapOf(110123 to SuUidProfile(110123, false, "example.app"))
            writeOk = false
        }
        val report = UltraSuperuserBackend(port).apply(listOf(view(110123, false)), emptyList(), 5)
        assertTrue(report.failed.single().dangerous)
        assertEquals("A_ULTRA_REVOKE_FAILED", report.failed.single().code)
    }
}
