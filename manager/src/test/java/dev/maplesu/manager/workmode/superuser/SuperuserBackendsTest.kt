package dev.maplesu.manager.workmode.superuser

import dev.maplesu.manager.workmode.control.schema.Tomb
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException

class SuperuserBackendsTest {
    private val identity = Fixtures.identity()

    private class FakeDirectPort : DirectSuperuserPort {
        var enabled: Boolean = true
        var grantResult: Boolean = true
        var revokeResult: Boolean = true
        val granted = linkedSetOf<Int>()
        val current = mutableMapOf<Int, Boolean>()
        val identities = mutableMapOf<Int, IdentitySnapshot>()
        val grantCalls = mutableListOf<Int>()
        val revokeCalls = mutableListOf<Int>()

        override fun enabled() = enabled
        override fun grantedUids() = granted.toSet()
        override fun hasCurrentGrant(uid: Int): Boolean? = current[uid]
        override fun identity(uid: Int): IdentitySnapshot? = identities[uid]
        override fun grant(uid: Int): Boolean {
            grantCalls.add(uid)
            if (grantResult) granted.add(uid)
            return grantResult
        }
        override fun revoke(uid: Int): Boolean {
            revokeCalls.add(uid)
            if (revokeResult) granted.remove(uid)
            return revokeResult
        }
    }

    private class FakeUltraPort : UltraSuperuserPort {
        var active: Boolean = true
        var grantResult: Boolean = true
        var revokeResult: Boolean = true
        val granted = linkedSetOf<String>()
        val uids = mutableMapOf<String, Int>()
        val identities = mutableMapOf<String, IdentitySnapshot>()
        val packagesByUid = mutableMapOf<Int, List<String>>()
        val grantCalls = mutableListOf<String>()
        val revokeCalls = mutableListOf<String>()

        override fun isActive() = active
        override fun grantedPackages() = granted.toSet()
        override fun isGranted(packageName: String) = granted.contains(packageName)
        override fun uidForPackage(packageName: String): Int? = uids[packageName]
        override fun identity(packageName: String, uid: Int) = identities[packageName]
        override fun packagesForUid(uid: Int) = packagesByUid[uid].orEmpty()
        override fun grant(packageName: String): Boolean {
            grantCalls.add(packageName)
            if (grantResult) granted.add(packageName)
            return grantResult
        }
        override fun revoke(packageName: String): Boolean {
            revokeCalls.add(packageName)
            if (revokeResult) granted.remove(packageName)
            return revokeResult
        }
    }

    private class FakeKsuPort : KsuSuperuserPort {
        var available: Boolean = true
        var countValue: Int = 0
        var setResult: Boolean = true
        val installed = mutableListOf<KsuInstalledApp>()
        val allowed = linkedSetOf<Pair<String, Int>>()
        val setCalls = mutableListOf<Triple<String, Int, Boolean>>()

        override fun available() = available
        override fun count() = countValue
        override fun allow(packageName: String, uid: Int): Boolean? =
            if (available) allowed.contains(packageName to uid) else null
        override fun setAllow(packageName: String, uid: Int, allow: Boolean): Boolean {
            setCalls.add(Triple(packageName, uid, allow))
            if (setResult) {
                if (allow) allowed.add(packageName to uid) else allowed.remove(packageName to uid)
            }
            return setResult
        }
        override fun installedApplications() = installed.toList()
        override fun identity(packageName: String, uid: Int): IdentitySnapshot? =
            installed.firstOrNull { it.packageName == packageName && it.uid == uid }?.identity
        override fun packagesForUid(uid: Int) = installed.filter { it.uid == uid }.map { it.packageName }
    }

    // ------------------------------------------------------------------ A_DIRECT

    @Test
    fun directEnumerateUsesCurrentIdentity() {
        val port = FakeDirectPort().apply {
            granted.addAll(listOf(Fixtures.UID, Fixtures.UID + 100))
            current[Fixtures.UID] = true
            current[Fixtures.UID + 100] = false
            identities[Fixtures.UID] = identity
            identities[Fixtures.UID + 100] = identity.copy(uid = Fixtures.UID + 100)
        }
        val views = DirectSuperuserBackend(port).enumerate()
        assertEquals(listOf(Fixtures.UID), views.map { it.uid })
        assertEquals(Granularity.UID, views.single().granularity)
    }

    @Test
    fun directEnumerateFailsClosedWhenIdentityUndecidable() {
        val port = FakeDirectPort().apply { granted.add(Fixtures.UID) }
        try {
            DirectSuperuserBackend(port).enumerate()
            fail("undecidable identity accepted")
        } catch (expected: IOException) {
            assertTrue(expected.message.orEmpty().contains("A_DIRECT_IDENTITY_CHECK_FAILED"))
        }
    }

    @Test
    fun directApplyIsIdempotentDiff() {
        val port = FakeDirectPort().apply {
            granted.add(Fixtures.UID)
            current[Fixtures.UID] = true
            identities[Fixtures.UID] = identity
        }
        val backend = DirectSuperuserBackend(port)
        val report = backend.apply(
            desired = listOf(Fixtures.view(uid = Fixtures.UID, granularity = Granularity.UID)),
            tombs = emptyList(),
            rev = 1,
        )
        assertTrue(report.succeeded)
        assertTrue(port.grantCalls.isEmpty())
    }

    @Test
    fun directRevokeFailureIsDangerous() {
        val port = FakeDirectPort().apply {
            granted.add(Fixtures.UID)
            current[Fixtures.UID] = true
            identities[Fixtures.UID] = identity
            revokeResult = false
        }
        val report = DirectSuperuserBackend(port).apply(
            desired = listOf(Fixtures.view(uid = Fixtures.UID, allow = false, granularity = Granularity.UID)),
            tombs = emptyList(), rev = 1,
        )
        assertEquals(1, report.failed.size)
        assertTrue(report.failed.single().dangerous)
        assertEquals("A_DIRECT_REVOKE_FAILED", report.failed.single().code)
    }

    @Test
    fun directUnavailableRejects() {
        val port = FakeDirectPort().apply { enabled = false }
        val report = DirectSuperuserBackend(port).apply(
            desired = listOf(Fixtures.view()), tombs = emptyList(), rev = 1,
        )
        assertEquals("A_DIRECT_UNAVAILABLE", report.failed.single().code)
        assertTrue(DirectSuperuserBackend(port).enumerate().isEmpty())
    }

    @Test
    fun directSkipsProtectedUids() {
        val port = FakeDirectPort().apply {
            granted.addAll(listOf(0, 1000))
            identities[0] = identity.copy(uid = 0, packageName = "root")
        }
        assertTrue(DirectSuperuserBackend(port).enumerate().isEmpty())
        val report = DirectSuperuserBackend(port).apply(
            desired = listOf(Fixtures.view(uid = 0, allow = true)), tombs = emptyList(), rev = 1,
        )
        assertTrue(report.succeeded)
        assertTrue(port.grantCalls.isEmpty())
    }

    // ------------------------------------------------------------------ A_ULTRA

    @Test
    fun ultraEnumerateBuildsPackageViews() {
        val port = FakeUltraPort().apply {
            granted.add(Fixtures.APP)
            uids[Fixtures.APP] = Fixtures.UID
            identities[Fixtures.APP] = identity
        }
        val views = UltraSuperuserBackend(port).enumerate()
        assertEquals(1, views.size)
        assertEquals(Granularity.PACKAGE, views.single().granularity)
        assertEquals(Fixtures.APP, views.single().packageName)
    }

    @Test
    fun ultraApplyIsIdempotentAndRevokes() {
        val port = FakeUltraPort().apply {
            granted.add(Fixtures.APP)
            uids[Fixtures.APP] = Fixtures.UID
            identities[Fixtures.APP] = identity
        }
        val backend = UltraSuperuserBackend(port)
        assertTrue(backend.apply(listOf(Fixtures.view(allow = true, granularity = Granularity.PACKAGE)),
            emptyList(), 1).succeeded)
        assertTrue(port.grantCalls.isEmpty())
        assertTrue(backend.apply(listOf(Fixtures.view(allow = false, granularity = Granularity.PACKAGE)),
            emptyList(), 2).succeeded)
        assertEquals(listOf(Fixtures.APP), port.revokeCalls)
    }

    @Test
    fun ultraRevokeFailureReported() {
        val port = FakeUltraPort().apply {
            granted.add(Fixtures.APP)
            uids[Fixtures.APP] = Fixtures.UID
            identities[Fixtures.APP] = identity
            revokeResult = false
        }
        val report = UltraSuperuserBackend(port).apply(
            listOf(Fixtures.view(allow = false, granularity = Granularity.PACKAGE)), emptyList(), 1,
        )
        assertEquals("A_ULTRA_REVOKE_FAILED", report.failed.single().code)
        assertTrue(report.failed.single().dangerous)
    }

    @Test
    fun ultraUnavailableRejects() {
        val port = FakeUltraPort().apply { active = false }
        val report = UltraSuperuserBackend(port).apply(listOf(Fixtures.view()), emptyList(), 1)
        assertEquals("A_ULTRA_UNAVAILABLE", report.failed.single().code)
    }

    // ------------------------------------------------------------------ B_KSU

    private fun ksuPort(): FakeKsuPort = FakeKsuPort().apply {
        countValue = 5
        installed.add(KsuInstalledApp(Fixtures.APP, Fixtures.UID, identity))
        installed.add(KsuInstalledApp(Fixtures.OTHER, Fixtures.UID + 1,
            identity.copy(uid = Fixtures.UID + 1, packageName = Fixtures.OTHER)))
        installed.add(KsuInstalledApp(Fixtures.MANAGER, 10_100,
            identity.copy(uid = 10_100, packageName = Fixtures.MANAGER)))
    }

    @Test
    fun ksuEnumerateUsesPerPackageProfilesAndCountsUnrepresentable() {
        val port = ksuPort().apply { allowed.add(Fixtures.APP to Fixtures.UID) }
        val backend = KsuSuperuserBackend(port)
        val views = backend.enumerate()
        assertEquals(1, views.size)
        assertEquals(Fixtures.APP, views.single().packageName)
        assertEquals(Granularity.UID_PACKAGE_PROFILE, views.single().granularity)
        // count=5，可枚举 1（管理器 uid 被保护跳过）→ 4 条无法表达。
        assertEquals(4, backend.unrepresentableCount())
    }

    @Test
    fun ksuUnavailableRejectsAndDoesNotWrite() {
        val port = ksuPort().apply { available = false }
        val backend = KsuSuperuserBackend(port)
        assertTrue(backend.enumerate().isEmpty())
        val report = backend.apply(listOf(Fixtures.view()), emptyList(), 1)
        assertTrue(report.failed.all { it.code == "KSU_UNAVAILABLE" })
        assertTrue(port.setCalls.isEmpty())
    }

    @Test
    fun ksuApplyOnlyTouchesAllowFlag() {
        val port = ksuPort()
        val backend = KsuSuperuserBackend(port)
        val report = backend.apply(
            listOf(Fixtures.view(uid = Fixtures.UID, packageName = Fixtures.APP, allow = true)),
            emptyList(), 1,
        )
        assertTrue(report.succeeded)
        assertEquals(listOf(Triple(Fixtures.APP, Fixtures.UID, true)), port.setCalls)
    }

    @Test
    fun ksuRevokeFailureReported() {
        val port = ksuPort().apply {
            allowed.add(Fixtures.APP to Fixtures.UID)
            setResult = false
        }
        val report = KsuSuperuserBackend(port).apply(
            listOf(Fixtures.view(uid = Fixtures.UID, packageName = Fixtures.APP, allow = false)),
            emptyList(), 1,
        )
        assertEquals("KSU_APPLY_REJECTED", report.failed.single().code)
        assertTrue(report.failed.single().dangerous)
    }

    @Test
    fun ksuSkipsProtectedManagerPackage() {
        val port = ksuPort()
        val report = KsuSuperuserBackend(port).apply(
            listOf(Fixtures.view(uid = 10_100, packageName = Fixtures.MANAGER, allow = false)),
            listOf(Tomb(10_100, 0, Fixtures.MANAGER, listOf(Fixtures.hash('a')), 2_000L, 2)),
            1,
        )
        assertTrue(report.succeeded)
        assertTrue(port.setCalls.isEmpty())
    }

    @Test
    fun unavailableKsuPortIsSafe() {
        val backend = KsuSuperuserBackend(UnavailableKsuSuperuserPort("not wired"))
        assertFalse(backend.available())
        assertTrue(backend.enumerate().isEmpty())
        assertNull(KsuSuperuserBackend(UnavailableKsuSuperuserPort("x")).verify().firstOrNull())
        assertEquals("KSU_UNAVAILABLE",
            backend.apply(listOf(Fixtures.view()), emptyList(), 1).failed.single().code)
    }
}
