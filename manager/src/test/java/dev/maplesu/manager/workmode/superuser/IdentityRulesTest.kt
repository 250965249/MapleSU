package dev.maplesu.manager.workmode.superuser

import dev.maplesu.manager.workmode.control.schema.GrantIntent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IdentityRulesTest {
    private val identity = Fixtures.identity()
    private val intent = Fixtures.intentFrom(identity)

    @Test
    fun matchExact() {
        assertEquals(IdentityVerdict.MATCH, IdentityRules.verdict(intent, identity))
    }

    @Test
    fun nullIdentityIsUnknown() {
        assertEquals(IdentityVerdict.UNKNOWN, IdentityRules.verdict(intent, null))
    }

    @Test
    fun updateTimeOnlyIsRotatedSoft() {
        val upgraded = identity.copy(lastUpdateTime = identity.lastUpdateTime + 1)
        assertEquals(IdentityVerdict.ROTATED_SOFT, IdentityRules.verdict(intent, upgraded))
    }

    @Test
    fun apkPathChangeIsRotatedSoft() {
        val moved = identity.copy(apkPathHash = IdentityRules.apkPathHash("/data/app/${Fixtures.APP}-1/base.apk"))
        assertEquals(IdentityVerdict.ROTATED_SOFT, IdentityRules.verdict(intent, moved))
    }

    @Test
    fun signerChangeIsStaleHard() {
        val resigned = identity.copy(signerSha256 = listOf(Fixtures.hash('e')))
        assertEquals(IdentityVerdict.STALE_HARD, IdentityRules.verdict(intent, resigned))
    }

    @Test
    fun packageRenameIsStaleHard() {
        val renamed = identity.copy(packageName = Fixtures.OTHER)
        assertEquals(IdentityVerdict.STALE_HARD, IdentityRules.verdict(intent, renamed))
    }

    @Test
    fun uidChangeIsStaleHard() {
        val reassigned = identity.copy(uid = Fixtures.UID + 1)
        assertEquals(IdentityVerdict.STALE_HARD, IdentityRules.verdict(intent, reassigned))
    }

    @Test
    fun reinstallIsStaleHard() {
        val reinstalled = identity.copy(firstInstallTime = identity.firstInstallTime + 1)
        assertEquals(IdentityVerdict.STALE_HARD, IdentityRules.verdict(intent, reinstalled))
    }

    @Test
    fun signerOrderDoesNotMatter() {
        val reordered = identity.copy(signerSha256 = identity.signerSha256.reversed())
        assertEquals(IdentityVerdict.MATCH, IdentityRules.verdict(intent, reordered))
    }

    @Test
    fun apkPathHashIs32CharsAndPathNotStored() {
        val hash = IdentityRules.apkPathHash("/data/app/x.apk")
        assertEquals(32, hash.length)
        assertTrue(hash.matches(Regex("[0-9a-f]{32}")))
        assertTrue(!hash.contains("/data"))
    }

    // ------------------------------------------------------------------ granularity / expansion

    @Test
    fun sharedUidIsRejectedForADirect() {
        assertNull(IdentityRules.expand(intent, BackendId.A_DIRECT, listOf(Fixtures.APP, Fixtures.OTHER)))
        // 恰好一个包才可表达。
        val expanded = IdentityRules.expand(intent, BackendId.A_DIRECT, listOf(Fixtures.APP))
        assertEquals(true, expanded?.allow)
        assertEquals(BackendId.A_DIRECT, expanded?.target)
    }

    @Test
    fun aUltraAllOrNoneWhenOnlyOnePackageAllowed() {
        // 只授权 APP；同 uid 的 OTHER 没有 allow 意图 → 该 uid 整体不 allow（all-or-none）。
        val expanded = IdentityRules.expandAll(listOf(intent), BackendId.A_ULTRA,
            mapOf(Fixtures.UID to listOf(Fixtures.APP, Fixtures.OTHER)))
        assertEquals(2, expanded.size)
        assertTrue(expanded.all { !it.allow })
        assertTrue(expanded.all { it.degraded == IdentityRules.ALL_OR_NONE_MARKER })
    }

    @Test
    fun aUltraAllowsWholeUidWhenEveryPackageAllowed() {
        val entries = listOf(intent, Fixtures.intent(packageName = Fixtures.OTHER, uid = Fixtures.UID))
        val expanded = IdentityRules.expandAll(entries, BackendId.A_ULTRA,
            mapOf(Fixtures.UID to listOf(Fixtures.APP, Fixtures.OTHER)))
        assertTrue(expanded.all { it.allow })
        assertTrue(expanded.all { it.degraded == IdentityRules.MULTI_PACKAGE_UID_MARKER })
    }

    @Test
    fun aUltraDenyRevokesWholeUid() {
        val entries = listOf(
            intent,
            Fixtures.intent(packageName = Fixtures.OTHER, uid = Fixtures.UID, decision = GrantIntent.DENY),
        )
        val expanded = IdentityRules.expandAll(entries, BackendId.A_ULTRA,
            mapOf(Fixtures.UID to listOf(Fixtures.APP, Fixtures.OTHER)))
        assertTrue(expanded.all { !it.allow })
    }

    @Test
    fun multiUserEntriesAreSeparated() {
        val user0 = Fixtures.intent(uid = Fixtures.UID, userId = 0)
        val user10 = Fixtures.intent(uid = Fixtures.UID_OTHER_USER, userId = 10)
        val expanded = IdentityRules.expandAll(listOf(user0, user10), BackendId.B_KSU, emptyMap())
        assertEquals(2, expanded.size)
        assertEquals(setOf(Fixtures.UID, Fixtures.UID_OTHER_USER), expanded.map { it.uid }.toSet())
        assertEquals(setOf(0, 10), expanded.map { it.uid / 100_000 }.toSet())
    }

    @Test
    fun protectedIdentitiesAreNeverExpanded() {
        assertNull(IdentityRules.expand(
            Fixtures.intent(uid = 0, userId = 0, packageName = "root"), BackendId.B_KSU, emptyList()))
        assertNull(IdentityRules.expand(
            Fixtures.intent(uid = 10_000, userId = 0, packageName = "android"), BackendId.A_ULTRA, emptyList()))
        assertNull(IdentityRules.expand(
            Fixtures.intent(uid = 10_100, userId = 0, packageName = Fixtures.MANAGER), BackendId.A_DIRECT, emptyList()))
        // 普通应用不受影响。
        assertTrue(IdentityRules.expand(intent, BackendId.B_KSU, emptyList()) != null)
    }

    @Test
    fun bKsuSkipsGrantForUninstalledPackage() {
        assertNull(IdentityRules.expand(intent, BackendId.B_KSU, listOf(Fixtures.OTHER)))
        // deny 仍可撤回（安全方向）。
        val deny = Fixtures.intentFrom(identity, GrantIntent.DENY)
        val expanded = IdentityRules.expand(deny, BackendId.B_KSU, listOf(Fixtures.OTHER))
        assertEquals(false, expanded?.allow)
    }

    @Test
    fun userIdIsDerivedFromFullUid() {
        assertEquals(0, IdentityRules.userIdOf(10_200))
        assertEquals(10, IdentityRules.userIdOf(1_010_200))
        assertEquals(10, identity.copy(uid = 1_010_200).userId)
    }
}
