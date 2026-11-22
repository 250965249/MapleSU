package dev.maplesu.manager.runtime.authorization

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.TreeSet

/**
 * Host regression for the one decision function (design §1.2 / §7.3 item 4).
 *
 * <p>Everything here is a refusal test except the allow case: default deny, revoke,
 * identity change, master switch, multi-package uid and cross-user must all produce the
 * same named code the endpoints return, because the endpoints now call this function and
 * do not re-implement any of these rules.
 */
class ManagerSuperuserPolicyTest {
    private val uid = 10_123
    private val other = 10_456

    private fun identity(
        uid: Int = this.uid,
        packageName: String = "com.example.su",
        signers: Set<String> = setOf("a".repeat(64)),
        firstInstall: Long = 1_000,
        lastUpdate: Long = 2_000,
        apkPath: String = "/data/app/com.example.su/base.apk",
    ) = ApplicationIdentity(
        uid, packageName, listOf(packageName), TreeSet(signers), firstInstall, lastUpdate, apkPath,
    )

    private fun snapshot(
        enabled: Boolean = true,
        grants: Map<Int, ApplicationIdentity> = mapOf(uid to identity()),
        rev: Long = 10,
        uidRev: Map<Int, Long> = mapOf(uid to 10L),
        tombs: List<SuperuserTomb> = emptyList(),
        corrupt: Boolean = false,
    ) = AuthorizationSnapshot(enabled, grants, rev, uidRev, tombs, corrupt = corrupt)

    @Test
    fun successfulLatestMirrorClearsAnOlderPendingWatermark() {
        val earlier = SuperuserApplied("ULTRA_ALLOWLIST", 3, 1000, false)
        val applied = SuperuserApplied("ULTRA_ALLOWLIST", 4, 2000, true)
        assertFalse(snapshot().copy(rev = 4, applied = listOf(earlier, applied)).pendingApply())
        assertTrue(snapshot().copy(rev = 5, applied = listOf(earlier, applied)).pendingApply())
        assertFalse(snapshot().copy(rev = 4, applied = listOf(applied, earlier)).pendingApply())
        assertTrue(snapshot().copy(applied = listOf(earlier, applied,
            SuperuserApplied("KSU_ALLOWLIST", 4, 2000, false))).pendingApply())
    }

    @Test
    fun changingMirrorBackendRetiresItsOldPendingWatermark() {
        val old = SuperuserApplied("KSU_ALLOWLIST", 3, 3000, false)
        val current = SuperuserApplied("ULTRA_ALLOWLIST", 4, 1000, true)
        assertFalse(snapshot().copy(rev = 4, applied = listOf(old, current)).pendingApply())
        assertFalse(snapshot().copy(rev = 4, applied = listOf(current, old)).pendingApply())
        assertTrue(snapshot().copy(rev = 5, applied = listOf(old, current)).pendingApply())
        val staleWrite = SuperuserApplied("ULTRA_ALLOWLIST", 4, 500, false)
        assertTrue(snapshot().copy(rev = 4, applied = listOf(current, staleWrite)).pendingApply())
        assertEquals(staleWrite, snapshot().copy(applied = listOf(current, staleWrite)).appliedOf("ULTRA_ALLOWLIST"))
    }

    @Test
    fun allowsOnlyTheExactRecordedInstallation() {
        val decision = ManagerSuperuserPolicy.decide(snapshot(), uid, identity())
        assertTrue(decision.allowed)
        assertEquals(SuCodes.ALLOW, decision.reason)
        assertEquals(10L, decision.rev)
        assertEquals(identity(), decision.grant)
    }

    @Test
    fun defaultDenyWithoutARecord() {
        val decision = ManagerSuperuserPolicy.decide(snapshot(grants = emptyMap()), uid, identity())
        assertFalse(decision.allowed)
        assertEquals(SuCodes.AUTH_NOT_GRANTED, decision.reason)
    }

    @Test
    fun masterSwitchOffIsItsOwnCode() {
        val decision = ManagerSuperuserPolicy.decide(snapshot(enabled = false), uid, identity())
        assertFalse(decision.allowed)
        assertEquals(SuCodes.AUTH_DISABLED, decision.reason)
    }

    @Test
    fun revokeIsNeverResurrectedByAStaleRecord() {
        // A revoke at rev 11, then a store record that survived the crash (uidRev 10).
        val revived = snapshot(
            rev = 11,
            tombs = listOf(SuperuserTomb(uid, "com.example.su", 11, 5_000)),
        )
        val decision = ManagerSuperuserPolicy.decide(revived, uid, identity())
        assertFalse(decision.allowed)
        assertEquals(SuCodes.AUTH_NOT_GRANTED, decision.reason)
    }

    @Test
    fun aLaterGrantSupersedesTheTombstone() {
        val regranted = snapshot(
            rev = 12,
            uidRev = mapOf(uid to 12L),
            tombs = listOf(SuperuserTomb(uid, "com.example.su", 11, 5_000)),
        )
        assertTrue(ManagerSuperuserPolicy.decide(regranted, uid, identity()).allowed)
    }

    @Test
    fun identityIsCheckedFieldByField() {
        val changedSigner = identity(signers = setOf("b".repeat(64)))
        val changedUpdate = identity(lastUpdate = 3_000)
        val changedApk = identity(apkPath = "/data/app/com.example.su/other.apk")
        val changedInstall = identity(firstInstall = 999)
        for (candidate in listOf(changedSigner, changedUpdate, changedApk, changedInstall)) {
            val decision = ManagerSuperuserPolicy.decide(snapshot(), uid, candidate)
            assertFalse("accepted $candidate", decision.allowed)
            assertEquals(SuCodes.AUTH_IDENTITY_CHANGED, decision.reason)
        }
    }

    @Test
    fun absentIdentityIsAChangedIdentityCode() {
        val decision = ManagerSuperuserPolicy.decide(snapshot(), uid, null)
        assertFalse(decision.allowed)
        assertEquals(SuCodes.AUTH_IDENTITY_CHANGED, decision.reason)
    }

    @Test
    fun crossUserRecordIsNotAccepted() {
        // A record under user 0's uid must not admit the same app under user 10.
        val otherUser = 1_010_123
        val decision = ManagerSuperuserPolicy.decide(
            snapshot(grants = mapOf(uid to identity()), uidRev = mapOf(uid to 10L)),
            otherUser,
            identity(uid = otherUser),
        )
        assertFalse(decision.allowed)
        assertEquals(SuCodes.AUTH_NOT_GRANTED, decision.reason)
    }

    @Test
    fun multiPackageUidIsAmbiguousNotPartiallyGranted() {
        val decision = ManagerSuperuserPolicy.decide(
            snapshot(), uid, identity(), listOf("com.example.su", "com.example.two"),
        )
        assertFalse(decision.allowed)
        assertEquals(SuCodes.SU_CALLER_PACKAGE_AMBIGUOUS, decision.reason)
    }

    @Test
    fun uidWithoutAPackageIsUnavailable() {
        val decision = ManagerSuperuserPolicy.decide(snapshot(), uid, null, emptyList())
        assertFalse(decision.allowed)
        assertEquals(SuCodes.SU_CALLER_PACKAGE_UNAVAILABLE, decision.reason)
    }

    @Test
    fun uidZeroIsOutsideTheCallerDomain() {
        val decision = ManagerSuperuserPolicy.decide(snapshot(), 0, null, null)
        assertFalse(decision.allowed)
        assertEquals(SuCodes.SU_CALLER_IDENTITY_UNAVAILABLE, decision.reason)
    }

    @Test
    fun corruptStoreDeniesEverythingEvenWhenItClaimsToBeEnabled() {
        val decision = ManagerSuperuserPolicy.decide(snapshot(corrupt = true), uid, identity())
        assertFalse(decision.allowed)
        assertEquals(SuCodes.AUTH_NOT_GRANTED, decision.reason)
    }

    @Test
    fun managementFastPathStillHonoursTheSwitch() {
        assertTrue(ManagerSuperuserPolicy.decideSelf(snapshot()).allowed)
        val off = ManagerSuperuserPolicy.decideSelf(snapshot(enabled = false))
        assertFalse(off.allowed)
        assertEquals(SuCodes.AUTH_DISABLED, off.reason)
    }

    @Test(expected = SecurityException::class)
    fun requireThrowsTheSameCodeTheEndpointsReturn() {
        ManagerSuperuserPolicy.require(snapshot(grants = emptyMap()), uid, identity())
    }
}
