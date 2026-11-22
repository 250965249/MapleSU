package dev.maplesu.manager.workmode.superuser

import dev.maplesu.manager.workmode.control.schema.AppliedMark
import dev.maplesu.manager.workmode.control.schema.GrantIntent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ApplyPlannerTest {
    private val identity = Fixtures.identity()
    private val packages = mapOf(Fixtures.UID to listOf(Fixtures.APP))

    private fun plan(
        shared: dev.maplesu.manager.workmode.control.schema.SharedSuperuserFile,
        target: BackendId = BackendId.A_DIRECT,
        packageMap: Map<Int, List<String>> = packages,
    ) = ApplyPlanner.plan(shared, target) { uid -> packageMap[uid].orEmpty() }

    @Test
    fun allowEntryBecomesGrant() {
        val planned = plan(Fixtures.shared(entries = listOf(Fixtures.intentFrom(identity))))
        assertEquals(1, planned.grants.size)
        assertEquals(0, planned.revokes.size)
        assertEquals(Fixtures.APP, planned.grants.single().packageName)
        assertTrue(planned.grants.single().allow)
    }

    @Test
    fun denyEntryBecomesRevoke() {
        val planned = plan(Fixtures.shared(entries = listOf(Fixtures.intentFrom(identity, GrantIntent.DENY))))
        assertEquals(1, planned.revokes.size)
        assertTrue(planned.revokes.single().packageName == Fixtures.APP)
        assertFalse(planned.revokes.single().allow)
    }

    @Test
    fun revokesComeBeforeGrantsInDesiredOrder() {
        val tomb = Fixtures.tomb(uid = Fixtures.UID + 10, packageName = Fixtures.OTHER,
            revokedAt = 2_000L, rev = 2)
        val shared = Fixtures.shared(
            entries = listOf(Fixtures.intentFrom(identity)),
            tombs = listOf(tomb),
        )
        val planned = plan(shared, BackendId.B_KSU, mapOf(
            Fixtures.UID to listOf(Fixtures.APP),
            Fixtures.UID + 10 to listOf(Fixtures.OTHER),
        ))
        assertEquals(1, planned.revokes.size)
        assertEquals(1, planned.grants.size)
        assertFalse(planned.desired.first().allow)
        assertTrue(planned.desired.last().allow)
    }

    @Test
    fun tombstoneBelowWatermarkReplaysRevoke() {
        val entry = Fixtures.intentFrom(identity).copy(
            decidedAt = 1_000L,
            applied = listOf(AppliedMark("A_DIRECT", 1, 1_000, true)),
        )
        val shared = Fixtures.shared(entries = listOf(entry), tombs = listOf(Fixtures.tomb(revokedAt = 2_000L)))
        val planned = plan(shared)
        assertEquals(1, planned.revokes.size)
        assertEquals(0, planned.grants.size)
    }

    @Test
    fun newerAllowDecisionSkipsTombstoneReplay() {
        val entry = Fixtures.intentFrom(identity).copy(decidedAt = 3_000L)
        val shared = Fixtures.shared(entries = listOf(entry), tombs = listOf(Fixtures.tomb(revokedAt = 2_000L)))
        val planned = plan(shared)
        assertEquals(0, planned.revokes.size)
        assertEquals(1, planned.grants.size)
    }

    @Test
    fun identityStaleIsSkippedForGrant() {
        val entry = Fixtures.intentFrom(identity).copy(identityStale = true)
        val planned = plan(Fixtures.shared(entries = listOf(entry)))
        assertEquals(1, planned.skippedIdentityStale)
        assertTrue(planned.grants.isEmpty())
        assertTrue(planned.revokes.isEmpty())
    }

    @Test
    fun rotatedSoftIsNotAutoGrantedOnLiteBackends() {
        val entry = Fixtures.intentFrom(identity).copy(degraded = listOf(GrantMerge.ROTATED_MARKER))
        val shared = Fixtures.shared(entries = listOf(entry))
        assertEquals(1, plan(shared, BackendId.A_DIRECT).skippedIdentityStale)
        assertEquals(1, plan(shared, BackendId.A_ULTRA, mapOf(Fixtures.UID to listOf(Fixtures.APP))).skippedIdentityStale)
        // B_KSU 可按当前包/uid 兑现，不因 A 侧待确认而拒绝。
        val bKsu = plan(shared, BackendId.B_KSU)
        assertEquals(1, bKsu.grants.size)
    }

    @Test
    fun aUltraAllOrNoneIsRecordedInDegraded() {
        val shared = Fixtures.shared(entries = listOf(Fixtures.intentFrom(identity)))
        val planned = plan(shared, BackendId.A_ULTRA, mapOf(Fixtures.UID to listOf(Fixtures.APP, Fixtures.OTHER)))
        assertTrue(planned.degraded.contains(IdentityRules.ALL_OR_NONE_MARKER))
        assertEquals(2, planned.revokes.size)
        assertTrue(planned.grants.isEmpty())
        assertEquals(setOf(Fixtures.APP, Fixtures.OTHER), planned.revokes.map { it.packageName }.toSet())
    }

    @Test
    fun protectedIdentitiesNeverPlanned() {
        val root = Fixtures.intent(uid = 0, userId = 0, packageName = "root", decision = GrantIntent.DENY)
        val manager = Fixtures.intent(
            uid = 10_100, userId = 0, packageName = Fixtures.MANAGER, decision = GrantIntent.DENY,
        )
        val shared = Fixtures.shared(entries = listOf(root, manager))
        val planned = plan(shared, BackendId.B_KSU)
        assertTrue(planned.revokes.isEmpty())
        assertTrue(planned.grants.isEmpty())
    }

    @Test
    fun multiPackageUidDenyRevokesEveryPackageForAPro() {
        val other = Fixtures.intent(
            uid = Fixtures.UID, userId = 0, packageName = Fixtures.OTHER, decision = GrantIntent.DENY,
        )
        val shared = Fixtures.shared(entries = listOf(Fixtures.intentFrom(identity), other))
        val planned = plan(shared, BackendId.A_ULTRA, mapOf(Fixtures.UID to listOf(Fixtures.APP, Fixtures.OTHER)))
        assertEquals(2, planned.revokes.size)
        assertTrue(planned.grants.isEmpty())
    }
}
