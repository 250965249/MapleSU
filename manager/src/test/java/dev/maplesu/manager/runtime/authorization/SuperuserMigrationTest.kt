package dev.maplesu.manager.runtime.authorization

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.TreeSet

/**
 * Host regression for the one-shot legacy import (design §3.1).
 *
 * <p>Two properties matter: the import is **idempotent** (the journal's `migrated`
 * watermark stops it) and an entry that cannot be mapped to exactly one current
 * installation is **not** a grant - it is recorded as unresolved and stays denied.
 */
class SuperuserMigrationTest {
    private val uid = 10_123
    private val goneUid = 10_999

    private fun identity(uid: Int = this.uid, packageName: String = "com.example.su") =
        ApplicationIdentity(
            uid, packageName, listOf(packageName),
            TreeSet(setOf("a".repeat(64))), 1_000, 2_000, "/data/app/$packageName/base.apk",
        )

    @Test
    fun importsJailbreakUidsAndKsuPackagesAndRecordsWatermarks() {
        val plan = SuperuserMigration.plan(
            journal = SuperuserJournal.fresh(),
            sources = listOf(
                SuperuserLegacySource(SuperuserMigration.SOURCE_JAILBREAK, uids = setOf(uid)),
                SuperuserLegacySource(
                    SuperuserMigration.SOURCE_KSU, packages = setOf("com.example.su"),
                ),
            ),
            identityOfUid = { candidate -> if (candidate == uid) identity() else null },
            uidOfPackage = { name -> if (name == "com.example.su") uid else null },
            now = 5_000,
        )
        assertEquals(2, plan.sources.size)
        // The same uid from two sources is one grant, not two records.
        assertEquals(1, plan.grants.size)
        assertEquals(identity(), plan.grants.single())
        assertTrue(plan.unresolved.isEmpty())
    }

    @Test
    fun unmappedEntriesAreUnresolvedAndStayDenied() {
        val plan = SuperuserMigration.plan(
            journal = SuperuserJournal.fresh(),
            sources = listOf(
                SuperuserLegacySource(
                    SuperuserMigration.SOURCE_JAILBREAK,
                    uids = setOf(goneUid),
                ),
                SuperuserLegacySource(
                    SuperuserMigration.SOURCE_ULTRA, packages = setOf("com.example.gone"),
                ),
            ),
            identityOfUid = { null },
            uidOfPackage = { null },
        )
        assertTrue(plan.grants.isEmpty())
        assertEquals(2, plan.unresolved.size)
        assertEquals(
            SuperuserMigration.REASON_IDENTITY_UNAVAILABLE,
            plan.unresolved.first { it.uid == goneUid }.reason,
        )
        assertEquals(
            SuperuserMigration.REASON_PACKAGE_UNRESOLVED,
            plan.unresolved.first { it.packageName == "com.example.gone" }.reason,
        )
        // Default deny: an unresolved entry is never turned into permission.
        val decision = ManagerSuperuserPolicy.decide(
            AuthorizationSnapshot(true, emptyMap()), goneUid, identity(goneUid),
        )
        assertFalse(decision.allowed)
    }

    @Test
    fun aPackageThatMovedToAnotherUidIsUnresolved() {
        val plan = SuperuserMigration.plan(
            journal = SuperuserJournal.fresh(),
            sources = listOf(
                SuperuserLegacySource(SuperuserMigration.SOURCE_KSU, packages = setOf("com.example.su")),
            ),
            identityOfUid = { identity(uid = 10_777, packageName = "com.example.other") },
            uidOfPackage = { 10_777 },
        )
        assertTrue(plan.grants.isEmpty())
        assertEquals(
            SuperuserMigration.REASON_IDENTITY_UNAVAILABLE,
            plan.unresolved.single().reason,
        )
    }

    @Test
    fun aMigratedSourceIsSkippedAndTheSecondRunIsEmpty() {
        val journal = SuperuserJournal.fresh().withMigrated(SuperuserMigration.SOURCE_JAILBREAK, 3)
        val plan = SuperuserMigration.plan(
            journal = journal,
            sources = listOf(
                SuperuserLegacySource(SuperuserMigration.SOURCE_JAILBREAK, uids = setOf(uid)),
            ),
            identityOfUid = { identity() },
            uidOfPackage = { uid },
        )
        assertTrue(plan.empty)
    }
}
