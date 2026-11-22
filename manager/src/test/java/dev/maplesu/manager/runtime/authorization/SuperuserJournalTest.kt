package dev.maplesu.manager.runtime.authorization

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException

/**
 * Host regression for the monotonic journal (design §1.1).
 *
 * <p>The journal is what makes "revoke never comes back" true across a crash and what
 * makes the legacy import idempotent. Both are properties of the *model*, so they are
 * tested here without a device and without a root file system.
 */
class SuperuserJournalTest {
    @Rule
    @JvmField
    val folder = TemporaryFolder()

    @Test
    fun revisionIsMonotonicAndGrantsMoveTheUidWatermark() {
        val journal = SuperuserJournal.fresh()
        assertEquals(0L, journal.rev)
        val first = journal.granted(10123, 1_000)
        assertEquals(1L, first.rev)
        assertEquals(1L, first.uidRevOf(10123))
        val second = first.granted(10456, 2_000)
        assertEquals(2L, second.rev)
        assertEquals(1L, second.uidRevOf(10123))
        assertEquals(2L, second.uidRevOf(10456))
    }

    @Test
    fun revokeDoesNotTouchTheGrantWatermarkAndIsIrreversibleForOlderGrants() {
        val granted = SuperuserJournal.fresh().granted(10123, 1_000)
        val revoked = granted.revoked(10123, "com.example.su", 2_000)
        assertEquals(2L, revoked.rev)
        // The critical invariant: a revoke that also moved uidRev would equal the
        // tombstone revision and fail its own tombRev > uidRev test.
        assertEquals(1L, revoked.uidRevOf(10123))
        assertTrue(revoked.revoked(10123))
        // An explicit later grant does come back - with a newer revision.
        val regranted = revoked.granted(10123, 3_000)
        assertFalse(regranted.revoked(10123))
        assertEquals(3L, regranted.uidRevOf(10123))
        // ... and the stale tombstone is gone, so it cannot shadow the new grant.
        assertTrue(regranted.tombs.none { it.uid == 10123 })
    }

    @Test
    fun switchOnlyBumpsTheRevision() {
        val touched = SuperuserJournal.fresh().granted(10123, 1_000).touched()
        assertEquals(2L, touched.rev)
        assertEquals(1L, touched.uidRevOf(10123))
        assertTrue(touched.tombs.isEmpty())
    }

    @Test
    fun writeAndReadRoundTripAndKeepThePreviousRevision() {
        val file = File(folder.newFolder("journal"), SuperuserJournalStore.FILE)
        val first = SuperuserJournal.fresh().granted(10123, 1_000)
        SuperuserJournalStore.write(file, first)
        val loaded = SuperuserJournalStore.read(file)
        assertNotNull(loaded)
        assertEquals(1L, loaded!!.rev)
        assertEquals(1L, loaded.uidRevOf(10123))

        val second = first.revoked(10123, "com.example.su", 2_000)
        SuperuserJournalStore.write(file, second)
        assertEquals(2L, SuperuserJournalStore.read(file)!!.rev)
        // The previous revision is the rollback/reconciliation copy.
        val previous = File(file.parentFile, SuperuserJournalStore.PREV)
        assertTrue("previous revision missing", previous.isFile)
        assertEquals(1L, SuperuserJournalStore.read(previous)!!.rev)
    }

    @Test
    fun malformedJournalFailsReadsInsteadOfLosingRevocations() {
        val directory = folder.newFolder("broken")
        val file = File(directory, SuperuserJournalStore.FILE)
        file.writeText("{\"schema\":1,\"rev\":")
        assertThrows(IOException::class.java) { SuperuserJournalStore.read(file) }
        assertThrows(IOException::class.java) { SuperuserJournalStore.revoked(file, 10123) }
        assertEquals(0L, SuperuserJournalStore.revision(file))
    }

    @Test
    fun unknownSchemaIsRefused() {
        val file = File(folder.newFolder("schema"), SuperuserJournalStore.FILE)
        file.writeText("{\"schema\":99,\"rev\":5}")
        assertThrows(IOException::class.java) { SuperuserJournalStore.read(file) }
    }

    @Test
    fun watermarksAreBounded() {
        var journal = SuperuserJournal.fresh().withMigrated("jailbreak", 3)
        repeat(SuperuserJournal.APPLIED_LIMIT + 5) { index ->
            journal = journal.withApplied(
                SuperuserApplied("KSU_ALLOWLIST", index.toLong(), index.toLong(), true),
            )
        }
        assertEquals(SuperuserJournal.APPLIED_LIMIT, journal.applied.size)
        repeat(SuperuserJournal.UNRESOLVED_LIMIT + 5) { index ->
            journal = journal.withUnresolved(
                listOf(SuperuserUnresolved("ksu", index, "p", "identity-unavailable", index.toLong())),
            )
        }
        assertEquals(SuperuserJournal.UNRESOLVED_LIMIT, journal.unresolved.size)
        assertEquals(3L, journal.migrated["jailbreak"])
    }
}
