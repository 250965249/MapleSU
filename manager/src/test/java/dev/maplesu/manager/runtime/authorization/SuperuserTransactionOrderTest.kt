package dev.maplesu.manager.runtime.authorization

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException
import java.util.TreeSet

/**
 * Host regression for the transaction's ordering and failure semantics
 * (design §3.2 / §7.3 item 2).
 *
 * <p>The design's order is journal -> bin -> mirror -> applied, and every crash point
 * has to land on the safe side. These tests inject a store failure at exactly those
 * points and assert what a *decision* would say afterwards, not merely that an exception
 * was thrown.
 */
class SuperuserTransactionOrderTest {
    @Rule
    @JvmField
    val folder = TemporaryFolder()

    private val uid = 10_123

    private fun identity() = ApplicationIdentity(
        uid, "com.example.su", listOf("com.example.su"),
        TreeSet(setOf("a".repeat(64))), 1_000, 2_000, "/data/app/com.example.su/base.apk",
    )

    private class FakeStore(
        var state: SuperuserStoreState,
        var failSave: Boolean = false,
        var failLoad: Boolean = false,
        var absent: Boolean = false,
    ) : SuperuserStorePort {
        var saves = 0
        override fun isAbsent(): Boolean = absent
        override fun load(): SuperuserStoreState {
            if (failLoad) throw IOException("AUTH_STORE_CORRUPT")
            return state
        }

        override fun save(state: SuperuserStoreState) {
            if (failSave) throw IOException("AUTH_STORE_WRITE_FAILED")
            this.state = state
            absent = false
            saves++
        }
    }

    private class RecordingMirror(
        override val backend: String = "KSU_ALLOWLIST",
        var ok: Boolean = true,
        var detail: String = "",
    ) : SuperuserMirror {
        var calls = 0
        override fun apply(snapshot: AuthorizationSnapshot): MirrorOutcome {
            calls++
            return if (ok) MirrorOutcome.success() else MirrorOutcome.failure(detail)
        }
    }

    private fun journal(dir: File): File = File(dir, SuperuserJournalStore.FILE)

    private fun transaction(
        directory: File,
        store: SuperuserStorePort,
        journalFile: File = journal(directory),
        mirror: SuperuserMirror? = null,
        audit: (SuperuserAuditRecord) -> Unit = {},
    ) = SuperuserTransaction(directory, store, journalFile, mirror, { 1_000L }, audit)

    private fun decide(store: FakeStore, journalFile: File): Decision {
        val state = store.state
        val loaded = SuperuserJournalStore.read(journalFile) ?: SuperuserJournal.fresh()
        return ManagerSuperuserPolicy.decide(
            AuthorizationsSnapshot.from(state.enabled, state.grants, loaded),
            uid,
            identity(),
        )
    }

    @Test fun explicitFirstInstallationAtomicallyEnablesItsIdentityBoundManager() {
        val dir = folder.newFolder("install-new")
        val store = FakeStore(SuperuserStoreState(false, emptyMap()), absent = true)
        val result = transaction(dir, store).initializeForInstallationIfAbsent(identity())
        assertTrue(result.code ?: "", result.ok)
        assertTrue(store.state.enabled)
        assertEquals(identity(), store.state.grants[uid])
        assertTrue(decide(store, journal(dir)).allowed)
        assertEquals(1, store.saves)
        assertTrue(transaction(dir, store).initializeForInstallationIfAbsent(identity()).ok)
        assertEquals("Existing authority is never initialized again", 1, store.saves)
    }

    @Test fun explicitInstallationPreservesAnExistingDisabledAuthority() {
        val dir = folder.newFolder("install-disabled")
        val store = FakeStore(SuperuserStoreState(false, emptyMap()))
        val result = transaction(dir, store).initializeForInstallationIfAbsent(identity())
        assertTrue(result.ok)
        assertFalse(store.state.enabled)
        assertEquals(0, store.saves)
    }

    @Test fun missingStoreWithExistingRevocationDoesNotCreateANewGrant() {
        val dir = folder.newFolder("install-revoked")
        val store = FakeStore(SuperuserStoreState(false, emptyMap()), absent = true)
        SuperuserJournalStore.write(journal(dir), SuperuserJournal.fresh().revoked(uid, identity().packageName, 1_000))
        assertTrue(transaction(dir, store).initializeForInstallationIfAbsent(identity()).ok)
        assertFalse(store.state.enabled)
        assertEquals(0, store.saves)
        assertTrue(SuperuserJournalStore.read(journal(dir))!!.revoked(uid))
    }

    @Test fun unreadableAuthorityIsNotAnUninitializedInstallation() {
        val dir = folder.newFolder("install-unreadable")
        val store = FakeStore(SuperuserStoreState(false, emptyMap()), failLoad = true, absent = true)
        assertFalse(transaction(dir, store).initializeForInstallationIfAbsent(identity()).ok)
        assertEquals(0, store.saves)
        assertFalse(journal(dir).exists())
    }

    @Test fun failedFirstInstallWriteLeavesDenialAndIsNotReinitialized() {
        val dir = folder.newFolder("install-partial")
        val store = FakeStore(SuperuserStoreState(false, emptyMap()), failSave = true, absent = true)
        assertFalse(transaction(dir, store).initializeForInstallationIfAbsent(identity()).ok)
        assertTrue(SuperuserJournalStore.read(journal(dir))!!.revoked(uid))
        store.failSave = false
        assertTrue(transaction(dir, store).initializeForInstallationIfAbsent(identity()).ok)
        assertEquals(0, store.saves)
        assertFalse(decide(store, journal(dir)).allowed)
    }

    @Test
    fun grantWritesJournalThenStoreAndIsVisibleToTheDecision() {
        val dir = folder.newFolder("grant")
        val store = FakeStore(SuperuserStoreState(true, emptyMap()))
        val audit = mutableListOf<SuperuserAuditRecord>()
        val transaction = transaction(dir, store, audit = { audit += it })
        val outcome = transaction.grant(identity(), origin = "manager")

        assertTrue(outcome.code ?: "", outcome.ok)
        assertEquals(1L, outcome.rev)
        assertEquals(identity(), store.state.grants[uid])
        assertEquals(1L, SuperuserJournalStore.read(journal(dir))!!.uidRevOf(uid))
        assertEquals("grant", audit.single().event)
        assertTrue(decide(store, journal(dir)).allowed)
    }

    @Test
    fun grantCrashBetweenJournalAndStoreStaysDenied() {
        val dir = folder.newFolder("grant-crash")
        val store = FakeStore(SuperuserStoreState(true, emptyMap()), failSave = true)
        val outcome = transaction(dir, store).grant(identity())

        assertFalse(outcome.ok)
        assertEquals(SuCodes.SU_STORE_WRITE_FAILED, outcome.code)
        // Journal is ahead (grant not effective yet), store has no record: deny.
        assertEquals(1L, SuperuserJournalStore.read(journal(dir))!!.rev)
        assertTrue(store.state.grants.isEmpty())
        assertEquals(SuCodes.AUTH_NOT_GRANTED, decide(store, journal(dir)).reason)
    }

    @Test
    fun revokeCrashBetweenJournalAndStoreStaysDenied() {
        val dir = folder.newFolder("revoke-crash")
        val store = FakeStore(SuperuserStoreState(true, mapOf(uid to identity())), failSave = true)
        val outcome = transaction(dir, store).revoke(uid, "com.example.su")

        assertFalse(outcome.ok)
        assertEquals(SuCodes.SU_STORE_WRITE_FAILED, outcome.code)
        // The record survived the crash, but the tombstone is newer: deny.
        assertTrue(store.state.grants.containsKey(uid))
        assertEquals(SuCodes.AUTH_NOT_GRANTED, decide(store, journal(dir)).reason)
    }

    @Test
    fun aJournalWriteFailureAbortsBeforeTouchingTheStore() {
        val dir = folder.newFolder("journal-failure")
        val brokenJournal = journal(dir)
        val store = FakeStore(SuperuserStoreState(true, mapOf(uid to identity())))
        var observations = 0
        val port = object : SuperuserStorePort {
            override fun load() = store.load().also {
                if (observations++ == 0) {
                    assertTrue(brokenJournal.mkdir())
                    File(brokenJournal, "blocker").writeText("keep target directory non-empty")
                }
            }
            override fun save(state: SuperuserStoreState) = store.save(state)
        }
        val outcome = transaction(dir, port, journalFile = brokenJournal)
            .revoke(uid, "com.example.su")

        assertFalse(outcome.ok)
        assertEquals(SuCodes.SU_JOURNAL_WRITE_FAILED, outcome.code)
        assertEquals("failed publication is observed without re-injecting the fixture", 2, observations)
        assertEquals("a revoke must not reach the store when its tombstone was not written",
            0, store.saves)
        assertTrue(store.state.grants.containsKey(uid))
        assertThrows(IOException::class.java) { SuperuserJournalStore.read(brokenJournal) }
    }

    @Test
    fun switchOffIsBinFirstSoAFailedJournalWriteStillDisables() {
        val dir = folder.newFolder("switch")
        val brokenJournal = journal(dir)
        val store = FakeStore(SuperuserStoreState(true, mapOf(uid to identity())))
        val port = object : SuperuserStorePort {
            override fun load() = store.load()
            override fun save(state: SuperuserStoreState) {
                store.save(state)
                assertTrue(brokenJournal.mkdir())
                File(brokenJournal, "blocker").writeText("keep target directory non-empty")
            }
        }
        val outcome = transaction(dir, port, journalFile = brokenJournal)
            .setEnabled(false)

        assertFalse(outcome.ok)
        // The switch lives only in the binary store; writing it first is what keeps a
        // crash from leaving every caller admitted.
        assertFalse(store.state.enabled)
        assertEquals(SuCodes.AUTH_DISABLED, ManagerSuperuserPolicy.decide(
            AuthorizationsSnapshot.from(store.state.enabled, store.state.grants, SuperuserJournal.fresh()),
            uid, identity()).reason)
    }

    @Test
    fun aFailedMirrorNeverRollsBackTheDecisionButStaysPending() {
        val dir = folder.newFolder("mirror")
        val store = FakeStore(SuperuserStoreState(true, emptyMap()))
        val mirror = RecordingMirror(ok = false, detail = "KSU_UNAVAILABLE")
        val outcome = transaction(dir, store, mirror = mirror).grant(identity())

        assertTrue(outcome.ok)
        assertTrue(outcome.pendingApply)
        assertTrue(decide(store, journal(dir)).allowed)
        val mark = SuperuserJournalStore.read(journal(dir))!!.applied.single()
        assertEquals("KSU_ALLOWLIST", mark.backend)
        assertFalse(mark.ok)

        // The retry path: the backend recovers, the decision does not change.
        mirror.ok = true
        val retried = transaction(dir, store, mirror = mirror).applyPending()
        assertTrue(retried.ok)
        assertFalse(retried.pendingApply)
        assertTrue(SuperuserJournalStore.read(journal(dir))!!.applied.last().ok)
        assertTrue(decide(store, journal(dir)).allowed)
    }

    @Test
    fun staleMirrorReceiptKeepsTheLatestDecisionAndRequiresReconciliation() {
        val dir = folder.newFolder("stale-mirror")
        val store = FakeStore(SuperuserStoreState(true, emptyMap()))
        val tx = transaction(dir, store)
        assertEquals(1L, tx.grant(identity()).rev)
        assertEquals(2L, tx.revoke(uid, "com.example.su").rev)
        assertFalse(tx.markApplied("ULTRA_ALLOWLIST", 2, MirrorOutcome.success()).pendingApply)

        val stale = tx.markApplied("ULTRA_ALLOWLIST", 1, MirrorOutcome.success())
        assertTrue(stale.ok)
        assertTrue(stale.pendingApply)
        assertEquals(2L, stale.rev)
        val journal = SuperuserJournalStore.read(journal(dir))!!
        assertEquals(2L, journal.rev)
        assertTrue(journal.revoked(uid))
        assertFalse(journal.applied.last().ok)
        assertEquals(2L, journal.applied.last().rev)
        assertTrue(store.state.grants.isEmpty())
        assertFalse(decide(store, journal(dir)).allowed)
        assertFalse(tx.markApplied("ULTRA_ALLOWLIST", 2, MirrorOutcome.success()).pendingApply)
    }

    @Test
    fun revokeOfAnUninstalledPackageKeepsItsNameForSubsequentRetries() {
        val dir = folder.newFolder("uninstalled-revoke")
        val store = FakeStore(SuperuserStoreState(true, mapOf(uid to identity())))
        val tx = transaction(dir, store)
        assertTrue(tx.revoke(uid, null).ok)
        assertEquals("com.example.su", SuperuserJournalStore.read(journal(dir))!!.tombs.single().packageName)
        assertTrue(tx.revoke(uid, null).ok)
        assertEquals("com.example.su", SuperuserJournalStore.read(journal(dir))!!.tombs.single().packageName)
    }

    @Test
    fun successfulMirrorOfAnOlderRevisionDoesNotSkipThePendingRetry() {
        val dir = folder.newFolder("behind-mirror")
        val store = FakeStore(SuperuserStoreState(true, emptyMap()))
        val mirror = RecordingMirror()
        val local = transaction(dir, store)
        val mirrored = transaction(dir, store, mirror = mirror)
        assertTrue(mirrored.grant(identity()).ok)
        assertEquals(1, mirror.calls)
        assertTrue(local.revoke(uid, "com.example.su").ok)
        assertTrue(mirrored.applyPending().ok)
        assertEquals(2, mirror.calls)
        assertEquals(2L, SuperuserJournalStore.read(journal(dir))!!.applied.last().rev)
    }

    @Test
    fun aCorruptStoreIsNeverOverwrittenByATransaction() {
        val dir = folder.newFolder("corrupt")
        val store = FakeStore(SuperuserStoreState(false, emptyMap()), failLoad = true)
        val outcome = transaction(dir, store).grant(identity())

        assertFalse(outcome.ok)
        assertEquals(SuCodes.SU_STORE_READ_FAILED, outcome.code)
        assertEquals(0, store.saves)
    }
}
