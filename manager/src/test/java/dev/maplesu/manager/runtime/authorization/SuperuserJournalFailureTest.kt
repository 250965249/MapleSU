package dev.maplesu.manager.runtime.authorization

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException

/** Exercises the real binary store, journal and both authorization consumers. */
class SuperuserJournalFailureTest {
    @Rule @JvmField val folder = TemporaryFolder()
    private val uid = 10_123
    private val identity = ApplicationIdentity(uid, "com.example.su", listOf("com.example.su"),
        setOf("a".repeat(64)), 1_000, 2_000, "/data/app/com.example.su/base.apk")

    private data class Fixture(val binary: File, val journal: File)

    private fun seed(): Fixture {
        val dir = folder.newFolder()
        val binary = File(dir, "authorizations.bin")
        FileAuthorizationStore(binary.toPath()).save(FileAuthorizationStore.State(true, mapOf(uid to identity)))
        val journal = File(dir, SuperuserJournalStore.FILE)
        SuperuserJournalStore.write(journal, SuperuserJournal.fresh().granted(uid, 1_000))
        return Fixture(binary, journal)
    }

    private fun transaction(f: Fixture, failSave: Boolean = false): SuperuserTransaction {
        val actual = FileSuperuserStorePort(f.binary.toPath())
        val port = object : SuperuserStorePort {
            override fun load() = actual.load()
            override fun save(state: SuperuserStoreState) {
                if (failSave) throw IOException("INJECTED_BIN_SAVE_FAILURE")
                actual.save(state)
            }
        }
        return SuperuserTransaction(f.binary.parentFile, port, f.journal)
    }

    private fun revokedWithFailedBinSave(): Fixture {
        val f = seed()
        val before = f.binary.readBytes()
        val result = transaction(f, failSave = true).revoke(uid, identity.packageName)
        assertFalse(result.ok)
        assertEquals(SuCodes.SU_STORE_WRITE_FAILED, result.code)
        assertArrayEquals(before, f.binary.readBytes())
        assertEquals(2L, SuperuserJournalStore.read(f.journal)!!.rev)
        assertTrue(SuperuserJournalStore.read(f.journal)!!.revoked(uid))
        assertFalse(ManagerSuperuserPolicy.decide(
            AuthorizationsSnapshot.load(f.binary.toPath(), f.journal), uid, identity).allowed)
        return f
    }

    @Test fun corruptJournalDoesNotResurrectGrantAfterFailedBinSave() {
        val f = revokedWithFailedBinSave()
        f.journal.writeText("{\"schema\":1,\"rev\":")
        val before = f.journal.readBytes()
        val snapshot = AuthorizationsSnapshot.load(f.binary.toPath(), f.journal)
        assertFalse("corrupt tombstone must not reopen old bin grant",
            ManagerSuperuserPolicy.decide(snapshot, uid, identity).allowed)
        assertTrue(snapshot.corrupt)
        assertArrayEquals(before, f.journal.readBytes())
    }

    @Test fun normalPolicyDoesNotAuthorizeWithCorruptTombstone() {
        val f = revokedWithFailedBinSave()
        val policy = AuthorizationPolicy(f.binary.toPath()) { identity }
        f.journal.writeText("broken")
        assertThrows(IOException::class.java) { policy.authorize(uid) }
        var committed = false
        assertFalse(policy.commitIfAuthorized(uid) { committed = true })
        assertFalse(committed)
    }

    @Test fun corruptJournalAbortsMutationWithoutOverwritingEitherFile() {
        val f = revokedWithFailedBinSave()
        f.journal.writeText("broken")
        val journalBefore = f.journal.readBytes()
        val binBefore = f.binary.readBytes()
        val previous = File(f.journal.parentFile, SuperuserJournalStore.PREV).readBytes()
        val result = transaction(f).grant(identity)
        assertFalse("corruption is a read failure, not a new revision", result.ok)
        assertEquals("SU_JOURNAL_READ_FAILED", result.code)
        assertArrayEquals(journalBefore, f.journal.readBytes())
        assertArrayEquals(binBefore, f.binary.readBytes())
        assertArrayEquals(previous, File(f.journal.parentFile, SuperuserJournalStore.PREV).readBytes())
    }

    @Test fun readFailureAbortsSwitchBeforeChangingTheStore() {
        val f = seed()
        f.journal.writeText("broken")
        val binaryBefore = f.binary.readBytes()
        val result = transaction(f).setEnabled(false)
        assertFalse(result.ok)
        assertEquals("SU_JOURNAL_READ_FAILED", result.code)
        assertArrayEquals(binaryBefore, f.binary.readBytes())
        assertFalse(AuthorizationPolicy(f.binary.toPath()) { identity }.isEnabled)
    }

    @Test fun invalidJournalFormsNeverBecomeAnEmptyHistory() {
        val forms = listOf("{\"schema\":99,\"rev\":2}", "{\"schema\":1,\"rev\":-1}",
            " ".repeat(SuperuserJournal.MAX_BYTES + 1))
        forms.forEach { text ->
            val f = seed()
            f.journal.writeText(text)
            assertTrue(AuthorizationsSnapshot.load(f.binary.toPath(), f.journal).corrupt)
            assertThrows(IOException::class.java) { SuperuserJournalStore.read(f.journal) }
        }
    }

    @Test fun directoryAtJournalPathIsReadFailureAndDoesNotRunCommand() {
        val f = seed()
        assertTrue(f.journal.delete())
        assertTrue(f.journal.mkdir())
        val policy = AuthorizationPolicy(f.binary.toPath()) { identity }
        assertTrue(AuthorizationsSnapshot.load(f.binary.toPath(), f.journal).corrupt)
        assertThrows(IOException::class.java) { policy.authorize(uid) }
        assertFalse(transaction(f).revoke(uid, identity.packageName).ok)
        assertTrue(f.journal.isDirectory)
    }

    @Test fun genuinelyAbsentJournalPreservesLegacyImportAndCurrentGrant() {
        val f = seed()
        assertTrue(f.journal.delete())
        assertNull(SuperuserJournalStore.read(f.journal))
        val snapshot = AuthorizationsSnapshot.load(f.binary.toPath(), f.journal)
        assertFalse(snapshot.corrupt)
        assertTrue(ManagerSuperuserPolicy.decide(snapshot, uid, identity).allowed)
        assertEquals(identity, AuthorizationPolicy(f.binary.toPath()) { identity }.authorize(uid))
        assertTrue(transaction(f).revoke(uid, identity.packageName).ok)
        assertEquals(1L, SuperuserJournalStore.read(f.journal)!!.rev)
        assertFalse(ManagerSuperuserPolicy.decide(
            AuthorizationsSnapshot.load(f.binary.toPath(), f.journal), uid, identity).allowed)
    }
}
