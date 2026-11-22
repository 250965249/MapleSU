package dev.maplesu.manager.runtime.authorization

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.file.Path
import java.util.TreeSet

/**
 * The two-mode consistency regression (design §7.2 / §7.3 item 3).
 *
 * <p>One snapshot, two readers: the Ultra path (`ManagerSuperuserPolicy.decide`) and the
 * Normal path (`AuthorizationPolicy`, the facade `NativeSuBinder` already used). The point
 * of the one-authority change is that these two cannot disagree about the list *or* the
 * refusal code, so the test drives them against the same files and compares the answers.
 *
 * <p>The KSU mirror is a mirror, not a third opinion: its `applied` watermark must point
 * at the decision's revision, and a failed mirror must be visible as `pendingApply`
 * without changing the decision.
 */
class TwoModeConsistencyTest {
    @Rule
    @JvmField
    val folder = TemporaryFolder()

    private val uid = 10_123

    private fun identity(update: Long = 2_000) = ApplicationIdentity(
        uid, "com.example.su", listOf("com.example.su"),
        TreeSet(setOf("a".repeat(64))), 1_000, update, "/data/app/com.example.su/base.apk",
    )

    private fun storeFile(
        enabled: Boolean,
        grants: Map<Int, ApplicationIdentity>,
    ): Path {
        val directory = folder.newFolder()
        val file = directory.toPath().resolve("authorizations.bin")
        FileAuthorizationStore(file).save(FileAuthorizationStore.State(enabled, grants))
        return file
    }

    private fun journalFile(store: Path, journal: SuperuserJournal): File =
        File(store.parent.toFile(), SuperuserJournalStore.FILE).also {
            SuperuserJournalStore.write(it, journal)
        }

    private fun normalPolicy(
        store: Path,
        current: ApplicationIdentity?,
    ): AuthorizationPolicy = AuthorizationPolicy(store, AuthorizationPolicy.TrustedIdentityProvider {
        current
    })

    private fun normalReason(store: Path, current: ApplicationIdentity?): String {
        val policy = normalPolicy(store, current)
        return try {
            policy.authorize(uid)
            SuCodes.ALLOW
        } catch (error: SecurityException) {
            error.message ?: "null"
        }
    }

    private fun ultraDecision(store: Path, current: ApplicationIdentity?): Decision =
        ManagerSuperuserPolicy.decide(
            AuthorizationsSnapshot.load(store, File(store.parent.toFile(), SuperuserJournalStore.FILE)),
            uid,
            current,
        )

    private fun assertBoth(store: Path, current: ApplicationIdentity?, expected: String) {
        val ultra = ultraDecision(store, current)
        val normal = normalReason(store, current)
        assertEquals("Ultra decision", expected, ultra.reason)
        assertEquals("Normal decision", expected, normal)
        if (expected != SuCodes.ALLOW) {
            assertFalse(ultra.allowed)
        }
    }

    @Test
    fun bothModesReadTheSameListAndReturnTheSameCodes() {
        val granted = storeFile(true, mapOf(uid to identity()))
        assertEquals(SuCodes.ALLOW, ultraDecision(granted, identity()).reason)
        assertEquals(SuCodes.ALLOW, normalReason(granted, identity()))

        val empty = storeFile(true, emptyMap())
        assertBoth(empty, identity(), SuCodes.AUTH_NOT_GRANTED)

        val disabled = storeFile(false, mapOf(uid to identity()))
        assertBoth(disabled, identity(), SuCodes.AUTH_DISABLED)

        val tombstoned = storeFile(true, mapOf(uid to identity()))
        journalFile(
            tombstoned,
            SuperuserJournal.fresh().granted(uid, 1_000).revoked(uid, "com.example.su", 2_000),
        )
        assertBoth(tombstoned, identity(), SuCodes.AUTH_NOT_GRANTED)

        val changed = storeFile(true, mapOf(uid to identity(update = 1_500)))
        assertBoth(changed, identity(update = 2_000), SuCodes.AUTH_IDENTITY_CHANGED)
    }

    @Test
    fun anUnreadableIdentityIsDeniedByBothModes() {
        val store = storeFile(true, mapOf(uid to identity()))
        // The Ultra endpoint reports the caller-resolution code before the list is read;
        // Normal's facade reports its own AUTH_IDENTITY_UNAVAILABLE. Both refuse, and the
        // names are the design's (§4.4: the two families exist on purpose).
        assertFalse(ultraDecision(store, null).allowed)
        assertEquals(SuCodes.AUTH_IDENTITY_CHANGED, ultraDecision(store, null).reason)
        assertEquals(SuCodes.AUTH_IDENTITY_UNAVAILABLE, normalReason(store, null))
    }

    @Test
    fun theKsuMirrorWatermarkPointsAtTheSameRevision() {
        val store = storeFile(true, mapOf(uid to identity()))
        val journal = SuperuserJournal.fresh()
            .granted(uid, 1_000)
            .withApplied(SuperuserApplied("KSU_ALLOWLIST", 1, 2_000, true))
        journalFile(store, journal)
        val snapshot = AuthorizationsSnapshot.load(store, File(store.parent.toFile(), SuperuserJournalStore.FILE))

        assertEquals(1L, snapshot.rev)
        assertEquals(1L, snapshot.appliedOf("KSU_ALLOWLIST")!!.rev)
        assertFalse(snapshot.pendingApply())
        // One list, one revision: both readers see exactly this.
        assertTrue(ManagerSuperuserPolicy.decide(snapshot, uid, identity()).allowed)
        assertEquals(SuCodes.ALLOW, normalReason(store, identity()))
    }

    @Test
    fun aFailedMirrorIsPendingWithoutChangingTheDecision() {
        val store = storeFile(true, mapOf(uid to identity()))
        journalFile(
            store,
            SuperuserJournal.fresh().granted(uid, 1_000)
                .withApplied(SuperuserApplied("KSU_ALLOWLIST", 1, 2_000, false, "KSU_UNAVAILABLE")),
        )
        val snapshot = AuthorizationsSnapshot.load(store, File(store.parent.toFile(), SuperuserJournalStore.FILE))

        assertTrue(snapshot.pendingApply())
        // The restricted entries already enforce the decision; the mirror is behind.
        assertTrue(ManagerSuperuserPolicy.decide(snapshot, uid, identity()).allowed)
        assertEquals(SuCodes.ALLOW, normalReason(store, identity()))
        assertEquals("KSU_UNAVAILABLE", snapshot.appliedOf("KSU_ALLOWLIST")!!.detail)
    }

    @Test
    fun theNormalFacadeWritesThroughTheTransactionJustLikeTheUltraTool() {
        val store = storeFile(true, emptyMap())
        val policy = normalPolicy(store, identity())
        policy.grant(uid)

        val journal = SuperuserJournalStore.read(
            File(store.parent.toFile(), SuperuserJournalStore.FILE),
        )
        assertNotNull("grant did not create a journal revision", journal)
        assertEquals(1L, journal!!.uidRevOf(uid))
        // Both readers see the grant written by the Normal facade.
        assertTrue(ManagerSuperuserPolicy.decide(
            AuthorizationsSnapshot.load(store, File(store.parent.toFile(), SuperuserJournalStore.FILE)),
            uid, identity(),
        ).allowed)

        policy.revoke(uid)
        assertEquals(
            SuCodes.AUTH_NOT_GRANTED,
            ultraDecision(store, identity()).reason,
        )
        assertEquals(
            SuCodes.AUTH_NOT_GRANTED,
            normalReason(store, identity()),
        )
    }
}
