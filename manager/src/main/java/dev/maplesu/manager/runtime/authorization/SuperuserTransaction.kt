package dev.maplesu.manager.runtime.authorization

import java.io.File
import java.io.IOException
import java.nio.file.Path
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.NoSuchFileException
import java.nio.file.attribute.BasicFileAttributes
import java.util.IdentityHashMap

/** I/O errors remain errors; only ENOENT is an uninitialized authority. */
private fun authorityFileAbsent(file: Path): Boolean = try {
    Files.readAttributes(file, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    false
} catch (_: NoSuchFileException) {
    true
}

/** The existing authority holds decisions and complete identity-bound profiles. */
data class SuperuserStoreState(
    val enabled: Boolean,
    val grants: Map<Int, ApplicationIdentity>,
    val profiles: Map<Int, StoredSuProfile> = emptyMap(),
)

/**
 * The binary store as a port, so the transaction's ordering can be tested at every
 * failure point without a root file system (design §7.3 item 2).
 *
 * <p>This is the *only* writer of `authorizations.bin` after this change: the Kotlin
 * transaction writes it, and `AuthorizationPolicy`, the one-shot tool and Normal's
 * resident service all go through the transaction. Legacy formats remain readable; v3 adds complete identity-bound profiles
 * ([FileAuthorizationStore], `MSUA` + SHA-256 trailer).
 */
interface SuperuserStorePort {
    /** Only a definite missing file may establish a new installation authority. */
    fun isAbsent(): Boolean = false
    /** @throws IOException when the file exists but cannot be parsed (fail-closed). */
    fun load(): SuperuserStoreState

    /** @throws IOException when the atomic replace fails. */
    fun save(state: SuperuserStoreState)
}

class FileSuperuserStorePort(private val file: Path) : SuperuserStorePort {
    override fun isAbsent(): Boolean = authorityFileAbsent(file)
    override fun load(): SuperuserStoreState {
        val store = FileAuthorizationStore(file)
        val state = store.load()
        return SuperuserStoreState(state.enabled, state.grants, state.profiles)
    }

    override fun save(state: SuperuserStoreState) {
        FileAuthorizationStore(file).save(FileAuthorizationStore.State(state.enabled, state.grants, state.profiles))
    }
}

/** One mirror backend (KSU allowlist, Ultra `su_auth`): the decision is already in force. */
interface SuperuserMirror {
    val backend: String

    /** Idempotent diff of the current decision; must never throw (return a failure). */
    fun apply(snapshot: AuthorizationSnapshot): MirrorOutcome
}

data class MirrorOutcome(val ok: Boolean, val detail: String = "") {
    companion object {
        @JvmStatic fun success(): MirrorOutcome = MirrorOutcome(true)
        @JvmStatic fun failure(detail: String): MirrorOutcome = MirrorOutcome(false, detail)
    }
}

/** No backend is applicable in this mode: nothing to mirror, nothing to retry. */
object NoSuperuserMirror : SuperuserMirror {
    override val backend: String = "NONE"
    override fun apply(snapshot: AuthorizationSnapshot): MirrorOutcome =
        MirrorOutcome.success()
}

/**
 * One authorization transaction (design §3.2 / §3.4).
 *
 * <p>Order, and why each step is where it is:
 *
 *  1. read journal + store under the transaction lock;
 *  2. write a denial tombstone first, including when preparing a grant;
 *  3. write `authorizations.bin` (v1 format, atomic replace);
 *  4. for a grant, publish its final journal at the prepared revision, then mirror
 *     the decision into the kernel-side backend and record
 *     `applied{backend, rev, ok, detail}`;
 *  5. audit one `grant`/`revoke` line.
 *
 * <p>A failed mirror does **not** roll the decision back - the restricted entries already
 * enforce it, and the design's answer is `PENDING_APPLY` + retry + boot reconcile, not a
 * silently re-opened grant. A switch publishes a restrictive intent before its bin
 * commit, then clears the intent at the same reserved revision. Recovery retains the
 * actual bin value and never replays an interrupted enable.
 */
class SuperuserTransaction(
    private val directory: File,
    private val store: SuperuserStorePort,
    private val journalFile: File,
    private val mirror: SuperuserMirror? = null,
    private val now: () -> Long = System::currentTimeMillis,
    private val audit: (SuperuserAuditRecord) -> Unit = {},
) {
    /** A committed decision can carry diagnostics; retries use `pendingApply`, not audit warnings. */
    data class Outcome(
        val ok: Boolean,
        val rev: Long,
        val code: String? = null,
        val pendingApply: Boolean = false,
        val detail: String = "",
    )

    fun grant(identity: ApplicationIdentity, origin: String = "manager"): Outcome = grantProfile(identity, null, origin)

    /** Explicit environment installation only; an existing disabled authority is preserved. */
    fun initializeForInstallationIfAbsent(identity: ApplicationIdentity): Outcome {
        val resolved = try { requireIdentity(identity) }
        catch (error: Throwable) { return Outcome(false, revision(), SuCodes.AUTH_IDENTITY_CHANGED, detail = describe(error)) }
        return locked(recoverSwitch = false) { _, journal ->
            if (!store.isAbsent() || !authorityFileAbsent(journalFile.toPath()) ||
                !authorityFileAbsent(File(directory, SuperuserJournalStore.PREV).toPath()) ||
                !authorityFileAbsent(File(directory, "import-complete").toPath()))
                return@locked Outcome(true, journal.rev, detail = "installation-authority-preserved")
            val prepared = journal.revoked(resolved.uid, resolved.packageName, now())
            val next = journal.granted(resolved.uid, now())
            val initialized = SuperuserStoreState(true, mapOf(resolved.uid to resolved))
            writeJournal(prepared)
            writeStore(next, initialized)
            writeJournal(next)
            applyMirror(next, initialized)
        }
    }

    fun saveProfile(identity: ApplicationIdentity, profile: SuProfile, origin: String = "manager"): Outcome {
        val stored = try { StoredSuProfile(requireIdentity(identity), profile.frozen()) }
        catch (error: IllegalArgumentException) {
            return Outcome(false, revision(), "PROFILE_INVALID", detail = describe(error))
        }
        return if (profile.allowSu) grantProfile(stored.identity, stored.profile, origin)
            else revokeProfile(identity.uid, profile.name, origin, stored)
    }

    private fun grantProfile(identity: ApplicationIdentity, requested: SuProfile?, origin: String): Outcome {
        val resolved = try {
            requireIdentity(identity)
        } catch (error: Throwable) {
            return Outcome(false, revision(), SuCodes.AUTH_IDENTITY_CHANGED, detail = describe(error))
        }
        return locked { state, journal ->
            val at = now()
            val prepared = journal.revoked(resolved.uid, resolved.packageName, at)
            val profile = requested ?: state.profiles[resolved.uid]?.takeIf { it.identity.matches(resolved) }
                ?.profile?.copy(allowSu = true)
            val profiles = if (profile == null) state.profiles - resolved.uid
                else state.profiles + (resolved.uid to StoredSuProfile(resolved, profile))
            val next = journal.granted(resolved.uid, at).withProfileRevision(resolved.uid, profile != null)
            val saved = state.copy(grants = state.grants + (resolved.uid to resolved), profiles = profiles)
            writeJournal(prepared)
            writeStore(next, saved)
            writeJournal(next)
            val applied = applyMirror(next, saved)
            afterCommit(applied, SuCodes.SU_AUDIT_WRITE_FAILED) {
                audit(
                    SuperuserAuditRecord(
                        event = "grant", uid = resolved.uid, packageName = resolved.packageName,
                        rev = next.rev, ok = true, source = origin, code = SuCodes.ALLOW,
                        detail = applied.detail,
                    ),
                )
                applied
            }
        }
    }

    fun revoke(uid: Int, packageName: String?, origin: String = "manager"): Outcome = revokeProfile(uid, packageName, origin, null)

    private fun revokeProfile(uid: Int, packageName: String?, origin: String, requested: StoredSuProfile?): Outcome = locked { state, journal ->
        // The tombstone is written first: after this line the uid is denied even if the
        // binary store write below never happens.
        val revokedPackage = packageName ?: state.grants[uid]?.packageName
            ?: journal.tombs.lastOrNull { it.uid == uid }?.packageName
        val prepared = journal.revoked(uid, revokedPackage, now())
        val profile = requested ?: state.profiles[uid]?.let { it.copy(profile = it.profile.copy(allowSu = false)) }
        val next = if (profile == null) prepared else prepared.withProfileRevision(uid, true)
        writeJournal(prepared)
        val saved = state.copy(grants = state.grants - uid,
            profiles = if (profile == null) state.profiles else state.profiles + (uid to profile))
        writeStore(next, saved)
        if (profile != null) writeJournal(next)
        val applied = applyMirror(next, saved)
        afterCommit(applied, SuCodes.SU_AUDIT_WRITE_FAILED) {
            audit(
                SuperuserAuditRecord(
                    event = "revoke", uid = uid, packageName = packageName.orEmpty(), rev = next.rev,
                    ok = true, source = origin, code = SuCodes.AUTH_NOT_GRANTED, detail = applied.detail,
                ),
            )
            applied
        }
    }

    /**
     * A restrictive journal intent precedes the bin commit; final publication clears
     * the intent without consuming another revision.
     */
    fun setEnabled(enabled: Boolean, origin: String = "manager"): Outcome = locked { state, journal ->
        val prepared = journal.preparedSwitch(enabled)
        writeJournal(prepared)
        val submitted = afterCommit(Outcome(false, journal.rev, pendingApply = true),
            SuCodes.SU_STORE_WRITE_FAILED) {
            writeStore(prepared, state.copy(enabled = enabled))
            Outcome(true, prepared.rev, pendingApply = true)
        }
        if (!submitted.ok) return@locked submitted
        val committed = afterCommit(submitted, SuCodes.SU_JOURNAL_WRITE_FAILED) {
            writeJournal(prepared.completedSwitch())
            submitted
        }
        afterCommit(committed, SuCodes.SU_AUDIT_WRITE_FAILED) {
            audit(
                SuperuserAuditRecord(
                    event = if (enabled) "enable" else "disable", rev = committed.rev, ok = true,
                    source = origin, code = if (enabled) SuCodes.ALLOW else SuCodes.AUTH_DISABLED,
                    detail = committed.detail,
                ),
            )
            committed
        }
    }

    /**
     * One-shot, idempotent legacy import (design §3.1).
     *
     * <p>Watermark behaviour: a source already present in `migrated` is skipped. The
     * marker is written **after** the binary store, so a crash between them can only
     * cause the import to run again - and re-importing the same identity is a no-op
     * grant, not a lost grant.
     */
    fun import(
        plan: SuperuserMigrationPlan,
        origin: String = "migrate",
    ): Outcome = locked { state, journal ->
        val pending = plan.sources.filter { !journal.migrated.containsKey(it) }
        if (pending.isEmpty() && plan.grants.isEmpty() && plan.unresolved.isEmpty()) {
            return@locked Outcome(true, journal.rev,
                pendingApply = AuthorizationsSnapshot.from(state.enabled, state.grants, journal, state.profiles).pendingApply(),
                detail = "already-migrated")
        }
        var prepared = journal
        var next = journal
        var saved = state
        for (identity in plan.grants) {
            val at = now()
            prepared = prepared.revoked(identity.uid, identity.packageName, at)
            val profile = saved.profiles[identity.uid]?.takeIf { it.identity.matches(identity) }
                ?.profile?.copy(allowSu = true)
            next = next.granted(identity.uid, at).withProfileRevision(identity.uid, profile != null)
            saved = saved.copy(grants = saved.grants + (identity.uid to identity), profiles =
                if (profile == null) saved.profiles - identity.uid
                else saved.profiles + (identity.uid to StoredSuProfile(identity, profile)))
        }
        if (prepared !== journal) writeJournal(prepared)
        writeStore(next, saved)
        // Clear prepared denials and mark sources only after the binary commit.
        for (source in pending) next = next.withMigrated(source, next.rev)
        if (plan.unresolved.isNotEmpty()) next = next.withUnresolved(plan.unresolved)
        if (next !== journal) writeJournal(next)
        var committed = Outcome(true, next.rev,
            pendingApply = AuthorizationsSnapshot.from(saved.enabled, saved.grants, next, saved.profiles).pendingApply(),
            detail = "imported=" + plan.grants.size)
        for (source in pending) {
            val receipt = committed
            committed = afterCommit(receipt, SuCodes.SU_AUDIT_WRITE_FAILED) {
                audit(
                    SuperuserAuditRecord(
                        event = "migrate", rev = next.rev, ok = true, source = source,
                        code = SuCodes.ALLOW, detail = "imported=" + plan.grants.size +
                            " unresolved=" + plan.unresolved.size,
                    ),
                )
                receipt
            }
        }
        committed
    }

    /** A delayed mirror may have changed the SDK after a newer decision was applied. */
    fun markApplied(backend: String, rev: Long, outcome: MirrorOutcome): Outcome = locked { _, journal ->
        val matches = rev == journal.rev
        val ok = matches && outcome.ok
        val detail = if (matches) outcome.detail else "STALE_MIRROR_REVISION:$rev:${journal.rev}"
        val committed = Outcome(true, journal.rev, pendingApply = !ok, detail = detail)
        val recorded = afterCommit(Outcome(false, journal.rev, pendingApply = true, detail = detail),
            SuCodes.SU_JOURNAL_WRITE_FAILED) {
            writeJournal(journal.withApplied(SuperuserApplied(backend, journal.rev, now(), ok, detail)))
            committed
        }
        if (!recorded.ok) return@locked recorded
        afterCommit(recorded, SuCodes.SU_AUDIT_WRITE_FAILED) {
            audit(SuperuserAuditRecord(
                event = "apply", rev = journal.rev, ok = ok, source = backend,
                code = if (ok) SuCodes.ALLOW else SuCodes.SU_TRANSPORT_UNAVAILABLE, detail = detail,
            ))
            recorded
        }
    }

    /**
     * Re-runs the mirror for the last decision when it failed or fell behind.
     * A null backend can recover an intent but leaves pending backend work explicit.
     */
    fun applyPending(): Outcome = locked { state, journal ->
        val active = mirror
        if (active == null) {
            return@locked Outcome(true, journal.rev,
                pendingApply = AuthorizationsSnapshot.from(state.enabled, state.grants, journal, state.profiles).pendingApply(),
                detail = "no-backend")
        }
        afterCommit(Outcome(false, journal.rev, pendingApply = true),
            SuCodes.SU_TRANSPORT_UNAVAILABLE) {
            val backend = active.backend
            val last = journal.applied.lastOrNull { it.backend == backend }
            if (journal.pendingApplyRev == null && last?.ok == true && last.rev == journal.rev) {
                Outcome(true, journal.rev, detail = "already-synced")
            } else {
                val applied = applyMirror(journal, state)
                applied.copy(ok = !applied.pendingApply)
            }
        }
    }

    // --- internals ---------------------------------------------------------

    /** Runs the mirror and records its watermark; a failing mirror never fails the decision. */
    private fun applyMirror(journal: SuperuserJournal, state: SuperuserStoreState): Outcome {
        val active = mirror
        if (active == null) return Outcome(true, journal.rev,
            pendingApply = AuthorizationsSnapshot.from(state.enabled, state.grants, journal, state.profiles).pendingApply())
        return afterCommit(Outcome(true, journal.rev, pendingApply = true),
            SuCodes.SU_TRANSPORT_UNAVAILABLE) {
            val backend = active.backend
            val snapshot = AuthorizationsSnapshot.from(state.enabled, state.grants, journal, state.profiles)
            val outcome = runCatching { active.apply(snapshot) }
                .getOrElse { MirrorOutcome.failure(describe(it)) }
            val applied = Outcome(true, journal.rev, pendingApply = !outcome.ok, detail = outcome.detail)
            val recorded = afterCommit(applied, SuCodes.SU_JOURNAL_WRITE_FAILED, pendingOnFailure = true) {
                val mark = SuperuserApplied(backend, journal.rev, now(), outcome.ok, outcome.detail)
                writeJournal(journal.withApplied(mark))
                applied
            }
            afterCommit(recorded, SuCodes.SU_AUDIT_WRITE_FAILED) {
                audit(
                    SuperuserAuditRecord(
                        event = "apply", rev = journal.rev, ok = outcome.ok, source = backend,
                        code = if (outcome.ok) SuCodes.ALLOW else SuCodes.SU_TRANSPORT_UNAVAILABLE,
                        detail = recorded.detail,
                    ),
                )
                recorded
            }
        }
    }

    /** Preserve the durable receipt when later synchronization or diagnostics fail. */
    private fun afterCommit(
        outcome: Outcome,
        failureCode: String,
        pendingOnFailure: Boolean = false,
        action: () -> Outcome,
    ): Outcome = try {
        action()
    } catch (error: Throwable) {
        val publication = causes(error).any { it is AuthorizationDurability.PublicationException }
        val failed = if (publication) failure(error, outcome.rev, observe = true) else null
        val detail = failureCode + ":" + (failed?.detail ?: describe(error))
        outcome.copy(
            rev = maxOf(outcome.rev, failed?.rev ?: outcome.rev),
            code = outcome.code ?: failureCode,
            pendingApply = outcome.pendingApply || pendingOnFailure || failed?.pendingApply == true,
            detail = if (outcome.detail.isEmpty()) detail else outcome.detail + " " + detail,
        )
    }

    private fun locked(recoverSwitch: Boolean = true, body: (SuperuserStoreState, SuperuserJournal) -> Outcome): Outcome {
        return try {
            SuperuserJournalStore.acquire(directory).use {
                var knownRev: Long? = null
                try {
                    // Only absence starts legacy history. A read failure aborts before any write.
                    var journal = SuperuserJournalStore.read(journalFile) ?: SuperuserJournal.fresh()
                    knownRev = journal.rev
                    val state = readStore()
                    if (journal.profileRev.keys.map { it.toInt() }.toSet() != state.profiles.keys)
                        throw IOException(SuCodes.SU_STORE_READ_FAILED, IOException("AUTH_STORE_PROFILE_MISSING"))
                    val intent = journal.pendingSwitch
                    if (recoverSwitch && intent != null) {
                        val completed = journal.completedSwitch()
                        val recovered = afterCommit(Outcome(false, intent.rev - 1, pendingApply = true),
                            SuCodes.SU_JOURNAL_WRITE_FAILED) {
                            writeJournal(completed)
                            Outcome(true, completed.rev, pendingApply = true)
                        }
                        if (!recovered.ok) return@use recovered
                        journal = completed
                    }
                    body(state, journal)
                } catch (error: IOException) {
                    // Still holding the transaction lock: observe facts, never retry a mutation.
                    failure(error, knownRev, observe = true)
                }
            }
        } catch (error: IOException) {
            failure(error, null, observe = false)
        } catch (error: Throwable) {
            Outcome(false, revision(), SuCodes.SU_STORE_WRITE_FAILED, detail = describe(error))
        }
    }

    private fun failure(error: Throwable, knownRev: Long?, observe: Boolean): Outcome {
        val publication = causes(error).filterIsInstance<AuthorizationDurability.PublicationException>().firstOrNull()
        var observedRev = knownRev
        var pending = publication?.let { it.published && !it.directorySynced } == true
        val detail = StringBuilder(describe(error))
        if (observe) {
            var journalKnown = false
            val journal = try {
                SuperuserJournalStore.read(journalFile).also {
                    journalKnown = true
                    if (it != null) observedRev = maxOf(observedRev ?: it.rev, it.rev)
                    detail.append(";observedJournal=").append(it?.rev ?: "absent")
                }
            } catch (read: Exception) {
                detail.append(";observedJournal=unknown:").append(describe(read))
                null
            }
            val state = try {
                store.load().also {
                    detail.append(";observedStore=readable,enabled=").append(it.enabled)
                        .append(",grants=").append(it.grants.size)
                }
            } catch (read: Exception) {
                detail.append(";observedStore=unknown:").append(describe(read))
                null
            }
            // Only pending diagnostics are projected here; an unreadable store is never an authority snapshot.
            pending = pending || if (journalKnown) {
                journal?.let { it.pendingSwitch != null || it.pendingApplyRev != null ||
                    (it.applied.asReversed().maxByOrNull { mark -> mark.rev }?.let { mark -> !mark.ok || mark.rev < it.rev } ?: false) } ?: false
            } else publication?.published == true
        }
        detail.append(";knownRev=").append(observedRev ?: "unknown").append(";pendingApply=").append(pending)
        val code = error.message?.takeIf { it.startsWith("SU_") } ?: SuCodes.SU_STORE_WRITE_FAILED
        return Outcome(false, observedRev ?: 0L, code, pendingApply = pending, detail = detail.toString())
    }

    private fun readStore(): SuperuserStoreState = try {
        store.load()
    } catch (error: IOException) {
        throw IOException(SuCodes.SU_STORE_READ_FAILED, error)
    }

    private fun writeStore(journal: SuperuserJournal, state: SuperuserStoreState) {
        try {
            store.save(state)
        } catch (error: IOException) {
            // The journal is already ahead; report the store's own failure so the caller
            // does not claim success. A revoke stays in force, a grant stays ineffective.
            throw IOException(SuCodes.SU_STORE_WRITE_FAILED, error)
        }
    }

    private fun writeJournal(journal: SuperuserJournal) {
        try {
            SuperuserJournalStore.write(journalFile, journal)
        } catch (error: IOException) {
            throw IOException(SuCodes.SU_JOURNAL_WRITE_FAILED, error)
        }
    }

    private fun revision(): Long = SuperuserJournalStore.revision(journalFile)

    private fun requireIdentity(identity: ApplicationIdentity): ApplicationIdentity {
        // The constructor already enforces the domain, a single package, non-empty
        // signers and a positive install time; this only re-states the intent.
        if (!ManagerSuperuserPolicy.validUserDomain(identity.uid)) {
            throw IllegalArgumentException(SuCodes.AUTH_IDENTITY_UNAVAILABLE)
        }
        return identity
    }

    private fun causes(error: Throwable): List<Throwable> {
        val seen = IdentityHashMap<Throwable, Boolean>()
        val result = ArrayList<Throwable>(8)
        var current: Throwable? = error
        while (current != null && result.size < 8 && seen.put(current, true) == null) {
            result.add(current)
            current = current.cause
        }
        return result
    }

    private fun describe(error: Throwable): String = causes(error).joinToString(" <- ") {
        it.javaClass.simpleName.take(80) + ":" + (it.message ?: "").take(512)
    }
}

/** One audit line produced by the transaction; formatted by `SuAuditLog`. */
data class SuperuserAuditRecord(
    val event: String,
    val uid: Int? = null,
    val packageName: String? = null,
    val rev: Long = 0,
    val ok: Boolean = true,
    val source: String = "manager",
    val code: String? = null,
    val detail: String = "",
)

/** Java-friendly construction: `AuthorizationPolicy` keeps its existing constructor shape. */
object SuperuserTransactions {
    /**
     * The transaction for a `authorizations.bin` path: the journal, lock and mirror live
     * in the same directory, which is the root-only store directory.
     */
    @JvmStatic
    @JvmOverloads
    fun local(
        storeFile: Path,
        mirror: SuperuserMirror? = null,
        audit: (SuperuserAuditRecord) -> Unit = {},
    ): SuperuserTransaction {
        val parent = storeFile.toAbsolutePath().parent ?: throw IllegalArgumentException("SU_STORE_PATH")
        return SuperuserTransaction(
            directory = parent.toFile(),
            store = FileSuperuserStorePort(storeFile),
            journalFile = File(parent.toFile(), SuperuserJournalStore.FILE),
            mirror = mirror,
            audit = audit,
        )
    }
}
