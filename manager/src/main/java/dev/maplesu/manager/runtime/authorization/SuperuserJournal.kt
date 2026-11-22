package dev.maplesu.manager.runtime.authorization

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File
import java.io.ByteArrayOutputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.NoSuchFileException
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.BasicFileAttributes
import java.util.concurrent.locks.ReentrantLock

@Serializable
data class SuperuserSwitchIntent(
    val version: Int = 1,
    val target: Boolean,
    val rev: Long,
)

/**
 * The monotonic superuser journal that lives next to `authorizations.bin`
 * (design §1.1).
 *
 * <p>Why a second file at all. `authorizations.bin` is Normal's already-shipped format:
 * it holds the decision (`uid + identity + enabled`) but it has no revision, no
 * tombstone and no "already mirrored to the kernel" watermark. Those three are exactly
 * what "revoke never resurrects" and "the KSU mirror is behind, not the decision" need,
 * so they live in a sibling JSON file in the same root-only directory instead of
 * changing a binary format that is already on devices.
 *
 * <p>Crash safety (design §1.1, last paragraph): a denial tombstone is written before
 * the binary store. Grant/import clears that denial only in its final journal after
 * the binary commit, at the same prepared revision. Thus an old binary record left by
 * a failed revoke is not restored by another failed grant. The previous revision is kept as
 * `superuser-journal.prev` for rollback and reconciliation.
 */
@Serializable
data class SuperuserJournal(
    val schema: Int = SCHEMA,
    /** Monotonic; +1 on every decision (grant / revoke / switch / import). */
    val rev: Long = 0,
    /** uid -> revision of that uid's **last grant**. A revoke never writes here. */
    val uidRev: Map<String, Long> = emptyMap(),
    val tombs: List<SuperuserTomb> = emptyList(),
    val applied: List<SuperuserApplied> = emptyList(),
    /** Legacy source -> revision at which it was imported (idempotent one-shot import). */
    val migrated: Map<String, Long> = emptyMap(),
    val unresolved: List<SuperuserUnresolved> = emptyList(),
    val pendingSwitch: SuperuserSwitchIntent? = null,
    val pendingApplyRev: Long? = null,
    val profileRev: Map<String, Long> = emptyMap(),
) {
    fun uidRevOf(uid: Int): Long = uidRev[uid.toString()] ?: 0L

    fun tombRev(uid: Int): Long =
        tombs.asSequence().filter { it.uid == uid }.maxOfOrNull { it.rev } ?: 0L

    /**
     * The design's revocation predicate. A grant at rev 7 after a revoke at rev 6 is
     * allowed (`7 > 6`); the reverse is refused, so a revoke cannot be undone by an
     * older snapshot or by a store record that survived a crash.
     */
    fun revoked(uid: Int): Boolean = tombRev(uid) > uidRevOf(uid)

    /** Explicit new grant: the `uidRev` watermark moves and that uid's tombstone is cleared. */
    fun granted(uid: Int, at: Long): SuperuserJournal {
        val next = rev + 1
        return copy(
            rev = next,
            pendingApplyRev = next,
            uidRev = uidRev + (uid.toString() to next),
            tombs = tombs.filterNot { it.uid == uid },
        )
    }

    /**
     * Revocation. The tombstone carries the new revision and `uidRev` is **not** touched:
     * if it were, the tombstone and the grant watermark would be equal and the revoke
     * would fail its own `tombRev > uidRev` test.
     */
    fun revoked(uid: Int, packageName: String?, at: Long): SuperuserJournal {
        val next = rev + 1
        val tomb = SuperuserTomb(uid = uid, packageName = packageName.orEmpty(), rev = next, at = at)
        return copy(rev = next, pendingApplyRev = next,
            tombs = (tombs.filterNot { it.uid == uid } + tomb))
    }

    /** A revision with no uid effect (global switch, mirror watermarks). */
    fun touched(): SuperuserJournal = copy(rev = rev + 1, pendingApplyRev = rev + 1)

    fun preparedSwitch(target: Boolean): SuperuserJournal {
        check(pendingSwitch == null && rev < Long.MAX_VALUE)
        val next = touched()
        return next.copy(pendingSwitch = SuperuserSwitchIntent(target = target, rev = next.rev))
    }

    /** The bin is authoritative; recovery never replays a requested enable. */
    fun completedSwitch(): SuperuserJournal = copy(pendingSwitch = null)

    fun withProfileRevision(uid: Int, present: Boolean): SuperuserJournal = copy(
        profileRev = if (present) profileRev + (uid.toString() to rev) else profileRev - uid.toString(),
    )

    /** Replace the backend's watermark; keeps at most 32 marks so the file stays bounded. */
    fun withApplied(mark: SuperuserApplied): SuperuserJournal =
        copy(applied = (applied + mark).takeLast(APPLIED_LIMIT),
            pendingApplyRev = if (pendingSwitch == null && mark.ok && mark.rev == rev) null
                else pendingApplyRev)

    fun withMigrated(source: String, atRev: Long): SuperuserJournal =
        copy(migrated = migrated + (source to atRev))

    fun withUnresolved(entries: List<SuperuserUnresolved>): SuperuserJournal =
        copy(unresolved = (unresolved + entries).distinct().takeLast(UNRESOLVED_LIMIT))

    companion object {
        const val SCHEMA = 1
        const val APPLIED_LIMIT = 32
        const val UNRESOLVED_LIMIT = 200
        const val MAX_BYTES = 512 * 1024

        @JvmStatic fun fresh(): SuperuserJournal = SuperuserJournal()
    }
}

/**
 * Reads and writes [SuperuserJournal] atomically.
 *
 * <p>[read] returns null only when the journal is absent from an existing directory.
 * A malformed or unreadable journal throws: it may contain a revocation newer than
 * the binary store, so treating it as an empty history could restore an old grant.
 */
object SuperuserJournalStore {
    const val FILE = "superuser-journal.json"
    const val PREV = "superuser-journal.prev"
    const val LOCK = "superuser-journal.lock"

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        explicitNulls = false
    }

    @JvmStatic
    @Throws(IOException::class)
    fun read(file: File): SuperuserJournal? {
        return try {
            val attributes = try {
                Files.readAttributes(file.toPath(), BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            } catch (missing: NoSuchFileException) {
                if (file.absoluteFile.parentFile?.isDirectory == true) return null
                throw missing
            }
            if (!attributes.isRegularFile || attributes.size() > SuperuserJournal.MAX_BYTES) {
                throw IOException("Invalid journal file or size")
            }
            val bytes = ByteArrayOutputStream()
            file.inputStream().use { input ->
                val buffer = ByteArray(4096)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (bytes.size() + count > SuperuserJournal.MAX_BYTES) {
                        throw IOException("Journal exceeds size limit")
                    }
                    bytes.write(buffer, 0, count)
                }
            }
            val parsed = json.decodeFromString(SuperuserJournal.serializer(), bytes.toString(Charsets.UTF_8.name()))
            if (parsed.schema != SuperuserJournal.SCHEMA || parsed.rev < 0) {
                throw IOException("Invalid journal schema or revision")
            }
            val intent = parsed.pendingSwitch
            if (intent != null && (intent.version != 1 || intent.rev <= 0 ||
                    intent.rev != parsed.rev || parsed.pendingApplyRev != intent.rev)) {
                throw IOException("Invalid switch intent")
            }
            if (parsed.pendingApplyRev?.let { it <= 0 || it > parsed.rev } == true) {
                throw IOException("Invalid pending apply revision")
            }
            if (parsed.profileRev.any { (key, value) ->
                    key.toIntOrNull()?.let { it.toString() != key || !ManagerSuperuserPolicy.validUserDomain(it) } != false ||
                        value <= 0 || value > parsed.rev }) throw IOException("Invalid profile revision")
            parsed
        } catch (error: Exception) {
            throw IOException("SU_JOURNAL_READ_FAILED", error)
        }
    }

    /** Atomically replaces [file]; the previous content is kept as `superuser-journal.prev`. */
    @JvmStatic
    @Throws(IOException::class)
    fun write(file: File, journal: SuperuserJournal) {
        val directory = file.absoluteFile.parentFile
            ?: throw IOException("SU_JOURNAL_DIRECTORY_MISSING")
        // The root-only store directory is created and validated by
        // RootAuthorizationStore; re-creating it here would turn a deleted (or
        // mis-owned) directory into a successful write, which is exactly the
        // "failed persistence published a grant" defect the legacy test covers.
        if (!directory.isDirectory) throw IOException("SU_JOURNAL_DIRECTORY_MISSING")
        val bytes = json.encodeToString(SuperuserJournal.serializer(), journal).toByteArray(Charsets.UTF_8)
        if (bytes.size > SuperuserJournal.MAX_BYTES) throw IOException("SU_JOURNAL_TOO_LARGE")
        val staging = FileAuthorizationStore.createTemporary(directory.toPath(), "superuser-journal-").toFile()
        try {
            FileOutputStream(staging).use { output ->
                output.write(bytes)
                output.fd.sync()
            }
            keepPrevious(file, directory)
            AuthorizationDurability.atomicReplace(staging.toPath(), file.toPath())
        } finally {
            if (staging.exists()) staging.delete()
        }
    }

    /** Used by the Java `AuthorizationPolicy` facade: the one question it needs answered. */
    @JvmStatic
    @Throws(IOException::class)
    fun revoked(file: File, uid: Int): Boolean = read(file)?.revoked(uid) ?: false

    /** Diagnostic only; a failed read is never used as an authorization snapshot. */
    @JvmStatic
    fun revision(file: File): Long = try { read(file)?.rev ?: 0L } catch (_: IOException) { 0L }

    private fun keepPrevious(file: File, directory: File) {
        if (!file.isFile) return
        val previous = File(directory, PREV)
        runCatching {
            Files.copy(
                file.toPath(), previous.toPath(),
                StandardCopyOption.REPLACE_EXISTING,
            )
        }
    }

    // FileChannel locks overlap within one JVM rather than waiting. This process
    // lock covers only the existing slow authority transaction/commit path.
    private val processLock = ReentrantLock()

    /**
     * Serializes transactions. The lock is a sibling file so two one-shot root tools
     * (a grant and a revoke racing from the UI) cannot interleave their revisions.
     */
    @JvmStatic
    @Throws(IOException::class)
    fun acquire(directory: File): CloseableLock {
        try {
            processLock.lockInterruptibly()
        } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            throw IOException("SU_JOURNAL_LOCK_INTERRUPTED", error)
        }
        try {
            if (!directory.isDirectory) throw IOException("SU_JOURNAL_DIRECTORY_MISSING")
            val file = RandomAccessFile(File(directory, LOCK), "rw")
            val channel = file.channel
            val lock = try {
                channel.lock()
            } catch (error: Throwable) {
                runCatching { channel.close() }
                runCatching { file.close() }
                throw IOException("SU_JOURNAL_LOCK_FAILED", error)
            }
            return CloseableLock(file, channel, lock, processLock)
        } catch (error: Throwable) {
            processLock.unlock()
            throw error
        }
    }

    /** A held transaction lock; closing releases it and removes nothing. */
    class CloseableLock @JvmOverloads constructor(
        private val file: RandomAccessFile,
        private val channel: FileChannel,
        private val lock: FileLock,
        private val processLock: ReentrantLock? = null,
    ) : java.io.Closeable {
        private var closed = false
        @Synchronized override fun close() {
            if (closed) return
            closed = true
            try {
                runCatching { lock.release() }
                runCatching { channel.close() }
                runCatching { file.close() }
            } finally {
                processLock?.unlock()
            }
        }
    }
}
