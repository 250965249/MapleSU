package dev.maplesu.manager.runtime.authorization

import dev.maplesu.manager.runtime.SuAuditEvent
import dev.maplesu.manager.runtime.SuAuditLog
import java.io.File
import java.nio.file.Path

/**
 * The root-side operations of the one authority (design §3.2).
 *
 * <p>It runs as a short-lived `app_process` behind whichever transport the mode has
 * (`DirectRoot` on Normal/Lite, the L3 gate child on Ultra). Exactly one operation per
 * process; the answer is one line so the caller cannot mistake a partial run for success.
 *
 * <p>**Seccomp-safe since 2026-10-31.** This process is a fork of the App, so it
 * inherits the App's seccomp filter, and no code here can lift it. The old
 * `systemContext()` helper called `ActivityThread.systemMain()`, which creates
 * `Resources`; that reaches `createIdmap` and its `ExecuteBinary` child, whose `setgid`
 * is trapped with `SIGSYS` (syscall 144) - the crash this tool kept producing for
 * `snapshot`, `grant`, `revoke`, `set-enabled` and `migrate`. The tool therefore never
 * creates a `Context`/`Resources` now:
 *
 *  - package identities come from the system binder through
 *    [SystemPackageSnapshotSource] (`IPackageManager`), not from a `PackageManager`
 *    owned by a `Context`;
 *  - the audit path is passed by the caller, instead of being derived from
 *    `context.createDeviceProtectedStorageContext()`;
 *  - `status` reports the process's own `Seccomp:` mode so the device evidence shows
 *    that the tool still runs under the App's filter and simply no longer calls a
 *    syscall it forbids.
 *
 * <p>What lives here and nowhere else: the transaction (journal -> bin -> applied), the
 * audit lines that belong to a decision, and the snapshot the app process cannot read for
 * itself. The *policy* is not implemented here - it is
 * [dev.maplesu.manager.runtime.authorization.ManagerSuperuserPolicy], shared with the
 * endpoints.
 */
internal object SuperuserOps {
    /**
     * @param managerUid the Manager's full Android UID; it also selects the Android user
     *   for the package-service reads.
     * @param legacy the shipped app-private store to import once.
     * @param auditFile the app's device-protected `su-audit.log`; an explicit path
     *   because this process has no `Context`.
     * @return the payload printed after `OK`; throws for a refused operation (the caller
     *   prints `ERR` and the Manager sees a failure, never a fabricated success).
     */
    @Throws(Exception::class)
    fun run(
        managerUid: Int,
        legacy: Path,
        auditFile: Path,
        operation: String,
        args: List<String>,
    ): String {
        val identities = PackageIdentityReader(SystemPackageSnapshotSource(managerUid))
        // Opening through RootAuthorizationStore is what validates (and creates) the
        // root-only directory and performs the shipped app-private legacy import. Doing
        // it first means every later write happens in a directory whose owner and mode
        // have already been checked.
        if (operation == "initialize-installation" && args.isEmpty())
            RootAuthorizationStore.openForInstallation(managerUid, legacy, identities)
        else RootAuthorizationStore.open(managerUid, legacy, identities)
        val directory = SuperuserPaths.directory(managerUid)
        val journalFile = File(directory, SuperuserJournalStore.FILE)
        val storePath = SuperuserPaths.store(managerUid)
        val auditLog = auditFile.toFile()

        fun transaction(): SuperuserTransaction = SuperuserTransaction(
            directory = directory,
            store = FileSuperuserStorePort(storePath),
            journalFile = journalFile,
            now = System::currentTimeMillis,
            audit = { record -> audit(auditLog, record) },
        )

        return when {
            operation == "current-identities" && args.isEmpty() -> {
                val before = AuthorizationsSnapshot.load(storePath, journalFile)
                check(!before.corrupt) { "AUTHORITY_UNREADABLE" }
                val observed = currentIdentityObservation(before, identities::read)
                check(AuthorizationsSnapshot.load(storePath, journalFile) == before) { "SU_AUTH_REVISION_CHANGED" }
                "identities=" + SuperuserWire.encode(observed)
            }
            operation == "initialize-installation" && args.isEmpty() -> {
                val snapshot = AuthorizationsSnapshot.load(storePath, journalFile)
                val decision = ManagerSuperuserPolicy.decide(snapshot, managerUid, identities.read(managerUid))
                outcome(SuperuserTransaction.Outcome(decision.allowed, snapshot.rev,
                    code = decision.reason.takeUnless { decision.allowed }, pendingApply = snapshot.pendingApply(),
                    detail = "installation-authority-verified"))
            }
            operation == "snapshot" -> snapshotLine(storePath, journalFile, transaction())
            operation == "status" -> statusLine(storePath, journalFile)
            operation == "enabled" -> enabled(storePath, journalFile).toString()
            operation == "count" -> currentGrantCount(identities, storePath, journalFile).toString()
            operation == "has" && args.size == 1 ->
                hasCurrentGrant(identities, storePath, journalFile, args[0].toInt()).toString()
            operation == "grant" && args.size == 1 -> {
                val uid = args[0].toInt()
                val identity = identities.read(uid)
                    ?: throw IllegalStateException(SuCodes.AUTH_IDENTITY_UNAVAILABLE)
                outcome(transaction().grant(identity, origin = "manager"))
            }
            operation == "save-profile" && args.size == 1 -> {
                val profile = SuperuserProfileWire.decode(args[0])
                val identity = identities.read(profile.currentUid)
                    ?: throw IllegalStateException(SuCodes.AUTH_IDENTITY_UNAVAILABLE)
                outcome(transaction().saveProfile(identity, profile, origin = "manager"))
            }
            operation == "revoke" && args.size == 1 -> {
                val uid = args[0].toInt()
                val packageName = identities.packageNameForUid(uid)
                outcome(transaction().revoke(uid, packageName, origin = "manager"))
            }
            operation.startsWith("set-enabled:") -> {
                val enabled = operation.substringAfter(':').toBooleanStrictOrNull()
                    ?: throw IllegalArgumentException("AUTH_TOOL_ARGUMENTS")
                val result = transaction().setEnabled(enabled, origin = "manager")
                if (!result.ok) errorLine(result)
                else "enabled=$enabled " + outcome(result)
            }
            operation == "migrate" && args.size == 1 -> {
                val plan = SuperuserWire.decodePlan(args[0])
                    ?: throw IllegalArgumentException("SU_MIGRATION_PLAN_INVALID")
                outcome(transaction().import(plan, origin = "migrate"))
            }
            operation == "mark-applied" && args.size == 4 -> {
                val backend = args[0]
                val rev = args[1].toLongOrNull()?.takeIf { it >= 0 }
                    ?: throw IllegalArgumentException("AUTH_TOOL_ARGUMENTS")
                val ok = args[2] == "1"
                val detail = runCatching {
                    String(java.util.Base64.getDecoder().decode(args[3]), Charsets.UTF_8)
                }.getOrDefault("")
                outcome(transaction().markApplied(backend, rev, MirrorOutcome(ok, detail)))
            }
            else -> throw IllegalArgumentException("AUTH_TOOL_UNKNOWN_OPERATION")
        }
    }

    // --- reads -------------------------------------------------------------

    /** Fresh root-side package facts, scoped to one authority revision; never a permission record. */
    internal fun currentIdentityObservation(snapshot: AuthorizationSnapshot,
                                            read: (Int) -> ApplicationIdentity?): AuthorizationSnapshot {
        check(!snapshot.corrupt) { "AUTHORITY_UNREADABLE" }
        val current = snapshot.grants.keys.sorted().mapNotNull { uid ->
            read(uid)?.takeIf { ManagerSuperuserPolicy.decide(snapshot, uid, it).allowed }?.let { uid to it }
        }.toMap()
        return AuthorizationSnapshot(false, current, rev = snapshot.rev)
    }

    private fun snapshotLine(store: Path, journalFile: File, transaction: SuperuserTransaction): String {
        var snapshot = AuthorizationsSnapshot.load(store, journalFile)
        if (snapshot.switchPending) {
            val recovered = transaction.applyPending()
            if (!recovered.ok) errorLine(recovered)
            snapshot = AuthorizationsSnapshot.load(store, journalFile)
        }
        val granted = snapshot.grants.keys.sorted()
        return buildString {
            append("enabled=").append(if (snapshot.enabled) 1 else 0)
            append(" count=").append(granted.size)
            append(" rev=").append(snapshot.rev)
            append(" uids=").append(granted.joinToString(","))
            append(" pending=").append(if (snapshot.pendingApply()) 1 else 0)
            append(" corrupt=").append(if (snapshot.corrupt) 1 else 0)
            append(" wire=").append(SuperuserWire.encode(snapshot))
        }
    }

    private fun statusLine(store: Path, journalFile: File): String {
        val snapshot = AuthorizationsSnapshot.load(store, journalFile)
        return "enabled=" + (if (snapshot.enabled) 1 else 0) +
            " rev=" + snapshot.rev +
            " pending=" + (if (snapshot.pendingApply()) 1 else 0) +
            " migrated=" + snapshot.migrated.entries.sortedBy { it.key }
                .joinToString(",") { it.key + ":" + it.value } +
            " unresolved=" + snapshot.unresolved.size +
            // Evidence only: the tool is expected to run with Seccomp=2 inherited from
            // the App. What changed is that it no longer calls a syscall the filter
            // traps, not that the filter disappeared.
            " seccomp=" + seccompMode()
    }

    private fun enabled(store: Path, journalFile: File): Boolean =
        AuthorizationsSnapshot.load(store, journalFile).enabled

    /**
     * The list/profile question `DirectPolicy.hasGrant` asks. A persisted record alone is
     * not "granted": the same decision function the endpoints use answers, so the
     * tombstone, the master switch and the current install identity are all applied -
     * there is no second rule here.
     */
    private fun hasCurrentGrant(
        identities: PackageIdentityReader,
        store: Path,
        journalFile: File,
        uid: Int,
    ): Boolean {
        val snapshot = AuthorizationsSnapshot.load(store, journalFile)
        val identity = runCatching { identities.read(uid) }.getOrNull()
        return ManagerSuperuserPolicy.decide(snapshot, uid, identity).allowed
    }

    private fun currentGrantCount(
        identities: PackageIdentityReader,
        store: Path,
        journalFile: File,
    ): Int {
        val snapshot = AuthorizationsSnapshot.load(store, journalFile)
        if (snapshot.corrupt) return 0
        return snapshot.grants.keys.count { uid ->
            val identity = runCatching { identities.read(uid) }.getOrNull()
            ManagerSuperuserPolicy.decide(snapshot, uid, identity).allowed
        }
    }

    // --- writes ------------------------------------------------------------

    private fun outcome(result: SuperuserTransaction.Outcome): String =
        if (!result.ok) errorLine(result)
        else "rev=" + result.rev + " pending=" + (if (result.pendingApply) 1 else 0) +
            " detail=" + escape(result.detail) + " code=" + (result.code ?: "OK")

    /** Only this typed transaction failure may publish a structured ERR receipt. */
    internal class TransactionFailure(val outcome: SuperuserTransaction.Outcome) :
        IllegalStateException(outcome.code ?: SuCodes.SU_STORE_WRITE_FAILED)

    private fun errorLine(result: SuperuserTransaction.Outcome): Nothing =
        throw TransactionFailure(result)

    private fun audit(file: File, record: SuperuserAuditRecord) {
        val event = SuAuditEvent(
            backend = record.source.takeIf { it == "normal" || it == "hook" || it == "lease" }
                ?: BACKEND_STORE,
            event = record.event,
            callerUid = record.uid,
            callerPackages = listOfNotNull(record.packageName?.takeIf { it.isNotEmpty() }),
            decision = if (record.ok) "allow" else "deny",
            reason = record.code,
            rev = record.rev,
            source = record.source,
        )
        // Audit is best-effort by design: a write failure must never change the decision.
        SuAuditLog.write(file, event)
    }

    private fun escape(value: String): String =
        if (value.isEmpty()) "-" else value.replace('\n', ' ').replace(' ', '_')

    /**
     * The process's inherited seccomp mode, read from `/proc/self/status`.
     *
     * <p>`0` is off, `2` is filter mode; `-1` means the read failed. This is
     * observational only - it never changes an operation - and it is the field the
     * device acceptance reads to prove the tool still runs under the App's filter while
     * no longer dying on it.
     */
    private fun seccompMode(): Int = runCatching {
        File("/proc/self/status").useLines { lines ->
            lines.firstOrNull { it.startsWith("Seccomp:") }
                ?.substringAfter(':')?.trim()?.toIntOrNull()
        } ?: -1
    }.getOrDefault(-1)

    private const val BACKEND_STORE = "store"
}
