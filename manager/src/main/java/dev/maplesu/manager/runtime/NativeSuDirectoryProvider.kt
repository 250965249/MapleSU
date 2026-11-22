package dev.maplesu.manager.runtime

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.os.Process
import dev.maplesu.manager.jailbreak.Derived
import dev.maplesu.manager.jailbreak.HookAttestServer
import dev.maplesu.manager.jailbreak.HookWorker
import dev.maplesu.manager.jailbreak.JailbreakExecutor
import dev.maplesu.manager.jailbreak.JailbreakLeaseStore
import dev.maplesu.manager.jailbreak.JailbreakRequest
import dev.maplesu.manager.jailbreak.JailbreakStatus
import java.io.File
import java.io.IOException

/** Private directory; public discovery returns only the original restricted Root Binder. */
class NativeSuDirectoryProvider : ContentProvider() {
    override fun onCreate(): Boolean {
        /*
         * The attempt can outlive the process that started it: the exploit hijacks the
         * runtime for the handover, and the instrumentation process died at exactly that
         * point twice with no Java stack. That leaves the status at
         * ROOT_WORKER_OBSERVED with the claim unrun, so DAEMON_READY stayed unreachable
         * even though the kernel side had finished.
         *
         * The status file and the worker's own record both survive a process death, so a
         * later start finishes the claim. Everything the claim depends on is re-checked
         * there (attempt, boot, restored enforcement, attestation evidence); this only
         * decides *when* to try, never *whether* it is allowed.
         */
        val app = context
        if (app != null) {
            /*
             * Design §5.2: `StageMark.LINE_SINK` was declared but never assigned anywhere
             * in the repository, so every `StageMark.outputLine(...)` - including the
             * `su:start:denied:*` lines of the lease endpoint - was a no-op. This process
             * hosts both endpoints, so it is the one place that has to install it.
             */
            StageMark.LINE_SINK = { line ->
                SuAuditLog.append(
                    app,
                    SuAuditEvent(backend = "stage", event = "stage", detail = line),
                )
            }
            Thread({
                runCatching {
                    var status = JailbreakStatus.read(app) ?: return@runCatching
                    val attemptId = status.attemptId ?: return@runCatching
                    // Entry trace: without it there was no way to tell "the branch never
                    // ran" from "it ran and the write failed".
                    android.util.Log.w("MapleSUSuDir", "resume: stage=" + status.stage +
                        " boot=" + status.bootId?.take(8) + " enforcing=" +
                        status.restoreEnforcing + " attempt=" + attemptId.take(8))
                    if (status.bootId == null ||
                        status.bootId != dev.maplesu.manager.jailbreak.DirtyfragAttempt.readBootId()
                    ) {
                        return@runCatching
                    }
                    /*
                     * §6.5/T5 reprove: a soft reboot keeps the L3 carrier but kills every
                     * userspace process. The record still says DAEMON_READY for this boot,
                     * so this process only re-publishes the restricted su endpoint and
                     * re-proves the carrier - it never reruns the one-shot exploit, which
                     * the admission guards would refuse anyway.
                     */
                    if (status.stage in setOf(JailbreakStatus.STAGE_DAEMON_READY,
                            JailbreakStatus.STAGE_CARRIER_PROVEN) &&
                        status.rootBackend == JailbreakRequest.BACKEND_HOOK
                    ) {
                        val gate = SuGate.read(app, status.attemptId, status.bootId)
                        if (gate.armed) {
                            val request = JailbreakRequest(
                                method = status.method, attemptId = attemptId,
                                bootId = status.bootId,
                                rootBackend = JailbreakRequest.BACKEND_HOOK)
                            val publication = publishConfirmedHook(recordCarrierProof(app)) {
                                publishHookSu(app, request)
                            }
                            if (!publication.ok) return@runCatching
                            android.util.Log.w("MapleSUSuDir",
                                "resume: republished ready hook session")
                            return@runCatching
                        }
                    }
                    /*
                     * The process can die before it publishes the kernel's own verdict:
                     * the helper writes maplesu-hook.json and exits, the instrumentation
                     * process is gone, and the status stays at PROVIDER_RUNNING even
                     * though the handover succeeded. Reconcile from that file - it is
                     * the helper's own record, root-owned, and HookEvidence applies the
                     * same refusal rules the executor would have applied.
                     */
                    /*
                     * Also run when the stage was reconciled by an earlier build that
                     * did not copy the restore fields: the evidence is the same source,
                     * and a status that says "observed" without a restored value is not
                     * claimable.
                     */
                    android.util.Log.w("MapleSUSuDir", "resume: same boot, evaluating reconcile")
                    /*
                     * `JAILBREAK_OWNER_EXITED` is not "no attempt happened": it says the
                     * process that started the attempt is gone, which is precisely the
                     * case where the kernel may have finished and left its record. The
                     * evidence checks below decide whether it did.
                     */
                    val ownerExited = status.stage == JailbreakStatus.STAGE_EXPIRED &&
                        status.failure == "JAILBREAK_OWNER_EXITED"
                    if (status.stage == JailbreakStatus.STAGE_PROVIDER_RUNNING || ownerExited ||
                        (status.stage == JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED &&
                            status.restoreEnforcing == null)
                    ) {
                        val merged = dev.maplesu.manager.jailbreak.HookEvidence.read(
                            dev.maplesu.manager.jailbreak.DirtyfragAttempt.hookEvidence(app))
                        if (merged == null ||
                            dev.maplesu.manager.jailbreak.HookEvidence.refusalToken(merged) != null
                        ) {
                            android.util.Log.w("MapleSUSuDir",
                                "no acceptable hook evidence to reconcile yet")
                            return@runCatching
                        }
                        /*
                         * The helper's JSON leaves the restored enforcement unset (only
                         * its log line carries it), so the value comes from the worker's
                         * own record, which is root-owned and checked for boot, attempt,
                         * uid 0, kernel domain and `enforcingFinal == 1`.
                         */
                        val workerEvidence = dev.maplesu.manager.jailbreak.HookAttestServer
                            .read(app, attemptId, status.bootId)
                        status = status.copy(
                            stage = JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED,
                            /*
                             * Take ownership: the record was just downgraded to EXPIRED
                             * because its owner pid is gone, and the claim re-reads it.
                             * A reconciled attempt is owned by the process that
                             * reconciled it.
                             */
                            ownerPid = android.os.Process.myPid(),
                            // The EXPIRED copy carries JAILBREAK_OWNER_EXITED; the claim
                            // refuses any record with a failure, and that reason is now
                            // answered by the reconciliation itself.
                            failure = null,
                            message = "reconciled from the helper's own record after the " +
                                "attempt process died",
                            restoreState = merged.restoreState,
                            restoreOrigin = merged.origin,
                            // The claim refuses unless this is exactly 1; leaving it
                            // null made a reconciled attempt unclaimable.
                            restoreEnforcing = merged.enforcing
                                ?: workerEvidence?.enforcing,
                            restoreFailures = merged.failures,
                            updatedAtMillis = System.currentTimeMillis(),
                        )
                        status.write(app)
                        android.util.Log.w("MapleSUSuDir", "status reconciled: " + merged.verdict)
                    }
                    if (status.stage != JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED) {
                        return@runCatching
                    }
                    if (status.rootBackend != JailbreakRequest.BACKEND_HOOK) return@runCatching
                    /*
                     * Same boot only. After a reboot the module is gone, so evidence from
                     * the previous boot would claim a root that no longer exists - W3 is
                     * explicitly a fresh attempt, not a resumption.
                     */
                    val bootNow = dev.maplesu.manager.jailbreak.DirtyfragAttempt.readBootId()
                    if (status.bootId == null || status.bootId != bootNow) {
                        return@runCatching
                    }
                    val request = JailbreakRequest(
                        method = status.method,
                        attemptId = attemptId,
                        bootId = status.bootId,
                        rootBackend = JailbreakRequest.BACKEND_HOOK,
                    )
                    val claim = claimHookDaemonReady(app, request)
                    // M3: the outcome is a record, not an exception - say exactly what it
                    // was, including which evidence the claim had (M4).
                    android.util.Log.w("MapleSUSuDir", "pending hook claim: stage=" +
                        claim.stage + " failure=" + claim.failure +
                        " source=" + claim.attestationSource)
                    /*
                     * Design §2.2 item 2: a resumed attempt must publish the restricted su
                     * entry too. Without this, an attempt that reached DAEMON_READY through
                     * the resume path answered third-party binds with "not published" for
                     * the rest of the boot.
                     */
                    publishConfirmedHook(claim) { publishHookSu(app, request) }
                        .failure?.let { android.util.Log.w("MapleSUSuDir", "pending hook publication: $it") }
                }.onFailure {
                    // No evidence yet (or the window is still open): leave the status
                    // where it is and say why, instead of failing a start.
                    android.util.Log.w("MapleSUSuDir", "pending hook claim skipped: " + it)
                }
            }, "maplesu-hook-resume").start()
        }
        return true
    }

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        val caller = Binder.getCallingUid()
        val app = requireNotNull(context)
        if (method == "refreshSuDiscovery") {
            check(caller == app.applicationInfo.uid) { "SU_DIRECTORY_MANAGER_ONLY" }
            NativeSuAdmission.accept(extras?.getString("snapshot")?.let {
                dev.maplesu.manager.runtime.authorization.SuperuserWire.decode(it)
            })
            return Bundle()
        }
        if (method == "prepare") {
            check(caller == app.applicationInfo.uid) { "SU_DIRECTORY_MANAGER_ONLY" }
            // S12: escalate happened before the single-threaded directory worker,
            // so concurrent binder calls could start several attempts over the
            // same lease store and fixed files. One attempt at a time, explicit BUSY.
            check(preparing.compareAndSet(false, true)) { "SU_DIRECTORY_BUSY" }
            // Only an attempt-bearing prepare starts a new trace: a later
            // request-less call must not erase the evidence of this attempt.
            if (extras?.getString("jailbreak") != null) StageMark.reset(app)
            StageMark.mark(app, "prepare:enter")
            val token = Binder.clearCallingIdentity()
            try {
                // A jailbreak request runs its provider here, in the process that
                // owns the trusted launcher, and refuses the normal-mode fallback:
                // the selected mode owns this attempt's executor.
                val jailbreak = extras?.getString("jailbreak")
                val attempt = extras?.getString("attempt")
                val boot = extras?.getString("boot")
                // Step-4 (item 7/MF-1): the backend has to travel with the request. When
                // this call dropped it, `request.rootBackend` was always null in here and
                // the hook branch below could never run - the DAEMON_READY write point was
                // unreachable no matter what the caller asked for.
                val backend = extras?.getString("rootBackend")
                val request = jailbreak?.let { method ->
                    if (attempt.isNullOrBlank()) throw IllegalStateException("SU_DIRECTORY_ATTEMPT_MISSING")
                    val built = JailbreakRequest.of(method, attempt, backend)
                    if (boot != null && built.bootId != null && boot != built.bootId)
                        throw IllegalStateException("SU_DIRECTORY_BOOT_CHANGED")
                    built
                }
                /*
                 * Read before the failure branch: the hook route's answer shape depends
                 * only on the backend the caller asked for, not on whether the escalation
                 * got that far.
                 */
                val hook = request?.rootBackend == JailbreakRequest.BACKEND_HOOK
                if (request != null) {
                    StageMark.mark(app, "prepare:escalate")
                    val status = JailbreakExecutor.escalate(app, request)
                    StageMark.mark(app, "prepare:escalate:" + status.stage +
                        (status.failure?.let { ":" + it } ?: ""))
                    // The failure is this attempt's result: returning a binder
                    // anyway is exactly how an earlier endpoint used to mask it.
                    if (status.stage != JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED) {
                        // M3 (report §5): the hook route answers with data, not with a
                        // binder exception. The token is already in the record, so it
                        // survives the death of whoever waits for this call; the lease
                        // routes keep throwing exactly as before.
                        if (hook) {
                            StageMark.mark(app, "prepare:return")
                            return hookBundle(status.stage, status.failure, null, false)
                        }
                        throw IllegalStateException(status.failure ?: "SU_DIRECTORY_ATTEMPT_FAILED")
                    }
                }
                /*
                 * Normal/KSU: the executor's verdict is the KernelSU late-load itself.
                 * There is no MapleSU lease to resolve (NativeSuDirectory.prepare would
                 * look for one and fail). Publish readiness only after the live KSU
                 * carrier actually executes SU; a late-load acknowledgement alone
                 * does not prove the manager can grant root.
                 */
                if (request != null && request.rootBackend == JailbreakRequest.BACKEND_KSU) {
                    val observed = JailbreakStatus.read(app)
                    check(observed != null && observed.attemptId == request.attemptId &&
                        observed.bootId == request.bootId &&
                        observed.rootBackend == JailbreakRequest.BACKEND_KSU &&
                        observed.stage == JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED &&
                        observed.failure == null
                    ) {
                        "SU_DIRECTORY_ATTEMPT_NOT_CONFIRMED:" + (observed?.stage ?: "missing")
                    }
                    val claim = recordNormalCarrierProof(app, observed)
                    StageMark.mark(app, "prepare:return:ksu")
                    return Bundle().apply {
                        putString("stage", claim.stage)
                        putString("failure", claim.failure)
                    }
                }
                /*
                 * Step-4 (item 8): the hook route never enters NativeSuDirectory. There
                 * is no lease to resolve and no management binder to publish (L3 has not
                 * designed one yet), so the directory step - and the adopt below - are
                 * skipped by construction rather than by a failing lookup.
                 */
                StageMark.mark(app, "prepare:directory")
                val manager = if (hook) null else NativeSuDirectory.prepare(app, request)
                StageMark.mark(app, "prepare:directory:done")
                if (manager != null) {
                    // S05: the executor lives in this process; publish it here so
                    // deploySu and later calls reuse it.
                    StageMark.mark(app, "prepare:adopt")
                    NativeSuDaemon.adopt(IRootManagementService.Stub.asInterface(manager),
                        request?.origin ?: "normal")
                    StageMark.mark(app, "prepare:adopt:done")
                }
                if (request != null && hook) {
                    // Step-4 (items 9/10/11): the non-lease proof path. It runs in the
                    // same `preparing` mutex and still requires "restore evidence first,
                    // live worker second" - exactly the order the lease branch uses.
                    StageMark.mark(app, "prepare:hook")
                    val claim = publishConfirmedHook(claimHookDaemonReady(app, request)) {
                        publishHookSu(app, request)
                    }
                    StageMark.mark(app, "prepare:hook:" + claim.stage +
                        (claim.failure?.let { ":" + it } ?: ""))
                    /*
                     * Design §2.2 item 1: publish the restricted entry and the broker from
                     * the hook branch, after the claim succeeded and before the answer is
                     * returned. The hook route never enters NativeSuDirectory.prepare, which
                     * is why both publications used to be unreachable here (G1-G4) and every
                     * third-party bind answered SU_EXECUTOR_NOT_PUBLISHED.
                     */
                    StageMark.mark(app, "prepare:return")
                    // M3: {stage, failure, attestationSource} travel as data. A publication
                    // failure belongs to this reply; it does not erase the carrier proof.
                    return hookBundle(claim.stage, claim.failure, claim.attestationSource,
                        claim.ok)
                }
                if (request != null) {
                    // The daemon bound from this attempt's lease. Only now, and
                    // only in the process that owns the lease, is the attempt
                    // allowed to claim DAEMON_READY - never from the UI process
                    // and never by overwriting a FAILED record.
                    val observed = JailbreakStatus.read(app)
                    check(observed != null && observed.attemptId == request.attemptId &&
                        observed.stage == JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED &&
                        observed.failure == null) {
                        "SU_DIRECTORY_ATTEMPT_NOT_CONFIRMED:" + (observed?.stage ?: "missing")
                    }
                    observed.copy(stage = JailbreakStatus.STAGE_DAEMON_READY,
                        message = "root executor answered UID 0 identity for this attempt",
                        ownerPid = Process.myPid(), updatedAtMillis = System.currentTimeMillis())
                        .write(app)
                    /*
                     * T7/T10: the Normal route's carrier is the KSU LKM. It proves itself
                     * (kernelsu in /proc/modules + packaged ksud answering + real `id -u`)
                     * and the proof is persisted before anything calls this attempt ready.
                     */
                    if (observed.rootBackend == JailbreakRequest.BACKEND_KSU) {
                        recordNormalCarrierProof(app, observed)
                    }
                    /*
                     * T11 / R6: the provider no longer reboots itself. A lease root is a
                     * userspace process, so a soft reboot from here necessarily kills the
                     * carrier it just proved; the reboot belongs to the UI's explicit
                     * action or to `bs --handover --phase post` on the root side.
                     */
                }
                StageMark.mark(app, "prepare:return")
                return Bundle().apply { putBinder("manager", manager) }
            } catch (error: Throwable) {
                StageMark.mark(app, "prepare:failed:" + (error.message ?: error.javaClass.simpleName))
                throw error
            } finally {
                preparing.set(false)
                Binder.restoreCallingIdentity(token)
            }
        }
        if (method == "reprove") {
            /*
             * §6.5: after a userspace (soft) reboot the L3 gate is still ARMED and the
             * record still describes this boot, but every userspace process — including
             * the published su endpoint — is gone. This entry re-proves the carrier and
             * re-publishes the endpoint without rerunning the one-shot exploit.
             */
            check(caller == app.applicationInfo.uid) { "SU_DIRECTORY_MANAGER_ONLY" }
            val token = Binder.clearCallingIdentity()
            try {
                val status = JailbreakStatus.read(app)
                val attempt = status?.attemptId
                val boot = status?.bootId
                val eligible = status != null && attempt != null && boot != null &&
                    status.rootBackend == JailbreakRequest.BACKEND_HOOK &&
                    boot == dev.maplesu.manager.jailbreak.DirtyfragAttempt.readBootId() &&
                    SuGate.read(app, attempt, boot).armed
                var reproved = false
                var failure: String? = null
                if (eligible) {
                    val request = JailbreakRequest(
                        method = status.method, attemptId = attempt, bootId = boot,
                        rootBackend = JailbreakRequest.BACKEND_HOOK)
                    val publication = publishConfirmedHook(recordCarrierProof(app)) { publishHookSu(app, request) }
                    reproved = publication.ok
                    failure = publication.failure
                    if (reproved) {
                        StageMark.mark(app, "reprove:ok:" + attempt.take(8))
                    }
                }
                return Bundle().apply {
                    putBoolean("eligible", eligible)
                    putBoolean("reproved", reproved)
                    putString("attemptId", attempt)
                    putString("bootId", boot)
                    putString("failure", failure)
                }
            } finally {
                Binder.restoreCallingIdentity(token)
            }
        }
        if (method == "status") {
            check(caller == app.applicationInfo.uid) { "SU_DIRECTORY_MANAGER_ONLY" }
            // Live probe from the process that owns the attempt: a persisted
            // DAEMON_READY record alone is not evidence that its transport still exists.
            val status = JailbreakStatus.read(app)
            val hook = status?.rootBackend == JailbreakRequest.BACKEND_HOOK
            /*
             * Step-4 (item 12 / P6): the hook route has no lease, so `JailbreakLeaseStore.live`
             * is always false there - which made the provider rewrite every hook
             * DAEMON_READY into EXPIRED the moment it was read. The liveness probe is the
             * attestation worker instead: the claim expires exactly when the worker stops
             * answering, which is what "expired" is supposed to mean.
             */
            val currentBootId = dev.maplesu.manager.jailbreak.DirtyfragAttempt.readBootId()
            val currentBoot = !currentBootId.isNullOrBlank() && status?.bootId == currentBootId
            val leaseLive = currentBoot && if (hook) {
                /*
                 * §6.5/T5: a soft reboot restarts userspace and takes the attest worker
                 * with it, while the L3 gate stays ARMED. The carrier (gate record bound
                 * to this attempt and boot) is the liveness fact, not the worker process.
                 */
                SuGate.read(app, status.attemptId, status.bootId).armed
            } else {
                JailbreakLeaseStore.live
            }
            val liveClaim = status != null && status.stage in JailbreakStatus.LIVE_CLAIM
            /*
             * C2/T5: this is a probe, not a decision. It reports the transport as a
             * derived fact and returns; it never rewrites `status.json`, never
             * synthesises EXPIRED and never tears down the publication that is
             * currently serving third-party `su` calls.
             */
            val transportGone = liveClaim && !leaseLive
            val refreshed = if (status != null && liveClaim) {
                status.withDerived(Derived(
                    bootChanged = status.derived?.bootChanged ?: false,
                    ownerAlive = status.derived?.ownerAlive,
                    carrierLive = leaseLive,
                ))
            } else status
            /*
             * M4: say which evidence the claim actually had. `ucred` is the kernel's own
             * answer on a connection the worker made; `daemon-record` is only the
             * root-owned file it wrote (report R3). Reading it from the record instead of
             * from a sentence is what makes the acceptance decision checkable (S6).
             */
            val attestationSource = if (hook) {
                runCatching {
                    HookAttestServer.read(app, refreshed?.attemptId, refreshed?.bootId)?.source
                }.getOrNull()
            } else null
            return Bundle().apply {
                putBoolean("leaseLive", leaseLive)
                putBoolean("expired", transportGone)
                putString("stage", refreshed?.stage)
                putString("attemptId", refreshed?.attemptId)
                putString("bootId", refreshed?.bootId)
                putString("restoreState", refreshed?.restoreState)
                putString("attestationSource", attestationSource)
            }
        }
        if (method == "deploySu") {
            // Publication of /dev/maplesu/bin/su has to run as root. In jailbreak
            // mode this process owns the only root transport of this boot, so the
            // script runs through the current executor instead of a credential
            // that does not exist (R02).
            check(caller == app.applicationInfo.uid) { "SU_DIRECTORY_MANAGER_ONLY" }
            val script = requireNotNull(extras?.getString("script")) { "SU_DEPLOY_SCRIPT_MISSING" }
            val token = Binder.clearCallingIdentity()
            try {
                /*
                 * L3 (ABI v1, 2026-10-31): the hook route's root transport is the
                 * kernel gate. There is no management binder to refuse any more, so
                 * the old `HOOK_MANAGEMENT_UNAVAILABLE` check is gone; what replaces
                 * it is stricter, not looser:
                 *
                 *  - the gate is re-read from the helper's root-owned record for THIS
                 *    attempt and boot (`SuGate.read`), never from the status file and
                 *    never from anything the caller passed;
                 *  - a missing, stale or non-ARMED record returns
                 *    {code:126, out:"", err:"SU_GATE_NOT_ARMED"} and starts no process;
                 *  - only an armed gate forks, and the forked child is the only thing
                 *    that ever holds root (this ART process never does).
                 *
                 * The lease/root routes keep their existing executor untouched.
                 */
                val status = JailbreakStatus.read(app)
                if (status?.rootBackend == JailbreakRequest.BACKEND_HOOK) {
                    val gate = SuGate.read(app, status.attemptId, status.bootId)
                    return NativeSu.asBundle(NativeSu.executeScript(
                        gate, script, File(app.filesDir, NativeSu.FALLBACK_NAME)))
                }
                return NativeSuDaemon.run(app, arrayOf("/system/bin/sh", "-c", script))
            } finally { Binder.restoreCallingIdentity(token) }
        }
        if (method == "cancel") {
            check(caller == app.applicationInfo.uid) { "SU_DIRECTORY_MANAGER_ONLY" }
            val token = Binder.clearCallingIdentity()
            try {
                JailbreakExecutor.cancel()
                app.stopService(android.content.Intent(app, HookSuKeeperService::class.java))
            } finally { Binder.restoreCallingIdentity(token) }
            return Bundle().apply { putBoolean("cancelled", true) }
        }
        /*
         * Design §6.8: revocation has three legs. The decision refuses new requests and
         * `AUTH_REVOKED` covers a request in its commit window; this method is the third -
         * it terminates the sessions this process already owns for that uid. The Manager
         * calls it over an in-app ContentProvider call (same application uid), which adds
         * no exported component and no new ABI.
         */
        if (method == "revokeSessions") {
            check(caller == app.applicationInfo.uid) { "SU_DIRECTORY_MANAGER_ONLY" }
            val uid = extras?.getInt("uid", -1) ?: -1
            val killed = if (uid >= 0) SuSessionRegistry.shared.killUid(uid) else 0
            val pending = if (uid >= 0) SuSessionRegistry.shared.activeForUid(uid) else 0
            return Bundle().apply {
                putInt("killed", killed)
                putInt("pendingCount", pending)
                putBoolean("pending", pending > 0)
            }
        }
        check(caller == 0) { "SU_DIRECTORY_ROOT_ONLY" }
        return synchronized(lock) {
            val root = requireNotNull(extras?.getBinder("root"))
            when (method) {
                "publish" -> {
                    check(endpoint == null) { "SU_DIRECTORY_ALREADY_PUBLISHED" }
                    val admin = requireNotNull(extras?.getBinder("manager"))
                    val death = IBinder.DeathRecipient {
                        synchronized(lock) {
                            if (endpoint == root) { endpoint = null; manager = null; recipient = null }
                        }
                    }
                    root.linkToDeath(death, 0)
                    endpoint = root; manager = admin; recipient = death
                }
                "clear" -> {
                    check(endpoint == root) { "SU_DIRECTORY_OWNER" }
                    recipient?.let { endpoint?.unlinkToDeath(it, 0) }
                    endpoint = null; manager = null; recipient = null
                }
                else -> error("SU_DIRECTORY_METHOD")
            }
            Bundle().apply {
                putInt("directoryUid", Process.myUid()); putInt("directoryPid", Process.myPid())
                putBoolean("published", endpoint != null)
            }
        }
    }

    /**
     * Step-4 (design §3.1/§3.5 item 10): the non-lease `DAEMON_READY`.
     *
     * <p>Three facts, each from a different source, none sufficient alone:
     *
     *  - **F1** the helper's verified restore - `restoreState` is a *restored* state,
     *    `restoreFailures == 0` and `restoreEnforcing == 1`. A JSON that says "OK" while
     *    the device is permissive is exactly what R3 produced, so the value is checked,
     *    not the label;
     *  - **F2** a live uid-0 worker, from the kernel's `SO_PEERCRED` ucred:
     *    `peerUid == 0`, `peerPid == reply.pid`, and the reply names this boot and
     *    attempt (when the kernel's ucred is not available at all, the worker's own
     *    record is accepted as **WEAK** evidence and labelled as such);
     *  - **F3** that worker's own readback of the policy (`enforcing == 1`).
     *
     * <p>M3 (report `maplesu-ultra-attestation-stability-2026-10-31.md` §5): this is no
     * longer a `check`/`throw` chain. Every refusal is a [ClaimResult] carrying the same
     * token that is written into the status record *before* the answer is returned, so
     * the reason survives the death of the process that called it (report Q2). The
     * attempt stays at `ROOT_WORKER_OBSERVED` - never backwards, never forwards.
     */
    private fun claimHookDaemonReady(app: android.content.Context, request: JailbreakRequest):
        ClaimResult {
        val sink = object : ClaimSink {
            override fun read(): JailbreakStatus? = JailbreakStatus.read(app)
            override fun write(status: JailbreakStatus) { status.write(app).getOrThrow() }
        }
        return decideHookClaim(
            request = request,
            sink = sink,
            // Q-D2: the occupant of this slot is `bs --attest`, an attestation-only
            // worker. It shares the *protocol* with the L3 daemon, not the
            // implementation, so a pass says "a uid-0 worker answered for this attempt
            // and reads enforcing" - it does not say `su` works.
            attest = { HookWorker.attest(app, request) },
            gate = { observed -> SuGate.read(app, observed.attemptId, observed.bootId) },
            proveCarrier = { observed -> CarrierProver.proveUltra(app, observed) },
            ownerPid = Process.myPid(),
            // M6-lite: the listener's verdict is part of the record, so the evidence says
            // whether the socket ever existed (report Q1/U4).
            attestServer = HookAttestServer.lastOutcome,
        )
    }

    /** Persists the KSU LKM carrier proof for the current attempt (T7/T10). */
    private fun recordNormalCarrierProof(app: android.content.Context, status: JailbreakStatus): ClaimResult {
        check(status.rootBackend == JailbreakRequest.BACKEND_KSU && status.failure == null &&
            !status.bootId.isNullOrBlank() && status.bootId ==
                dev.maplesu.manager.jailbreak.DirtyfragAttempt.readBootId() &&
            !status.attemptId.isNullOrBlank() &&
            status.stage in setOf(JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED,
                JailbreakStatus.STAGE_DAEMON_READY)) { "SU_DIRECTORY_ATTEMPT_NOT_CONFIRMED" }
        // This process also predates late-load. Acquire its real manager driver
        // before asking debug su to prove root, without restarting the Provider.
        dev.maplesu.manager.ksu.KsuManagerFd.ensure(app)
        val channel = dev.maplesu.manager.ksu.KsuRootChannel()
        val exec: (String) -> CarrierProver.CommandResult? = { command ->
            runCatching {
                val result = channel.exec(app, command)
                CarrierProver.CommandResult(
                    result.code, result.out.joinToString("\n"), result.err.joinToString("\n"))
            }.getOrNull()
        }
        val sink = object : ClaimSink {
            override fun read(): JailbreakStatus? = JailbreakStatus.read(app)
            override fun write(status: JailbreakStatus) { status.write(app).getOrThrow() }
        }
        return confirmHookCarrier(status, sink, { CarrierProver.proveNormal(app, it, exec) },
            Process.myPid()).also {
            StageMark.mark(app, if (it.ok) "carrier:proven:" + CarrierProver.KIND_KSU
                else "carrier:rejected:" + it.failure)
        }
    }

    /** Persists the L3 carrier proof for the current attempt (T6/T10). */
    @Synchronized
    private fun recordCarrierProof(app: android.content.Context): ClaimResult {
        val status = JailbreakStatus.read(app)
            ?: return ClaimResult(JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED,
                "SU_DIRECTORY_ATTEMPT_NOT_CONFIRMED:missing")
        val sink = object : ClaimSink {
            override fun read(): JailbreakStatus? = JailbreakStatus.read(app)
            override fun write(status: JailbreakStatus) { status.write(app).getOrThrow() }
        }
        return confirmHookCarrier(status, sink, { CarrierProver.proveUltra(app, it) },
            Process.myPid()).also {
            StageMark.mark(app, if (it.ok) "carrier:proven:" + CarrierProver.KIND_L3
                else "carrier:rejected:" + it.failure)
        }
    }

    /** M3: the hook route's answer as data (`{stage, failure, attestationSource}`). */
    private fun hookBundle(stage: String?, failure: String?, attestationSource: String?,
                           prepared: Boolean): Bundle = Bundle().apply {
        putString("stage", stage)
        putString("failure", failure)
        putString("attestationSource", attestationSource)
        putBoolean("hookPrepared", prepared)
    }

    /**
     * Publishes the hook route's restricted `su` entry (design §2.2).
     *
     * <p>Order matters: the endpoint first, then the broker, because the broker hands out
     * whatever [restrictedSu] holds. Both publications must succeed before the caller
     * reports readiness; an existing carrier proof remains available for a later retry.
     *
     * <p>Only `INativeSuService` is published. `IRootManagementService` stays in-process
     * ([manager]), exactly as on the lease route.
     */
    private fun publishHookSu(app: android.content.Context, request: JailbreakRequest) {
        try {
            val endpoint = HookSuEndpoint(app, request.attemptId)
            publishRestrictedSu(endpoint.asBinder())
            NativeSuBrokerService.publish(app)
            StageMark.mark(app, "hook:su:published:ok")
        } catch (error: Exception) {
            StageMark.mark(app, "hook:su:publish-failed:" +
                (error.message ?: error.javaClass.simpleName))
            throw error
        }
    }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = error("No directory rows")
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = error("No directory rows")
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = error("No directory rows")

    companion object {
        const val AUTHORITY = "dev.maplesu.manager.root_directory"

        /** DirtyFragX performs its soft reboot asynchronously; keep the same shape. */
        private const val SOFT_REBOOT_DELAY_MILLIS = 500L
        private val lock = Any()
        private val preparing = java.util.concurrent.atomic.AtomicBoolean()
        @Volatile internal var endpoint: IBinder? = null
            private set
        @Volatile internal var manager: IBinder? = null
            private set
        /** The restricted su endpoint this process published itself; never a Root hand-over. */
        @Volatile internal var restrictedSu: IBinder? = null
            private set

        /**
         * Records the management binder this process resolved.
         *
         * <p>It is deliberately **not** published as [endpoint]: the endpoint the
         * broker hands to a client is the restricted su interface, and that is
         * published by [NativeSuDirectoryLease] from the Root process. The earlier
         * version assigned both fields here, which happened *after* the lease had
         * published the real su binder, so the broker handed out
         * `IRootManagementService` and every traditional client failed with
         * "Binder invocation to an incorrect interface" before any authorization
         * decision was taken.
         */
        internal fun publishManager(binder: IBinder) {
            manager = binder
        }

        /**
         * Publishes the restricted `su` interface of this process (design §2.2).
         *
         * <p>Normal mode publishes from the Root process through [NativeSuDirectoryLease],
         * which is why `publish` is gated on `caller == 0`. Jailbreak and hook modes have
         * no Root-side Android service: the only process that can reach the executor is
         * `:root_directory`, which hosts this provider and [NativeSuBrokerService]. Their
         * binder is therefore set in-process; it is never handed in from a caller.
         *
         * <p>What this does **not** change: the management boundary. The endpoint is
         * `INativeSuService` only, every call it serves authorizes by
         * `Binder.getCallingUid()`, and [manager] (the management binder) stays a separate
         * object that the broker never returns.
         */
        internal fun publishRestrictedSu(binder: IBinder?) {
            synchronized(lock) {
                restrictedSu = binder
                endpoint = binder
            }
        }

        /** Removes only this process's publication; a Root-published endpoint is untouched. */
        internal fun clearRestrictedSu() {
            synchronized(lock) {
                if (restrictedSu != null && endpoint === restrictedSu) endpoint = null
                restrictedSu = null
            }
        }
        private var recipient: IBinder.DeathRecipient? = null
    }
}

/*
 * ---------------------------------------------------------------------------
 * M3 (report `maplesu-ultra-attestation-stability-2026-10-31.md` §5): the hook
 * claim answers with a named outcome instead of throwing across the binder.
 *
 * The reason a claim throws is the reason that dies with the process that called
 * it: the old `IllegalStateException("HOOK_BACKEND_NOT_READY:…")` existed only in
 * the caller's stack and in `instrument.txt`, and nothing was left on disk for a
 * post-mortem (report Q2/§S2). Everything below is top-level on purpose - it has
 * no `Context`, so the host test drives every refusal branch and can assert that
 * the record was written before the answer was returned.
 * ---------------------------------------------------------------------------
 */

/**
 * One claim outcome. `failure` is the same token that is written into the status
 * record: `HOOK_BACKEND_NOT_READY:<reason>`, `SU_DIRECTORY_ATTEMPT_NOT_CONFIRMED:<stage>`
 * or a write-failure token. `ok` is true only when the stage really became
 * `DAEMON_READY`.
 */
internal data class ClaimResult(
    val stage: String,
    val failure: String?,
    /**
     * M4: [HookWorker.SOURCE_UCRED] or [HookWorker.SOURCE_DAEMON_RECORD], when an
     * attestation was actually evaluated. Null when the claim never got that far.
     */
    val attestationSource: String? = null,
) {
    val ok: Boolean get() = failure == null && stage == JailbreakStatus.STAGE_DAEMON_READY
}

/** Where a claim reads and writes its record; production wraps [JailbreakStatus]. */
internal interface ClaimSink {
    fun read(): JailbreakStatus?
    fun write(status: JailbreakStatus)
}

/** A proven carrier is not yet a published SU service. Preserve a publication failure in the reply. */
internal fun publishConfirmedHook(claim: ClaimResult, publish: () -> Unit): ClaimResult {
    if (!claim.ok) return claim
    return try {
        publish()
        claim
    } catch (_: Exception) {
        claim.copy(failure = "HOOK_BACKEND_NOT_READY:su_publication_failed")
    }
}

/**
 * The claim itself (design §3.5 item 10 / step-4 D4), free of Android types.
 *
 * <p>Order is load-bearing: **restore evidence first, live worker second**, and the
 * refusal is written to [ClaimSink] *before* it is returned.
 *
 * @param ownerPid the process that takes ownership of the record
 *   (`Process.myPid()` in production). Passed in rather than read here so the host test
 *   drives every branch without an Android runtime.
 * @param attestServer the listener's last outcome ([HookAttestServer.lastOutcome]). It
 *   is part of every message - including the refusals - because "the listener never came
 *   up" and "it came up and the worker never connected" used to be indistinguishable
 *   without a logcat (report Q1/U4).
 */
internal fun decideHookClaim(
    request: JailbreakRequest,
    sink: ClaimSink,
    attest: () -> HookWorker.Attestation?,
    gate: (JailbreakStatus) -> SuGate.Gate,
    proveCarrier: (JailbreakStatus) -> CarrierProver.Result,
    ownerPid: Int,
    attestServer: String? = null,
): ClaimResult {
    val observed = sink.read()

    fun suffix(): String = if (attestServer == null) "" else "; attestServer=" + attestServer

    fun refuse(token: String, message: String, source: String? = null): ClaimResult {
        val failed = observed?.copy(
            failure = token,
            message = if (source == null) message + suffix()
                      else message + "; attestationSource=" + source + suffix(),
            // The claim runs in the process that owns the attempt now. Taking ownership
            // keeps the record from being expired as "the owner exited" before anybody
            // reads the token out of it (JailbreakStatus.read does exactly that).
            ownerPid = ownerPid,
            updatedAtMillis = System.currentTimeMillis(),
        )
        if (failed != null) {
            /*
             * C3/T3: a carrier proof outranks a refusal. When the record already carries
             * one, the token is returned to the caller but the record is not rewritten -
             * the exception is a DEGRADED event, not a failure of the attempt.
             */
            if (observed?.carrier == null) runCatching { sink.write(failed) }
        }
        return ClaimResult(
            stage = failed?.stage ?: JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED,
            failure = token,
            attestationSource = source,
        )
    }

    if (observed == null || observed.attemptId != request.attemptId ||
        observed.bootId != request.bootId ||
        observed.stage != JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED ||
        observed.failure != null
    ) {
        return refuse("SU_DIRECTORY_ATTEMPT_NOT_CONFIRMED:" + (observed?.stage ?: "missing"),
            "the attempt is not claimable")
    }
    val restored = observed.restoreState == "RESTORED_BASELINE" ||
        observed.restoreState == "RESTORED_KERNEL"
    if (observed.restoreEnforcing != 1 || observed.restoreFailures != 0 || !restored) {
        return refuse("HOOK_BACKEND_NOT_READY:restore_not_enforcing",
            "restore is not a restored enforcing baseline (state=" + observed.restoreState +
                " enforcing=" + observed.restoreEnforcing +
                " failures=" + observed.restoreFailures + ")")
    }
    val attestation = attest()
        ?: return refuse("HOOK_BACKEND_NOT_READY:worker_unreachable",
            "no attestation worker answered for this attempt")
    val reason = HookWorker.refusal(attestation)
    if (reason != null) {
        return refuse("HOOK_BACKEND_NOT_READY:" + reason,
            "the attestation was refused: " + reason, attestation.source)
    }
    // The attestation worker is not a usable SU channel. Require the current
    // attempt's gate, then a real UID-0 child, before publishing READY.
    val gateState = runCatching { gate(observed) }.getOrNull()
    if (gateState?.armed != true || gateState.attempt != request.attemptId ||
        gateState.bootId != request.bootId
    ) {
        return refuse("HOOK_BACKEND_NOT_READY:su_gate_not_armed",
            "the attestation worker has no armed SU gate for this attempt" +
                "; gate=" + gateState?.suGate + "; reason=" + gateState?.reason +
                "; bound=" + gateState?.bound + "; attempt=" + gateState?.attempt +
                "; boot=" + gateState?.bootId, attestation.source)
    }
    val state = gateState.state
    val message = attestationClaimMessage(attestation) +
        "; attestationSource=" + attestation.source +
        "; suGate=" + state + suffix()
    val candidate = observed.copy(
        message = message,
        ownerPid = ownerPid,
        // The only pid that may be published: the one the kernel filled in (F2), or -
        // on the WEAK path - the pid the root-owned record names.
        workerPid = attestation.peerPid,
        workerDomain = attestation.domain,
        suGate = state,
        suToken = gateState.suToken?.hex,
        updatedAtMillis = System.currentTimeMillis(),
    )
    return confirmHookCarrier(candidate, sink, proveCarrier, ownerPid, attestation.source)
}

/** Both carriers and soft-reboot recovery share the same real-SU success gate. */
internal fun confirmHookCarrier(
    observed: JailbreakStatus,
    sink: ClaimSink,
    prove: (JailbreakStatus) -> CarrierProver.Result,
    ownerPid: Int,
    attestationSource: String? = null,
): ClaimResult {
    val proof = runCatching { prove(observed) }.getOrElse {
        CarrierProver.Result.Rejected("probe_failed:" + it.javaClass.simpleName)
    }
    if (proof is CarrierProver.Result.Rejected) {
        val backend = if (observed.rootBackend == JailbreakRequest.BACKEND_KSU) "KSU" else "HOOK"
        val token = backend + "_BACKEND_NOT_READY:carrier:" + proof.reason
        // Keep an earlier carrier proof as historical evidence, but report the
        // current recovery failure to the caller instead of publishing success.
        if (observed.carrier == null) runCatching {
            sink.write(observed.copy(failure = token, message = token, ownerPid = ownerPid,
                updatedAtMillis = System.currentTimeMillis()))
        }
        return ClaimResult(observed.stage, token, attestationSource)
    }
    val carrier = (proof as CarrierProver.Result.Proven).proof
    val proven = observed.copy(
        stage = JailbreakStatus.STAGE_CARRIER_PROVEN,
        carrier = carrier,
        // Recovery bypasses decideHookClaim. Mirror the gate that the real root
        // probe just proved, so authorization resolves the same usable transport.
        // Execution still re-reads the root-owned record and its token.
        suGate = if (carrier.kind == CarrierProver.KIND_L3)
            carrier.facts["gate"] ?: observed.suGate else observed.suGate,
        failure = null,
        ownerPid = ownerPid,
        revision = observed.revision + 1,
        updatedAtMillis = System.currentTimeMillis(),
    )
    val ready = proven.copy(stage = JailbreakStatus.STAGE_DAEMON_READY,
        revision = proven.revision + 1, updatedAtMillis = System.currentTimeMillis())
    val written = runCatching {
        if (observed.stage == JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED) sink.write(proven)
        sink.write(ready)
    }
    if (written.isFailure) {
        return ClaimResult(stage = observed.stage,
            failure = "SU_DIRECTORY_STATUS_WRITE_FAILED",
            attestationSource = attestationSource)
    }
    return ClaimResult(stage = ready.stage, failure = null,
        attestationSource = attestationSource)
}

/**
 * M4 (report R3/S6): the sentence a claim may write about its evidence.
 *
 * Only the socket path may say the worker *answered* - that word is the kernel's
 * ucred talking. The daemon record is the worker's own file, so it says exactly
 * that, marks itself WEAK, and never borrows the stronger wording.
 */
internal fun attestationClaimMessage(attestation: HookWorker.Attestation): String =
    if (attestation.source == HookWorker.SOURCE_UCRED) {
        "hook backend: kernel-credentialed worker pid=" + attestation.peerPid +
            " (bs --attest) answered for this attempt"
    } else {
        "hook backend: worker record (uid-0 file, no kernel ucred) pid=" +
            attestation.peerPid + " for this attempt; WEAK evidence"
    }

