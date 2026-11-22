package dev.maplesu.manager.runtime

import android.content.Context
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.os.ParcelFileDescriptor
import dev.maplesu.manager.jailbreak.JailbreakRequest
import dev.maplesu.manager.jailbreak.JailbreakStatus
import dev.maplesu.manager.jailbreak.carrierBindsAttempt
import dev.maplesu.manager.runtime.authorization.AndroidApplicationIdentities
import dev.maplesu.manager.runtime.authorization.AuthorizationSnapshot
import dev.maplesu.manager.runtime.authorization.Decision
import dev.maplesu.manager.runtime.authorization.ManagerSuperuserPolicy
import dev.maplesu.manager.runtime.authorization.SuCodes
import dev.maplesu.manager.runtime.authorization.SuperuserControl
import java.io.ByteArrayInputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The restricted third-party `su` endpoint of the **Ultra (hook)** route
 * (design §2 / §4).
 *
 * <p>Why a second endpoint instead of reusing [JailbreakSuEndpoint]: that one's transport
 * is the lease line protocol, and the hook route has no lease at all. Giving hook a fake
 * lease would create a second ownerless transport whose `live` flag says nothing about
 * the hook's attestation. Here the transport is the thing the hook route actually has:
 * [SuGate] (a root-owned record bound to this attempt and boot) plus [NativeSu]'s
 * streaming gate fork.
 *
 * <p>The request path is the design's, in this order:
 *  - caller identity comes from `Binder.getCallingUid()` only - the frame's uid is the
 *    *target* uid and is required to be 0;
 *  - [ManagerSuperuserPolicy] decides against the Manager's store (via
 *    [SuperuserControl], which reads it through a root child on this route), **before**
 *    anything is forked;
 *  - the gate is re-read from the helper's record for this attempt and boot; a missing,
 *    stale or non-ARMED record refuses with `SU_GATE_NOT_ARMED` and starts nothing;
 *  - the child is forked **blocked**, the decision is re-read, and only then is it
 *    released onto `prctl` - the same linearization point as `NativeSuBinder`'s
 *    `commitIfAuthorized`;
 *  - a revoke that lands during the window aborts the child (`AUTH_REVOKED`), and a
 *    revoke after the session exists terminates it through [SuSessionRegistry].
 *
 * <p>What this class never does: hand out the management binder, return the token, put
 * the token in a bundle/log/audit line, or call `prctl` in this process. The ART process
 * stays at its own credentials; only the forked child ever becomes root.
 */
internal class HookSuEndpoint(
    private val context: Context,
    private val attemptId: String,
    private val snapshotLoader: () -> AuthorizationSnapshot? = { SuperuserControl.snapshot(context) },
    private val statusLoader: () -> JailbreakStatus? = { JailbreakStatus.read(context) },
    private val gateLoader: (JailbreakStatus) -> SuGate.Gate = { status ->
        SuGate.read(context, status.attemptId, status.bootId)
    },
    private val runner: NativeSu.StreamRunner = NativeSu.streamRunner(),
    private val registry: SuSessionRegistry = SuSessionRegistry.shared,
    private val audit: (SuAuditEvent) -> Unit = { event -> SuAuditLog.append(context, event) },
    private val clock: () -> Long = System::currentTimeMillis,
    private val elapsedNanos: () -> Long = System::nanoTime,
) : INativeSuService.Stub() {

    override fun start(
        frame: ByteArray?,
        stdin: ParcelFileDescriptor?,
        stdout: ParcelFileDescriptor?,
        stderr: ParcelFileDescriptor?,
        owner: IBinder?,
    ): INativeSuSession {
        val caller = Binder.getCallingUid()
        val own = context.applicationInfo.uid
        val identityToken = Binder.clearCallingIdentity()
        var created: Session? = null
        try {
            // 1./2. Caller identity: Binder uid, resolved through PackageManager. A
            // multi-package uid cannot be represented as one identity and is refused by
            // the shared policy (SU_CALLER_PACKAGE_AMBIGUOUS).
            val packages = runCatching {
                context.packageManager.getPackagesForUid(caller)?.toList()
            }.getOrNull()
            val identity = if (caller == own) null else runCatching {
                AndroidApplicationIdentities(context).read(caller)
            }.getOrNull()
            /*
             * Design §2.3: a caller whose package identity cannot be resolved at all is a
             * different answer than "the installation changed". uid 0, a system uid, and
             * an uninstalled app land here and are refused before the list is consulted.
             */
            if (caller != own && (packages.isNullOrEmpty() || identity == null)) {
                referee(caller, packages, null, SuCodes.SU_CALLER_IDENTITY_UNAVAILABLE,
                    backend = BACKEND_HOOK)
                throw SecurityException(SuCodes.SU_CALLER_IDENTITY_UNAVAILABLE)
            }

            // 3. The one decision. A store that cannot be read is a refusal; it never
            // becomes "no grants" by accident.
            val snapshot = snapshotLoader()
            if (snapshot == null) {
                referee(caller, packages, null, SuCodes.SU_TRANSPORT_UNAVAILABLE, backend = BACKEND_HOOK)
                throw IllegalStateException(SuCodes.SU_TRANSPORT_UNAVAILABLE)
            }
            val decision = decide(snapshot, caller, own, identity, packages)
            if (!decision.allowed) {
                referee(caller, packages, decision, decision.reason, backend = BACKEND_HOOK)
                throw SecurityException(decision.reason)
            }

            // 5. Gate before any fork. `JailbreakStatus` is app-private and the gate is
            // re-read from the root-owned record bound to this attempt and boot.
            val status = statusLoader()
            if (status == null || status.rootBackend != JailbreakRequest.BACKEND_HOOK ||
                status.stage != JailbreakStatus.STAGE_DAEMON_READY ||
                status.bootId == null || status.attemptId != attemptId ||
                // §6.2: a proof written for another attempt/boot is not this attempt's.
                !carrierBindsAttempt(status)
            ) {
                audit(
                    SuAuditEvent(
                        backend = BACKEND_HOOK, event = "gate", attemptId = attemptId,
                        callerUid = caller, callerPackages = packages.orEmpty(),
                        decision = "deny", reason = SuCodes.SU_EXECUTOR_NOT_READY,
                        gate = SuGate.UNAVAILABLE,
                    ),
                )
                throw IllegalStateException(SuCodes.SU_EXECUTOR_NOT_READY)
            }
            val gate = gateLoader(status)
            if (!gate.armed) {
                audit(
                    SuAuditEvent(
                        backend = BACKEND_HOOK, event = "gate", attemptId = attemptId,
                        bootId = status.bootId, callerUid = caller,
                        callerPackages = packages.orEmpty(), decision = "deny",
                        reason = SuCodes.SU_GATE_NOT_ARMED, gate = SuGate.UNAVAILABLE,
                    ),
                )
                throw IllegalStateException(SuCodes.SU_GATE_NOT_ARMED)
            }
            audit(
                SuAuditEvent(
                    backend = BACKEND_HOOK, event = "gate", attemptId = attemptId,
                    bootId = status.bootId, callerUid = caller,
                    callerPackages = packages.orEmpty(), decision = "allow",
                    gate = SuGate.ARMED, rev = decision.rev,
                ),
            )

            // 4. Request shape, identical to the Normal restricted entry.
            require(frame != null && stdin != null && stdout != null && stderr != null && owner != null) {
                SuCodes.SU_REQUEST_INVALID
            }
            require(frame.size <= MAX_FRAME) { SuCodes.SU_REQUEST_INVALID }
            val input = ByteArrayInputStream(frame)
            val request = NativeSuRequest.readFrom(input)
            require(input.available() == 0) { SuCodes.SU_REQUEST_TRAILING_DATA }
            require(request.terminals == 0) { SuCodes.SU_TERMINAL_UNAVAILABLE }
            require(request.targetUid == 0) { SuCodes.SU_TARGET_UID_UNAVAILABLE }
            val argv = argvOf(request)
            audit(
                SuAuditEvent(
                    backend = BACKEND_HOOK, event = "request", attemptId = attemptId,
                    bootId = status.bootId, callerUid = caller,
                    callerPackages = packages.orEmpty(), argv0 = SuAuditLog.argv0(argv),
                    argvSha256 = SuAuditLog.argvDigest(argv), gate = SuGate.ARMED,
                    rev = decision.rev,
                ),
            )

            // 6. Capacity before anything is forked.
            if (registry.activeCount() >= GLOBAL_SESSION_LIMIT ||
                registry.activeForUid(caller) >= PER_UID_SESSION_LIMIT
            ) {
                throw IllegalStateException(SuCodes.SU_SESSION_LIMIT)
            }
            // The decision is written before the answer, as the design requires.
            audit(
                SuAuditEvent(
                    backend = BACKEND_HOOK, event = "decision", attemptId = attemptId,
                    bootId = status.bootId, callerUid = caller,
                    callerPackages = packages.orEmpty(), decision = "allow",
                    argv0 = SuAuditLog.argv0(argv), argvSha256 = SuAuditLog.argvDigest(argv),
                    gate = SuGate.ARMED, rev = decision.rev, source = "manager",
                ),
            )

            // 7. Fork the blocked child. Nothing the caller asked for runs yet.
            val token = requireNotNull(gate.suToken) { SuCodes.SU_GATE_NOT_ARMED }.value
            val pid = runner.start(
                token, HookSuCommand.argv(request, argv), stdin.fd, stdout.fd, stderr.fd, request.globalMount,
            )
            if (pid <= 0) throw IllegalStateException(startFailure(pid))
            val session = Session(caller, pid, owner, SuAuditLog.argv0(argv), status, decision.rev)
            created = session

            // 8. The commit window: re-read the decision while the child exists but is
            // not yet root. A revoke, a switch-off or an identity change that landed
            // during setup aborts the child instead of admitting it.
            val fresh = snapshotLoader()
            val redecision = if (fresh == null) {
                Decision.deny(SuCodes.SU_TRANSPORT_UNAVAILABLE)
            } else {
                decide(fresh, caller, own, identity, packages)
            }
            if (!redecision.allowed) {
                audit(
                    SuAuditEvent(
                        backend = BACKEND_HOOK, event = "decision", attemptId = attemptId,
                        bootId = status.bootId, callerUid = caller,
                        callerPackages = packages.orEmpty(), decision = "deny",
                        reason = SuCodes.AUTH_REVOKED, argv0 = SuAuditLog.argv0(argv),
                        argvSha256 = SuAuditLog.argvDigest(argv), gate = SuGate.ARMED,
                        rev = redecision.rev, source = "manager",
                    ),
                )
                throw SecurityException(SuCodes.AUTH_REVOKED)
            }

            when (val admission = registry.admit(
                caller, pid,
                terminate = { session.signalChild(SIGTERM) },
                kill = { session.signalChild(SIGKILL) },
            )) {
                is SuSessionRegistry.Admission.Admitted -> {
                    session.bindRegistryId(admission.session.id)
                }
                is SuSessionRegistry.Admission.Refused -> {
                    throw IllegalStateException(admission.reason)
                }
            }
            // 9. Release: the child arms the gate, proves uid 0 and execs.
            if (!runner.commit(pid)) {
                throw IllegalStateException(SuCodes.SU_GATE_NOT_ARMED)
            }
            session.begin()
            audit(
                SuAuditEvent(
                    backend = BACKEND_HOOK, event = "exec", attemptId = attemptId,
                    bootId = status.bootId, callerUid = caller,
                    callerPackages = packages.orEmpty(), sessionId = session.id,
                    argv0 = SuAuditLog.argv0(argv), argvSha256 = SuAuditLog.argvDigest(argv),
                    gate = SuGate.ARMED, rev = decision.rev,
                ),
            )
            return session
        } catch (error: Throwable) {
            created?.release()
            throw when (error) {
                is SecurityException, is IllegalArgumentException, is IllegalStateException -> error
                else -> IllegalStateException("SU_SESSION_START_FAILED", error)
            }
        } finally {
            // These are this process's duplicates; the child already inherited its own.
            runCatching { stdin?.close() }
            runCatching { stdout?.close() }
            runCatching { stderr?.close() }
            Binder.restoreCallingIdentity(identityToken)
        }
    }

    /** The same decision function on both modes; the Manager's uid only needs the switch. */
    private fun decide(
        snapshot: AuthorizationSnapshot,
        caller: Int,
        own: Int,
        identity: dev.maplesu.manager.runtime.authorization.ApplicationIdentity?,
        packages: List<String>?,
    ): Decision =
        if (caller == own) ManagerSuperuserPolicy.decideSelf(snapshot)
        else ManagerSuperuserPolicy.decide(snapshot, caller, identity, packages)

    private fun referee(
        caller: Int,
        packages: List<String>?,
        decision: Decision?,
        reason: String,
        backend: String,
    ) {
        audit(
            SuAuditEvent(
                backend = backend, event = "decision", attemptId = attemptId,
                callerUid = caller, callerPackages = packages.orEmpty(),
                decision = "deny", reason = reason, rev = decision?.rev,
                source = "manager",
            ),
        )
    }

    private fun argvOf(request: NativeSuRequest): List<String> =
        if (request.arguments.first().startsWith("/")) request.arguments
        else listOf(request.executable) + request.arguments.drop(1)

    private fun startFailure(pid: Long): String = when (pid) {
        NativeSu.START_ZERO_TOKEN -> SuCodes.SU_GATE_NOT_ARMED
        NativeSu.START_LIMIT -> SuCodes.SU_SESSION_LIMIT
        else -> SuCodes.SU_EXEC_FAILED
    }

    /** One admitted child. Owns the pid; the registry owns the revoke signal. */
    private inner class Session(
        private val callerUid: Int,
        private val pid: Long,
        private val owner: IBinder,
        private val argv0: String?,
        private val status: JailbreakStatus,
        private val rev: Long,
    ) : INativeSuSession.Stub(), IBinder.DeathRecipient {
        private val closed = AtomicBoolean(false)
        private val exited = CountDownLatch(1)
        @Volatile private var exit: Int? = null
        @Volatile private var registryId: String? = null
        @Volatile private var linked = false
        private val startedAt = clock()

        val id: String get() = registryId ?: "unregistered-$pid"

        fun bindRegistryId(value: String) {
            registryId = value
        }

        @Synchronized fun begin() {
            enforceOpen()
            owner.linkToDeath(this, 0)
            linked = true
            // One monitor per session: its only job is to reap (or time the child out) and
            // to publish the exit exactly once.
            val monitor = Thread({ awaitExitAndPublish() }, "maplesu-hook-su-$pid").apply { isDaemon = true }
            monitor.start()
        }

        private fun awaitExitAndPublish() {
            val deadline = elapsedNanos() + TimeUnit.MILLISECONDS.toNanos(NativeSu.SESSION_LIFETIME_MILLIS)
            try {
                while (true) {
                    val finished = synchronized(this) {
                        if (exit != null) true else {
                            val remaining = deadline - elapsedNanos()
                            if (remaining <= 0) {
                                stopChild(NativeSu.EXIT_TIMEOUT)
                                true
                            } else {
                                // kill(SIGKILL) also waitpids. Keep every pid operation
                                // and exit publication under this lock to prevent reuse.
                                val wait = TimeUnit.NANOSECONDS.toMillis(remaining)
                                    .coerceIn(1, REAP_POLL_MILLIS.toLong()).toInt()
                                val observed = runner.reap(pid, wait)
                                if (observed == NativeSu.REAP_RUNNING) false else {
                                    publishExit(if (observed >= 0) observed else NativeSu.EXIT_EXEC_FAILED)
                                    true
                                }
                            }
                        }
                    }
                    if (finished) return
                    Thread.sleep(1)
                }
            } catch (_: Throwable) {
                synchronized(this) { stopChild(NativeSu.EXIT_EXEC_FAILED) }
            }
        }

        /** Called under the session lock; a non-waitable pid is never signalled again. */
        private fun stopChild(failureCode: Int) {
            if (exit != null) return
            val observed = runCatching { runner.reap(pid, 0) }.getOrDefault(NativeSu.REAP_ERROR)
            val code = when {
                observed >= 0 -> observed
                observed == NativeSu.REAP_RUNNING -> {
                    runCatching { runner.kill(pid, SIGKILL) }
                    failureCode
                }
                else -> NativeSu.EXIT_EXEC_FAILED
            }
            publishExit(code)
        }

        @Synchronized private fun publishExit(code: Int) {
            if (exit != null) return
            exit = code
            registryId?.let { registry.release(it) }
            exited.countDown()
            audit(
                SuAuditEvent(
                    backend = BACKEND_HOOK, event = "exit", attemptId = attemptId,
                    bootId = status.bootId, callerUid = callerUid, sessionId = id,
                    argv0 = argv0, exitCode = code, durationMs = clock() - startedAt,
                    gate = SuGate.ARMED, rev = rev,
                ),
            )
        }

        override fun openTerminal(): ParcelFileDescriptor? {
            enforceOwner()
            enforceOpen()
            return null
        }

        override fun awaitExit(timeoutMillis: Int): Bundle {
            enforceOwner()
            enforceOpen()
            require(timeoutMillis in 0..30_000) { "SU_WAIT_TIMEOUT_INVALID" }
            val finished = exited.await(timeoutMillis.coerceAtLeast(0).toLong(), TimeUnit.MILLISECONDS)
            val code = exit
            return Bundle().apply {
                putBoolean("finished", finished && code != null)
                putInt("exitCode", code ?: -1)
            }
        }

        override fun signal(signal: Int) {
            enforceOwner()
            enforceOpen()
            require(signal in ALLOWED_SIGNALS) { "SU_SIGNAL_INVALID" }
            signalChild(signal)
        }

        @Synchronized fun signalChild(signal: Int) {
            if (closed.get() || exit != null) return
            if (signal == SIGKILL) stopChild(NativeSu.EXIT_EXEC_FAILED)
            else runner.kill(pid, signal)
        }

        override fun resize(window: IntArray?) {
            enforceOwner()
            enforceOpen()
            // No PTY is allocated: a terminal master cannot be handed back over this
            // transport, so the honest answer is a refusal, not a fake descriptor.
            throw IllegalStateException(SuCodes.SU_RESIZE_UNAVAILABLE)
        }

        override fun cancel() {
            enforceOwner()
            if (closed.get()) return
            runCatching { signalChild(SIGTERM) }
            audit(
                SuAuditEvent(
                    backend = BACKEND_HOOK, event = "cancel", attemptId = attemptId,
                    bootId = status.bootId, callerUid = callerUid, sessionId = id,
                    argv0 = argv0, rev = rev,
                ),
            )
        }

        override fun close() {
            enforceOwner()
            release()
        }

        @Synchronized fun release() {
            if (!closed.compareAndSet(false, true)) return
            if (linked) {
                runCatching { owner.unlinkToDeath(this, 0) }
                linked = false
            }
            stopChild(NativeSu.EXIT_EXEC_FAILED)
        }

        override fun binderDied() {
            release()
        }

        private fun enforceOwner() {
            if (Binder.getCallingUid() != callerUid) throw SecurityException("SU_OWNER_MISMATCH")
        }

        private fun enforceOpen() {
            check(!closed.get()) { "SU_SESSION_CLOSED" }
        }
    }

    companion object {
        const val BACKEND_HOOK = "hook"
        private const val MAX_FRAME = 140_000
        private const val GLOBAL_SESSION_LIMIT = 4
        private const val PER_UID_SESSION_LIMIT = 2
        private const val REAP_POLL_MILLIS = 100

        /** Signals the restricted ABI allows (same set as `NativeSuBinder`). */
        private val ALLOWED_SIGNALS = setOf(
            android.system.OsConstants.SIGINT,
            android.system.OsConstants.SIGTERM,
            android.system.OsConstants.SIGHUP,
            android.system.OsConstants.SIGQUIT,
            android.system.OsConstants.SIGTSTP,
            android.system.OsConstants.SIGCONT,
        )

        /** The two signals the session lifecycle itself issues. */
        private val SIGTERM = android.system.OsConstants.SIGTERM
        private val SIGKILL = android.system.OsConstants.SIGKILL
    }
}
