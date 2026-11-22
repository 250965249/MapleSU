package dev.maplesu.manager.runtime

import android.content.Context
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.UserManager
import android.system.OsConstants
import dev.maplesu.manager.runtime.authorization.AndroidApplicationIdentities
import dev.maplesu.manager.runtime.authorization.ApplicationIdentity
import dev.maplesu.manager.runtime.authorization.AuthorizationPolicy
import java.io.ByteArrayInputStream
import java.io.IOException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean

/** Restricted Root endpoint; each session is created under the single authorization owner. */
internal class NativeSuBinder(private val context: Context, private val policy: AuthorizationPolicy) : INativeSuService.Stub() {
    private val sessions = HashSet<Session>()
    private var closed = false
    private var startsInFlight = 0
    private val workers = Executors.newCachedThreadPool { task ->
        Thread(task, "maplesu-native-su").apply { isDaemon = true }
    }

    override fun start(frame: ByteArray?, stdin: ParcelFileDescriptor?, stdout: ParcelFileDescriptor?,
        stderr: ParcelFileDescriptor?, owner: IBinder?): INativeSuSession {
        val callingUid = Binder.getCallingUid()
        val streams = listOfNotNull(stdin, stdout, stderr)
        val token = Binder.clearCallingIdentity()
        var created: Session? = null
        try {
            check(context.getSystemService(UserManager::class.java)?.isUserUnlocked == true) { "SU_USER_LOCKED" }
            require(streams.size == 3 && owner != null && frame != null && frame.size <= 140_000) { "SU_REQUEST_INVALID" }
            val input = ByteArrayInputStream(frame)
            val request = NativeSuRequest.readFrom(input)
            require(input.available() == 0) { "SU_REQUEST_TRAILING_DATA" }
            val session = Session(callingUid, owner, request)
            synchronized(sessions) {
                check(!closed) { "SU_SESSION_CLOSED" }
                sessions.add(session)
                startsInFlight++
            }
            created = session
            // Reserve/link before authority reads, so revoke cannot miss a stale reader.
            session.reserve()
            val identity = policy.authorize(callingUid)
            session.rememberIdentity(identity)
            // 2. Prepare the Root child without executing the user command. The child
            //    is forked and blocked before exec; nothing the caller asked for runs.
            session.prepare(streams)
            // 3. Commit in the same critical section as a fresh decision. A revoke, a
            //    switch-off or an identity change that completed before this point
            //    refuses the request with no side effect at all - the prepared child
            //    is discarded, never started.
            if (!policy.commitIfAuthorized(callingUid, identity) { session.commitNoWait() }) {
                throw SecurityException("AUTH_REVOKED")
            }
            // 4. Outside the lock: wait for the real start and hand the session over.
            session.awaitStarted()
            return session
        } catch (error: Throwable) {
            if (created?.retainPendingStart() == true) return checkNotNull(created)
            created?.release()
            throw when (error) {
                is SecurityException, is IllegalArgumentException, is IllegalStateException -> error
                is Exception -> IllegalStateException("SU_SESSION_START_FAILED", error)
                else -> error
            }
        } finally {
            streams.forEach { runCatching { it.close() } }
            created?.finishStart()
            Binder.restoreCallingIdentity(token)
        }
    }

    private inner class Session(private val callerUid: Int, private val owner: IBinder,
        private val request: NativeSuRequest) : INativeSuSession.Stub(), IBinder.DeathRecipient {
        private val closed = AtomicBoolean(false)
        private var cancelled = false
        private val exited = CompletableFuture<Int>()
        private val startDone = CountDownLatch(1)
        @Volatile private var running: MapleSuSupervisedProcess? = null
        @Volatile var registryId: String? = null
            private set
        private var identity: ApplicationIdentity? = null
        private var terminal: ParcelFileDescriptor? = null
        private var linked = false
        private var terminalClaimed = false
        private var starting = true
        private var prepareUnknown = false
        private var reaped = false
        private var startError: String? = null

        @Synchronized fun reserve() {
            enforceStart()
            when (val admission = SuSessionRegistry.shared.admit(callerUid, 0L,
                terminate = { requestCancel() }, kill = { requestCancel() }, retainUntilExit = true)) {
                is SuSessionRegistry.Admission.Refused -> error(admission.reason)
                is SuSessionRegistry.Admission.Admitted -> registryId = admission.session.id
            }
            try {
                linked = true
                owner.linkToDeath(this, 0)
                enforceStart()
            } catch (failure: Throwable) {
                release()
                throw failure
            }
        }

        fun prepare(streams: List<ParcelFileDescriptor>) {
            synchronized(this) {
                enforceStart()
                prepareUnknown = true
            }
            // Fork/PTY setup happens outside this monitor so a concurrent release or
            // a second request never waits behind process creation.
            try {
                val process = MapleSuSupervisedProcess.prepareRootSu(context, request,
                    streams.map { it.fileDescriptor }.toTypedArray(), onLaunched = ::attachProcess)
                synchronized(this) {
                    running = process
                    prepareUnknown = false
                    if (closed.get() || cancelled) process.cancel()
                }
            } catch (failure: Throwable) {
                synchronized(this) {
                    prepareUnknown = false
                    if (startError == null) startError = failure.message ?: failure.javaClass.simpleName
                }
                throw failure
            }
        }

        private fun attachProcess(process: MapleSuSupervisedProcess) {
            val cancel = synchronized(this) {
                running = process
                closed.get() || cancelled
            }
            workers.execute { observeExit(process) }
            if (cancel) process.cancel()
        }

        @Synchronized fun retainPendingStart(): Boolean {
            prepareUnknown = false
            if (startError == null) return false
            val process = running ?: return false
            if (!process.process.isAlive) return false
            cancelled = true
            process.cancel()
            return true
        }

        /** Called while the policy lock is held: one byte, no waiting. */
        @Synchronized fun commitNoWait() {
            enforceStart()
            synchronized(sessions) {
                check(!this@NativeSuBinder.closed) { "SU_SESSION_CLOSED" }
                try {
                    checkNotNull(running).commitNoWait()
                } catch (failure: IOException) {
                    if (startError == null) startError = failure.message ?: failure.javaClass.simpleName
                    // Policy maps IOException to denial. Here the failure is in the native write.
                    throw IllegalStateException("SU_SESSION_START_FAILED", failure)
                }
            }
        }

        @Synchronized fun rememberIdentity(value: ApplicationIdentity) {
            enforceStart()
            check(value.uid == callerUid) { "SU_OWNER_MISMATCH" }
            identity = value
        }

        fun awaitStarted() {
            val process = checkNotNull(running)
            try {
                process.awaitStarted()
                synchronized(this) {
                    enforceStart()
                    terminal = process.openTerminal()
                }
            } catch (failure: Throwable) {
                synchronized(this) {
                    if (startError == null) startError = failure.message ?: failure.javaClass.simpleName
                }
                throw failure
            }
        }

        private fun observeExit(process: MapleSuSupervisedProcess) {
            var interrupted = false
            var code: Int? = null
            try {
                while (code == null) {
                    try {
                        val observed = process.process.waitFor()
                        check(observed in 0..255) { "SU_WAIT_RESULT_INVALID" }
                        code = observed
                    }
                    catch (failure: InterruptedException) {
                        interrupted = true
                        exited.completeExceptionally(failure)
                        requestCancel()
                    }
                }
            } catch (failure: Exception) {
                exited.completeExceptionally(failure)
                requestCancel()
            } finally {
                // A fast child may exit before awaitStarted has received/duplicated its PTY.
                while (true) {
                    try { startDone.await(); break }
                    catch (_: InterruptedException) { interrupted = true }
                }
                process.closeControl()
                runCatching { process.process.outputStream.close() }
                runCatching { process.process.inputStream.close() }
                runCatching { process.process.errorStream.close() }
                synchronized(this) {
                    reaped = code != null
                    releaseReservation()
                }
                code?.let { exited.complete(it) }
                if (interrupted) Thread.currentThread().interrupt()
            }
        }

        fun finishStart() {
            synchronized(this) {
                starting = false
                releaseReservation()
            }
            startDone.countDown()
            synchronized(sessions) {
                startsInFlight--
                if (this@NativeSuBinder.closed && startsInFlight == 0) workers.shutdown()
            }
        }

        private fun releaseReservation() {
            // A thrown prepare without a returned handle has no native reap receipt.
            if (starting || prepareUnknown || (running != null && !reaped)) return
            registryId?.let { SuSessionRegistry.shared.release(it) }
            registryId = null
            if (terminal == null) {
                unlinkOwner()
                synchronized(sessions) { sessions.remove(this) }
            }
        }

        override fun openTerminal(): ParcelFileDescriptor? {
            enforceOwner()
            synchronized(this) {
                enforceOpen()
                check(!terminalClaimed) { "SU_TERMINAL_ALREADY_CLAIMED" }
                terminalClaimed = true
                val claimed = terminal
                terminal = null
                releaseReservation()
                return claimed
            }
        }

        override fun awaitExit(timeoutMillis: Int): Bundle {
            enforceOwner()
            require(timeoutMillis in 0..30_000) { "SU_WAIT_TIMEOUT_INVALID" }
            return try {
                Bundle().apply {
                    putInt("exitCode", exited.get(timeoutMillis.toLong(), TimeUnit.MILLISECONDS))
                    putBoolean("finished", true)
                    synchronized(this@Session) { startError?.let { putString("startError", it) } }
                }
            } catch (_: TimeoutException) {
                Bundle().apply {
                    putBoolean("finished", false)
                    synchronized(this@Session) {
                        startError?.let { putBoolean("pending", true); putString("startError", it) }
                    }
                }
            } catch (error: Exception) {
                if (error is InterruptedException) Thread.currentThread().interrupt()
                throw IllegalStateException("SU_WAIT_FAILED", error)
            }
        }

        override fun signal(signal: Int) {
            enforceOwner()
            enforceOpen()
            require(signal in setOf(OsConstants.SIGINT, OsConstants.SIGTERM, OsConstants.SIGHUP,
                OsConstants.SIGQUIT, OsConstants.SIGTSTP, OsConstants.SIGCONT)) { "SU_SIGNAL_INVALID" }
            checkNotNull(running).signal(signal)
        }

        override fun resize(window: IntArray?) {
            enforceOwner()
            enforceOpen()
            require(window != null && window.size == 4 && window.all { it in 0..65535 } && request.terminals != 0) { "SU_WINDOW_INVALID" }
            checkNotNull(running).resize(window)
        }

        override fun cancel() {
            // Cancel and close stay idempotent: they are also the teardown paths used
            // by the owner-death recipient and by the executor's own shutdown.
            enforceOwner()
            requestCancel()
        }

        override fun close() {
            enforceOwner()
            if (closed.get()) return
            release()
        }

        override fun binderDied() { release() }

        /** Distinguishes "this session is finished" from a permission failure. */
        private fun enforceOpen() {
            check(!closed.get()) { "SU_SESSION_CLOSED" }
        }

        private fun enforceStart() {
            enforceOpen()
            check(!cancelled) { "SU_SESSION_CANCELLED" }
        }

        private fun requestCancel() {
            val process = synchronized(this) { cancelled = true; running }
            process?.cancel()
        }

        @Synchronized fun release() {
            if (!closed.compareAndSet(false, true)) return
            cancelled = true
            runCatching { terminal?.close() }
            terminal = null
            running?.let { process ->
                process.cancel()
                process.closeControl()
            }
            unlinkOwner()
            releaseReservation()
        }

        private fun unlinkOwner() {
            if (!linked) return
            linked = false
            runCatching { owner.unlinkToDeath(this, 0) }
        }

        private fun enforceOwner() {
            if (Binder.getCallingUid() != callerUid) throw SecurityException("SU_OWNER_MISMATCH")
            val token = Binder.clearCallingIdentity()
            try {
                if (AndroidApplicationIdentities(context).read(callerUid) != identity) throw SecurityException("AUTH_IDENTITY_CHANGED")
            } finally { Binder.restoreCallingIdentity(token) }
        }
    }

    fun activeCount(): Int = synchronized(sessions) { sessions.count { it.registryId != null } }

    fun close() {
        val active = synchronized(sessions) { closed = true; sessions.toList() }
        active.forEach { it.release() }
        synchronized(sessions) { if (startsInFlight == 0) workers.shutdown() }
    }

    companion object {
        fun get(context: Context): INativeSuService = NativeSuDaemon.service(context)
    }
}
