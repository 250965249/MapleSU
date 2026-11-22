package dev.maplesu.manager.runtime

import android.content.Context
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Base64
import dev.maplesu.manager.jailbreak.JailbreakLeaseStore
import dev.maplesu.manager.jailbreak.JailbreakLeaseTransport
import dev.maplesu.manager.runtime.authorization.ManagerSuperuserPolicy
import dev.maplesu.manager.runtime.authorization.SuCodes
import dev.maplesu.manager.runtime.authorization.SuperuserControl
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The restricted third-party `su` interface of jailbreak mode.
 *
 * E2: in normal mode [NativeSuBinder] runs in the Root process that libsu started and
 * publishes itself through [NativeSuDirectoryLease]. Jailbreak mode has no such process
 * - the only Root transport of the boot is the provider lease - so nothing used to
 * publish `INativeSuService` and [NativeSuBrokerService] handed every third party a
 * `null` binding (`SU_EXECUTOR_NOT_READY`). This class is that missing interface.
 *
 * Where it runs: `:root_directory`, the same process that owns the lease and hosts
 * [NativeSuDirectoryProvider] / [NativeSuBrokerService], so the endpoint a client
 * receives is a local binder in the process that can actually reach the executor.
 *
 * What it is not: the management plane. Authorization here is the original product
 * rule - the caller's Binder uid needs the master switch *and* a grant
 * ([JailbreakGrantStore]), exactly like [JailbreakLeaseProxy.start]. The Manager's own
 * uid keeps working, so a trusted internal call is not blocked by its own policy. The
 * management binder ([IRootManagementService]) remains a separate object with its own
 * caller checks and is never handed out by the broker.
 *
 * Transport: the same lease line protocol. Output arrives as pushed `EVT` lines that
 * [JailbreakLeaseStore.registerEvents] routes by token, so this class never polls and
 * the caller's descriptors receive the child's bytes as they are produced.
 */
internal class JailbreakSuEndpoint(private val context: Context) : INativeSuService.Stub() {

    override fun start(frame: ByteArray?, stdin: ParcelFileDescriptor?, stdout: ParcelFileDescriptor?,
                       stderr: ParcelFileDescriptor?, owner: IBinder?): INativeSuSession {
        val caller = Binder.getCallingUid()
        var handedOff = false
        try {
            if (stdin == null || stdout == null || stderr == null || owner == null) {
                authorize(caller)
                throw IllegalArgumentException(SuCodes.SU_REQUEST_INVALID)
            }
            val session = Session(caller, frame, owner, stdin, stdout, stderr)
            try {
                session.begin()
            } catch (error: Throwable) {
                session.release()
                throw when (error) {
                    is SecurityException, is IllegalArgumentException, is IllegalStateException -> error
                    else -> IllegalStateException("SU_SESSION_START_FAILED", error)
                }
            }
            handedOff = true
            return session
        } finally {
            if (!handedOff) {
                runCatching { stdin?.close() }
                runCatching { stdout?.close() }
                runCatching { stderr?.close() }
            }
        }
    }

    private fun authorize(caller: Int) {
        val own = context.applicationInfo.uid
        /*
         * Design §1.2/§3.2: authorization is the one decision function against the
         * Manager's store, not this route's own uid list. The legacy `JailbreakGrantStore`
         * is now import-only - a grant written there has no effect, which is what stops a
         * fifth authority from reappearing.
         *
         * Authorization still happens before a single byte is encoded: a refused request
         * must not reach the executor at all.
         */
        val snapshot = SuperuserControl.snapshot(context)
        if (snapshot == null) {
            StageMark.outputLine("su:start:unavailable:$caller")
            throw IllegalStateException(SuCodes.SU_TRANSPORT_UNAVAILABLE)
        }
        val packages = runCatching {
            context.packageManager.getPackagesForUid(caller)?.toList()
        }.getOrNull()
        val identity = if (caller == own) null else runCatching {
            dev.maplesu.manager.runtime.authorization.AndroidApplicationIdentities(context)
                .read(caller)
        }.getOrNull()
        val decision = if (caller == own) {
            ManagerSuperuserPolicy.decideSelf(snapshot)
        } else {
            ManagerSuperuserPolicy.decide(snapshot, caller, identity, packages)
        }
        if (!decision.allowed) {
            StageMark.outputLine("su:start:denied:$caller:" + decision.reason)
            throw SecurityException(decision.reason)
        }
    }

    /** One authorised child, relayed over the lease. */
    private inner class Session(
        private val callerUid: Int,
        private val frame: ByteArray?,
        private val owner: IBinder,
        stdin: ParcelFileDescriptor,
        stdout: ParcelFileDescriptor,
        stderr: ParcelFileDescriptor,
    ) : INativeSuSession.Stub(), IBinder.DeathRecipient {
        private lateinit var transport: JailbreakLeaseTransport
        @Volatile private var registration: JailbreakLeaseTransport.Registration? = null
        @Volatile private var transportError: String? = null
        private val closed = AtomicBoolean(false)
        private val exited = CountDownLatch(1)
        @Volatile private var exit: Int? = null
        @Volatile private var childExit: Int? = null
        @Volatile private var streamFailure: String? = null
        @Volatile private var waitFailure: String? = null
        @Volatile private var token: Int? = null
        @Volatile private var inputCancelled = false
        @Volatile private var inputFailure: String? = null
        private val eventLock = Any()
        private val input: InputStream = ParcelFileDescriptor.AutoCloseInputStream(stdin)
        private val output: OutputStream = ParcelFileDescriptor.AutoCloseOutputStream(stdout)
        private val error: OutputStream = ParcelFileDescriptor.AutoCloseOutputStream(stderr)
        private val workers = Executors.newCachedThreadPool { runnable ->
            Thread(runnable, "maplesu-jailbreak-su").apply { isDaemon = true }
        }
        @Volatile private var linked = false
        private var registryId: String? = null
        @Volatile private var revoked = false
        @Volatile private var hasTerminal = false
        @Volatile private var preparing = false
        @Volatile private var prepareUnknown = false
        private val closingRemote = AtomicBoolean(false)

        fun begin() {
            val refused = synchronized(this) {
                enforceOpen()
                when (val admission = SuSessionRegistry.shared.admit(
                    callerUid, 0L, terminate = { revoke() }, kill = { release() }, retainUntilExit = true,
                )) {
                    is SuSessionRegistry.Admission.Admitted -> {
                        registryId = admission.session.id
                        owner.linkToDeath(this, 0)
                        linked = true
                        null
                    }
                    is SuSessionRegistry.Admission.Refused -> admission.reason
                }
            }
            // Revoke must see this reservation before the authority can return an old read.
            authorize(callerUid)
            enforceOpen()
            check(refused == null) { requireNotNull(refused) }
            require(frame != null) {
                SuCodes.SU_REQUEST_INVALID
            }
            require(frame.size <= 140_000) { SuCodes.SU_REQUEST_INVALID }
            if (!JailbreakLeaseStore.live) throw IllegalStateException("SU_EXECUTOR_NOT_READY")
            transport = JailbreakLeaseStore.eventTransport()
            val input = ByteArrayInputStream(frame)
            val request = NativeSuRequest.readFrom(input)
            require(input.available() == 0) { SuCodes.SU_REQUEST_TRAILING_DATA }
            hasTerminal = request.terminals != 0
            require(request.targetUid == 0) { SuCodes.SU_TARGET_UID_UNAVAILABLE }
            // The root owner captures its own identity and prepares the gated native child.
            preparing = true
            val reply = try {
                send("prepare $callerUid " + startPayload(request).substringBefore(' '))
            } catch (error: Throwable) {
                prepareUnknown = true
                throw error
            } finally {
                preparing = false
            }
            check(reply.startsWith("OK ") && field(reply, "prepared") == "1") {
                "SU_EXECUTOR_REFUSED:" + reply.take(160)
            }
            val started = field(reply, "token")?.toIntOrNull() ?: error("SU_EXECUTOR_NO_TOKEN")
            check(started > 0) { "SU_EXECUTOR_NO_TOKEN" }
            val attached = synchronized(this) {
                token = started
                if (closed.get() || revoked) false else {
                    synchronized(eventLock) {
                        registration = transport.registerEvents(started) { event -> onEvent(event) }
                    }
                    true
                }
            }
            if (!attached) {
                closeRemote(started)
                if (revoked) throw SecurityException(SuCodes.AUTH_REVOKED)
                error("SU_SESSION_CLOSED")
            }
            enforceOpen()
            val committed = send("commit $started")
            check(committed.startsWith("OK ") && field(committed, "token") == started.toString()) {
                "SU_EXECUTOR_REFUSED:" + committed.take(160)
            }
            enforceOpen()
            if (exit == null && transportError == null) workers.execute { pumpInput(started) }
        }

        override fun openTerminal(): ParcelFileDescriptor? {
            enforceOwner()
            enforceOpen()
            if (!hasTerminal) return null
            val started = token ?: error("SU_EXECUTOR_NO_TOKEN")
            return JailbreakTerminalTransfer.receive(transport, started, context.applicationInfo.uid)
        }

        override fun awaitExit(timeoutMillis: Int): Bundle {
            enforceOwner()
            enforceOpen()
            require(timeoutMillis in 0..30_000) { "SU_WAIT_TIMEOUT_INVALID" }
            val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis.toLong())
            while (exit == null && !closed.get() && observeTransportFailure() == null) {
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) break
                exited.await(minOf(remaining, TimeUnit.MILLISECONDS.toNanos(25)), TimeUnit.NANOSECONDS)
            }
            val transportFailure = observeTransportFailure()
            val code = exit
            val child = childExit.takeIf { code != null }
            val failure = inputFailure
            return Bundle().apply {
                putBoolean("finished", transportFailure != null || code != null)
                putBoolean("childExitKnown", transportFailure == null && child != null)
                transportFailure?.let { putString("transportError", it) }
                putInt("exitCode", if (transportFailure != null || code == 0 && failure != null) -1 else code ?: -1)
                child?.let { putInt("childExitCode", it) }
                streamFailure?.let { putString("streamError", it) }
                waitFailure?.let { putString("waitError", it) }
                failure?.let {
                    putString("stdinError", it)
                    if (it.startsWith("ERR JAILBREAK_EXECUTOR_STDIN_FAILED error64=")) {
                        putString("stdinErrorDetail", decode(it.substringAfter("error64=")).toString(Charsets.UTF_8))
                    }
                }
            }
        }

        override fun signal(signal: Int) {
            enforceOwner()
            enforceOpen()
            require(signal in ALLOWED_SIGNALS) { "SU_SIGNAL_INVALID" }
            val started = token ?: return
            if (exit != null) return
            val reply = send("signal $started $signal")
            check(reply == "OK" || reply.startsWith("OK ")) { "SU_SIGNAL_REFUSED:" + reply.take(120) }
        }

        override fun resize(window: IntArray?) {
            enforceOwner()
            enforceOpen()
            require(hasTerminal && window != null && window.size == 4 && window.all { it in 0..65535 }) {
                "SU_RESIZE_INVALID"
            }
            val started = token ?: error("SU_EXECUTOR_NO_TOKEN")
            val reply = send("resize $started " + window.joinToString(" "))
            check(reply == "OK") { "SU_RESIZE_REFUSED:" + reply.take(120) }
        }

        override fun cancel() {
            enforceOwner()
            if (closed.get() || exit != null) return
            inputCancelled = true
            runCatching { input.close() }
            workers.shutdown()
            val started = token ?: return
            runCatching { send("cancel $started") }
        }

        override fun close() {
            enforceOwner()
            release()
        }

        // Registry callbacks run under the provider's identity, not the Binder caller.
        private fun revoke() {
            val started = synchronized(this) {
                if (closed.get() || exit != null) return
                revoked = true
                inputCancelled = true
                token
            }
            // A pending start holds the lease writer; never wait for it in terminate().
            started?.let {
                runCatching { workers.execute {
                    if (!closed.get() && exit == null) runCatching { send("cancel $it") }
                } }
            }
        }

        private fun releaseRegistry() = synchronized(this) {
            registryId?.let { SuSessionRegistry.shared.release(it) }
            registryId = null
        }

        fun release() {
            if (!closed.compareAndSet(false, true)) return
            val started = synchronized(this) {
                if (linked) {
                    runCatching { owner.unlinkToDeath(this, 0) }
                    linked = false
                }
                token
            }
            exited.countDown()
            runCatching { input.close() }
            runCatching { output.close() }
            runCatching { error.close() }
            workers.shutdown()
            if (started != null) closeRemote(started)
            else if (!preparing && !prepareUnknown) releaseRegistry()
        }

        // A close acknowledgement means the root owner reaped the child and drained its
        // workers. Only explicit CLOSE_PENDING may be continued on this captured lease.
        private fun closeRemote(started: Int) {
            if (!closingRemote.compareAndSet(false, true)) return
            Thread({
                try {
                    while (true) {
                        val reply = send("close $started")
                        if (reply == "OK") {
                            runCatching { registration?.close() ?: transport.unregisterEvents(started) }
                            releaseRegistry()
                            return@Thread
                        }
                        if (!reply.startsWith("ERR JAILBREAK_EXECUTOR_CLOSE_PENDING")) return@Thread
                        Thread.sleep(25)
                    }
                } catch (failure: Throwable) {
                    if (failure is InterruptedException) Thread.currentThread().interrupt()
                    // Unknown transport completion retains a PENDING reservation.
                }
            }, "maplesu-su-close-$started").apply { isDaemon = true; start() }
        }

        /** The client died: its child must not outlive it. */
        override fun binderDied() {
            release()
        }

        private fun enforceOwner() {
            if (Binder.getCallingUid() != callerUid) throw SecurityException("SU_OWNER_MISMATCH")
        }

        private fun enforceOpen() {
            if (revoked) throw SecurityException(SuCodes.AUTH_REVOKED)
            check(!closed.get()) { "SU_SESSION_CLOSED" }
        }

        private fun observeTransportFailure(): String? {
            val current = registration
            val failure = transportError ?: if (current != null) current.failure else transport.failure
            if (failure != null) failTransport(failure)
            return transportError
        }

        private fun failTransport(reason: String) {
            synchronized(this) {
                if (transportError != null) return
                transportError = reason
            }
            inputCancelled = true
            exited.countDown()
            // The listener may hold eventLock while blocked in a caller-owned sink.
            runCatching { input.close() }
            runCatching { output.close() }
            runCatching { error.close() }
            token?.let { started ->
                runCatching { workers.execute { runCatching { send("close $started") } } }
            }
            workers.shutdown()
        }

        private fun readExitFacts(payload: String): Int {
            require(payload.length <= 12_000) { "JAILBREAK_EVENT_EXIT_INVALID" }
            val parts = payload.split(' ')
            val code = parts[0].toIntOrNull()
            require(code != null && code in -1..255 && code.toString() == parts[0]) { "JAILBREAK_EVENT_EXIT_INVALID" }
            val fields = parts.drop(1).map { it.substringBefore('=') to it.substringAfter('=', "") }
            require(fields.size <= 3 && fields.map { it.first }.distinct().size == fields.size &&
                fields.all { it.first in setOf("childExit", "streamError64", "waitError64") && it.second.isNotEmpty() }) { "JAILBREAK_EVENT_EXIT_INVALID" }
            val facts = fields.toMap()
            val raw = facts["childExit"]?.let {
                val value = it.toIntOrNull()
                require(code == -1 && value != null && value in 0..255 && value.toString() == it) { "JAILBREAK_EVENT_EXIT_INVALID" }
                value
            } ?: code.takeIf { it >= 0 }
            fun errorFact(key: String): String? = facts[key]?.let {
                require(code == -1) { "JAILBREAK_EVENT_EXIT_INVALID" }
                val bytes = decode(it, 4096)
                require(java.util.Base64.getEncoder().encodeToString(bytes) == it) { "JAILBREAK_EVENT_EXIT_INVALID" }
                bytes.toString(Charsets.UTF_8).also { text ->
                    require(text.isNotEmpty() && text.toByteArray(Charsets.UTF_8).contentEquals(bytes)) { "JAILBREAK_EVENT_EXIT_INVALID" }
                }
            }
            val stream = errorFact("streamError64")
            val wait = errorFact("waitError64")
            require(wait == null || raw == null) { "JAILBREAK_EVENT_EXIT_INVALID" }
            childExit = raw
            streamFailure = stream
            waitFailure = wait
            return code
        }

        private fun onEvent(event: String) {
            try {
                synchronized(eventLock) {
                    if (transportError != null || exit != null) return
                    val kind = event.substringBefore(' ')
                    val payload = event.substringAfter(' ', "")
                    if (closed.get()) {
                        if (kind == "exit") {
                            exit = readExitFacts(payload)
                            if (childExit != null && waitFailure == null) releaseRegistry()
                        }
                        return
                    }
                    when (kind) {
                        "out" -> write(output, decode(payload, 4096))
                        "err" -> write(error, decode(payload, 4096))
                        "stdin-error" -> {
                            recordInputFailure(decode(payload).toString(Charsets.UTF_8))
                        }
                        "transport-error" -> failTransport(payload)
                        "exit" -> {
                            val code = readExitFacts(payload)
                            synchronized(this) {
                                if (closed.get() || transportError != null || exit != null) return
                                exit = code
                                if (childExit != null && waitFailure == null) releaseRegistry()
                            }
                            runCatching { input.close() }
                            runCatching { output.close() }
                            runCatching { error.close() }
                            exited.countDown()
                            workers.shutdown()
                        }
                        else -> error("JAILBREAK_EVENT_KIND_INVALID")
                    }
                }
            } catch (error: Throwable) {
                failTransport(error.message?.takeIf { it.startsWith("JAILBREAK_EVENT_") }
                    ?: "JAILBREAK_EVENT_SINK_FAILED")
                throw error
            }
        }

        /**
         * Caller stdin -> executor. `-` is the end-of-input marker, so a shell sees
         * EOF instead of a stream that never closes.
         */
        private fun pumpInput(started: Int) {
            val buffer = ByteArray(2048)
            try {
                while (!closed.get() && !inputCancelled && exit == null) {
                    val read = input.read(buffer)
                    if (read <= 0) break
                    if (!sendInput(started, Base64.encodeToString(buffer.copyOf(read), Base64.NO_WRAP))) return
                }
                if (!closed.get() && !inputCancelled && exit == null) sendInput(started, "-")
            } catch (error: Throwable) {
                if (!closed.get() && !inputCancelled && exit == null) {
                    recordInputFailure(error.message ?: error.javaClass.simpleName)
                    runCatching { send("cancel $started") }
                }
            } finally {
                runCatching { input.close() }
            }
        }

        private fun sendInput(started: Int, payload: String): Boolean {
            while (!closed.get() && !inputCancelled && exit == null) {
                val reply = send("stdin $started $payload")
                when (reply) {
                    "OK", "OK queued" -> return true
                    "ERR JAILBREAK_EXECUTOR_STDIN_BACKPRESSURE" -> Thread.sleep(10)
                    else -> throw IllegalStateException(reply)
                }
            }
            return false
        }

        private fun recordInputFailure(reason: String) = synchronized(this) {
            if (inputFailure == null) {
                inputFailure = reason
                StageMark.outputLine("su:stdin:" + reason)
            }
        }

        private fun write(stream: OutputStream, bytes: ByteArray) {
            if (bytes.isEmpty()) return
            stream.write(bytes)
            stream.flush()
        }

        private fun send(request: String, timeoutSeconds: Long = 10): String =
            transport.request(request, timeoutSeconds)

        private fun decode(value: String, maxBytes: Int = 16_384): ByteArray = try {
            require(value.length <= ((maxBytes + 2) / 3) * 4)
            java.util.Base64.getDecoder().decode(value).also { require(it.size <= maxBytes) }
        } catch (error: Exception) {
            throw IllegalArgumentException("JAILBREAK_EVENT_BASE64_INVALID", error)
        }
    }

    private companion object {
        val ALLOWED_SIGNALS = setOf(
            android.system.OsConstants.SIGINT, android.system.OsConstants.SIGTERM,
            android.system.OsConstants.SIGHUP, android.system.OsConstants.SIGQUIT,
            android.system.OsConstants.SIGTSTP, android.system.OsConstants.SIGCONT,
        )

        fun field(reply: String, name: String): String? = reply.removePrefix("OK ").split(' ')
            .firstOrNull { it.startsWith(name + "=") }?.substringAfter('=')

        /**
         * Reuse the validated binary request so empty argv entries and embedded
         * newlines survive the lease. Older executors reject the explicit format
         * option before spawning; a refusal is never retried as a legacy request.
         */
        fun startPayload(request: NativeSuRequest): String {
            val frame = ByteArrayOutputStream().also(request::writeTo).toByteArray()
            return Base64.encodeToString(frame, Base64.NO_WRAP) + " format=msu1"
        }
    }
}
