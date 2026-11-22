package dev.maplesu.manager.runtime

import android.os.Bundle
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Base64
import dev.maplesu.manager.jailbreak.JailbreakLeaseStore
import dev.maplesu.manager.jailbreak.JailbreakLeaseTransport
import dev.maplesu.manager.runtime.authorization.ManagerSuperuserPolicy
import dev.maplesu.manager.runtime.authorization.SuperuserControl
import java.io.FileOutputStream

/**
 * Local AIDL implementation backed by the lease line protocol.
 *
 * DEV-16: a binder cannot cross process boundaries here (`Parcel.marshall` rejects
 * Parcel objects), so the product's own `IRootManagementService` proxy forwards
 * each call to the resident executor over the lease transport that is measured to
 * work (DEV-24). `start()` opens a streaming task: the executor returns a token,
 * a pump thread polls `output <token>` and feeds two pipes, so callers keep using
 * the normal AIDL shape (`openStdout`/`openStderr`/`awaitExit`/`cancel`).
 */
class JailbreakLeaseProxy(private val context: android.content.Context) : IRootManagementService.Stub() {

    override fun status(): Bundle {
        val reply = send("status")
        StageMark.outputLine("proxy:status:" + reply.take(160))
        if (!reply.startsWith("OK ")) {
            throw IllegalStateException("JAILBREAK_EXECUTOR_NO_REPLY:" + reply)
        }
        val fields = fields(reply)
        if (fields["rootUid"]?.toIntOrNull() != 0) {
            throw IllegalStateException("JAILBREAK_EXECUTOR_NOT_ROOT")
        }
        return Bundle().apply {
            putInt("rootUid", fields["rootUid"]!!.toInt())
            putInt("rootPid", fields["rootPid"]!!.toInt())
            putInt("managerUid", fields["managerUid"]!!.toInt())
            putInt("protocol", fields["protocol"]!!.toInt())
        }
    }

    override fun isEnabled(): Boolean = SuperuserControl.snapshot(context)?.enabled ?: false

    override fun setEnabled(enabled: Boolean) {
        // The jailbreak entry page is one of the transaction's write transports (design
        // §3.2). It no longer writes the legacy uid list: that list is import-only now.
        SuperuserControl.setEnabled(context, enabled).requireApplied()
    }

    override fun hasGrant(uid: Int): Boolean = granted(context, uid)

    override fun grant(uid: Int) {
        SuperuserControl.grant(context, uid).requireApplied()
    }

    override fun revoke(uid: Int) {
        val result = SuperuserControl.revoke(context, uid)
        if (result.ok) {
            // Revocation's third leg (design §6.8): the decision is already enforced; the
            // live sessions this uid owns must not survive it.
            val killed = SuperuserControl.killSessions(context, uid)
            StageMark.outputLine("proxy:revoke:killed=$killed")
        }
        result.requireApplied()
    }

    override fun grantCount(): Int = SuperuserControl.snapshot(context)?.let { snapshot ->
        val identities = dev.maplesu.manager.runtime.authorization.AndroidApplicationIdentities(context)
        snapshot.grants.keys.count { uid ->
            val identity = runCatching { identities.read(uid) }.getOrNull()
            ManagerSuperuserPolicy.decide(snapshot, uid, identity).allowed
        }
    } ?: 0

    /** One uid's decision, read through the same policy the endpoints use. */
    private fun granted(context: android.content.Context, uid: Int): Boolean {
        val snapshot = SuperuserControl.snapshot(context) ?: return false
        val identity = runCatching {
            dev.maplesu.manager.runtime.authorization.AndroidApplicationIdentities(context)
                .read(uid)
        }.getOrNull()
        return ManagerSuperuserPolicy.decide(snapshot, uid, identity).allowed
    }

    override fun start(argv: Array<String>?, owner: IBinder?, globalMnt: Boolean): IRootTask? {
        if (argv.isNullOrEmpty()) return null
        /*
         * Authorization, before anything is executed. The broker hands this binder to
         * other apps, so the caller is identified by Binder alone, and the answer is the
         * one shared decision (design §1.2) - the same codes the Ultra endpoint returns.
         */
        val caller = android.os.Binder.getCallingUid()
        val own = context.applicationInfo.uid
        val snapshot = SuperuserControl.snapshot(context)
        if (snapshot == null) {
            StageMark.outputLine("proxy:start:unavailable:$caller")
            return null
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
            StageMark.outputLine("proxy:start:denied:$caller:" + decision.reason)
            return null
        }
        val transport = JailbreakLeaseStore.eventTransport()
        val encoded = JailbreakLeaseArgv.encode(argv)
        // Push-based streaming: the executor emits output events per chunk, so the
        // App never polls and cannot lose a race with its own requests (DEV-33).
        val reply = transport.request("start $encoded format=argv1" + if (globalMnt) " globmnt=1" else "", 20)
        StageMark.outputLine("proxy:start:" + reply.take(120))
        if (!reply.startsWith("OK ")) return null
        val token = fields(reply)["token"]?.toIntOrNull() ?: return null
        return RemoteTask(token, transport)
    }

    private fun send(request: String, timeoutSeconds: Long = 10): String =
        JailbreakLeaseStore.request(request, timeoutSeconds)

    private fun fields(reply: String): Map<String, String> =
        reply.removePrefix("OK ").split(' ').filter { it.contains('=') }
            .associate { token ->
                val index = token.indexOf('=')
                token.substring(0, index) to token.substring(index + 1)
            }

    private fun decode(value: String?): ByteArray = try {
        if (value.isNullOrEmpty()) ByteArray(0) else Base64.decode(value, Base64.NO_WRAP)
    } catch (error: Throwable) {
        ByteArray(0)
    }

    private fun unsupported(operation: String): Nothing =
        throw UnsupportedOperationException(JailbreakDaemonMain.NOT_IMPLEMENTED + ":" + operation)

    /** A finished command exposed as an IRootTask through two pipes. */
    private class LocalTask(
        private val exitCode: Int,
        private val stdout: ByteArray,
        private val stderr: ByteArray,
    ) : IRootTask.Stub() {
        override fun openStdin(): ParcelFileDescriptor = pipe(ByteArray(0))

        override fun openStdout(): ParcelFileDescriptor = pipe(stdout)

        override fun openStderr(): ParcelFileDescriptor = pipe(stderr)

        override fun awaitExit(timeoutMillis: Int): Bundle = Bundle().apply {
            putInt("exitCode", exitCode)
        }

        override fun cancel() = Unit

        override fun close() = Unit

        private fun pipe(bytes: ByteArray): ParcelFileDescriptor {
            val pair = ParcelFileDescriptor.createPipe()
            val write = pair[1]
            Thread {
                runCatching {
                    FileOutputStream(write.fileDescriptor).use { stream ->
                        stream.write(bytes)
                        stream.flush()
                    }
                }
                runCatching { write.close() }
            }.apply { isDaemon = true; start() }
            return pair[0]
        }
    }

    /**
     * One streaming command. The pump is the only reader of `output`, so stdout and
     * stderr stay in order; the pipes give the caller ordinary file descriptors.
     */
    private inner class RemoteTask(private val token: Int, private val transport: JailbreakLeaseTransport) : IRootTask.Stub() {
        private val stdoutPipe = ParcelFileDescriptor.createPipe()
        private val stderrPipe = ParcelFileDescriptor.createPipe()
        private val out = FileOutputStream(stdoutPipe[1].fileDescriptor)
        private val err = FileOutputStream(stderrPipe[1].fileDescriptor)
        private val exitLatch = java.util.concurrent.CountDownLatch(1)
        @Volatile private var exit: Int? = null
        @Volatile private var childExit: Int? = null
        @Volatile private var streamFailure: String? = null
        @Volatile private var waitFailure: String? = null
        private val stdinLock = Any()
        @Volatile private var stdinClaimed = false
        @Volatile private var stdinInput: java.io.InputStream? = null
        @Volatile private var stdinThread: Thread? = null
        @Volatile private var inputCancelled = false
        @Volatile private var inputFailure: String? = null
        private val inputFailureLock = Any()
        private val closed = java.util.concurrent.atomic.AtomicBoolean(false)

        @Volatile private var registration: JailbreakLeaseTransport.Registration? = null
        @Volatile private var transportError: String? = null

        init {
            try { registration = transport.registerEvents(token) { event -> onEvent(event) } }
            catch (error: Throwable) {
                close()
                runCatching { stdoutPipe[0].close() }
                runCatching { stderrPipe[0].close() }
                throw error
            }
        }

        private fun send(request: String, timeoutSeconds: Long = 10): String =
            transport.request(request, timeoutSeconds)

        /*
         * Connected stdin (E2): the caller's writes are relayed into the child through
         * the executor's `stdin` op, and closing the caller's end sends the end-of-input
         * marker so an interactive child sees EOF. The previous implementation returned a
         * pipe whose write end was already closed, so every write failed and no
         * interactive shell could ever receive a command.
         *
         * The read end stays here; the caller receives a duplicate of the write end. A
         * process holding its own copy of the write end open would never observe EOF.
         */
        override fun openStdin(): ParcelFileDescriptor {
            synchronized(stdinLock) {
                check(!closed.get() && !inputCancelled && exit == null) { "SU_SESSION_CLOSED" }
                check(!stdinClaimed) { "SU_STDIN_ALREADY_CLAIMED" }
                stdinClaimed = true
                val pair = ParcelFileDescriptor.createPipe()
                val input = ParcelFileDescriptor.AutoCloseInputStream(pair[0])
                val handover = ParcelFileDescriptor.dup(pair[1].fileDescriptor)
                runCatching { pair[1].close() }
                stdinInput = input
                stdinThread = Thread {
                    val buffer = ByteArray(2048)
                    try {
                        while (!closed.get() && !inputCancelled && exit == null) {
                            val count = input.read(buffer)
                            if (count <= 0) break
                            if (!sendInput(Base64.encodeToString(buffer.copyOf(count), Base64.NO_WRAP))) return@Thread
                        }
                        if (!closed.get() && !inputCancelled && exit == null) sendInput("-")
                    } catch (error: Throwable) {
                        if (!closed.get() && !inputCancelled && exit == null) {
                            recordInputFailure(error.message ?: error.javaClass.simpleName)
                            runCatching { send("cancel $token") }
                        }
                    } finally {
                        runCatching { input.close() }
                    }
                }.apply { isDaemon = true; name = "maplesu-proxy-stdin-$token"; start() }
                return handover
            }
        }

        private fun sendInput(payload: String): Boolean {
            while (!closed.get() && !inputCancelled && inputFailure == null && exit == null) {
                when (val reply = send("stdin $token $payload")) {
                    "OK", "OK queued" -> return true
                    // Only this exact response guarantees that this block was not accepted.
                    "ERR JAILBREAK_EXECUTOR_STDIN_BACKPRESSURE" -> Thread.sleep(10)
                    else -> throw IllegalStateException(reply)
                }
            }
            return false
        }

        private fun recordInputFailure(reason: String) {
            synchronized(inputFailureLock) {
                if (inputFailure == null) {
                    inputFailure = reason
                    StageMark.outputLine("proxy:stdin:" + reason)
                }
            }
        }

        private fun stopInput() {
            inputCancelled = true
            stdinThread?.interrupt()
            runCatching { stdinInput?.close() }
        }

        override fun openStdout(): ParcelFileDescriptor = stdoutPipe[0]

        override fun openStderr(): ParcelFileDescriptor = stderrPipe[0]

        override fun awaitExit(timeoutMillis: Int): Bundle {
            val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(timeoutMillis.coerceAtLeast(0).toLong())
            while (exit == null && !closed.get() && observeTransportFailure() == null) {
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) break
                exitLatch.await(minOf(remaining, java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(25)), java.util.concurrent.TimeUnit.NANOSECONDS)
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

        override fun cancel() {
            if (closed.get() || exit != null) return
            inputCancelled = true
            stdinThread?.interrupt()
            try {
                val reply = send("cancel $token")
                check(reply == "OK") { reply }
            } finally { stopInput() }
        }

        override fun close() {
            if (!closed.compareAndSet(false, true)) return
            registration?.close() ?: transport.unregisterEvents(token)
            // Stop relaying input first: an open read end would keep the pump alive and
            // swallow the close's effect on the child.
            stopInput()
            runCatching { out.close() }
            runCatching { err.close() }
            runCatching { stdoutPipe[1].close() }
            runCatching { stderrPipe[1].close() }
            exitLatch.countDown()
            runCatching { send("close $token") }
        }

        private fun observeTransportFailure(): String? {
            val current = registration
            val failure = transportError ?: if (current != null) current.failure else transport.failure
            if (failure != null) failTransport(failure)
            return transportError
        }

        private fun failTransport(reason: String) {
            synchronized(inputFailureLock) {
                if (transportError != null) return
                transportError = reason
            }
            exitLatch.countDown()
            stopInput()
            // The independent failure path must also release a blocked listener write.
            runCatching { stdoutPipe[1].close() }
            runCatching { stderrPipe[1].close() }
            runCatching { out.close() }
            runCatching { err.close() }
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
                if (closed.get() || transportError != null || exit != null) return
                val kind = event.substringBefore(' ')
                val payload = event.substringAfter(' ', "")
                when (kind) {
                    "out" -> write(out, decode(payload, 4096))
                    "err" -> write(err, decode(payload, 4096))
                    "stdin-error" -> {
                        recordInputFailure(decode(payload).toString(Charsets.UTF_8))
                        stopInput()
                    }
                    "transport-error" -> failTransport(payload)
                    "exit" -> {
                        val code = readExitFacts(payload)
                        exit = code
                        stopInput()
                        runCatching { out.close() }
                        runCatching { err.close() }
                        runCatching { stdoutPipe[1].close() }
                        runCatching { stderrPipe[1].close() }
                        exitLatch.countDown()
                    }
                    else -> error("JAILBREAK_EVENT_KIND_INVALID")
                }
            } catch (error: Throwable) {
                failTransport(error.message?.takeIf { it.startsWith("JAILBREAK_EVENT_") }
                    ?: "JAILBREAK_EVENT_SINK_FAILED")
                runCatching { send("close $token") }
                throw error
            }
        }

        private fun write(stream: FileOutputStream, bytes: ByteArray) {
            if (bytes.isEmpty()) return
            stream.write(bytes)
            stream.flush()
        }

        private fun decode(value: String, maxBytes: Int = 16_384): ByteArray = try {
            require(value.length <= ((maxBytes + 2) / 3) * 4)
            java.util.Base64.getDecoder().decode(value).also { require(it.size <= maxBytes) }
        } catch (error: Exception) {
            throw IllegalArgumentException("JAILBREAK_EVENT_BASE64_INVALID", error)
        }
    }
}
