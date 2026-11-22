package dev.maplesu.manager.runtime

import android.os.Process
import android.os.ParcelFileDescriptor
import dev.maplesu.manager.runtime.authorization.ApplicationIdentity
import dev.maplesu.manager.runtime.authorization.AuthorizationPolicy
import dev.maplesu.manager.runtime.authorization.PackageIdentityReader
import dev.maplesu.manager.runtime.authorization.RootAuthorizationStore
import dev.maplesu.manager.runtime.authorization.SystemPackageSnapshotSource
import java.nio.file.Paths
import java.io.ByteArrayOutputStream
import java.io.ByteArrayInputStream
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.Base64
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Root executor entry point for jailbreak mode.
 *
 * DEV-10/DEV-11: libsu cannot drive the leased shell, so the launcher writes an
 * `exec app_process64 ...` line into the lease; the shell replaces itself with this
 * process, which then owns the lease stdin/stdout (DEV-24).
 *
 * Protocol: one request line in, one reply line out.
 *   `status`                  -> `OK rootUid=0 rootPid=<pid> managerUid=<uid> protocol=1`
 *   `ping`                    -> `OK pong`
 *   `protocol`                -> capability facts; prepare/PTY need root launch configuration
 *   `start <b64 argv> [cwd=<b64>] [env=<b64>] [globmnt=1]`
 *   `start <b64 argv vector> format=argv1 [globmnt=1]`
 *   `start <b64 NativeSuRequest> format=msu1`
 *                             -> `OK token=<n> pid=<pid>`
 *   `prepare <fullUid> <msu1>` -> `OK token=<n> prepared=1` (root re-resolves identity)
 *   `commit <token>`          -> final locked authority read and native one-byte release
 *   `terminal <token> <name> <challenge>` -> authenticated PTY FD-only transfer
 *   `resize <token> <r> <c> <x> <y>` -> existing native window frame
 *   `output <token>`          -> `OK exit=<code|running> out=<b64 delta> err=<b64 delta>`
 *   `wait <token> <timeoutMs>`-> `OK exit=<code|running>`
 *   Failed aggregate exits may append `childExit=<0..255>`, `streamError64=` and
 *   `waitError64=` facts. Legacy scalar -1 means unknown child exit, never a real code.
 *   `stdin <token> <b64|->`   -> `OK queued` (accepted, not yet written; `-` queues EOF)
 *   `signal <token> <number>` -> `OK` (native frame accepted, not delivery ACK; legacy uses kill)
 *   `cancel <token>`          -> `OK`
 *   `close <token>`           -> `OK`   (terminates the child, then forgets the task)
 * Anything else is refused with `ERR JAILBREAK_EXECUTOR_NOT_IMPLEMENTED <request>`.
 * Refusing is deliberate: the product must never see a fabricated success.
 *
 * E2: `stdin`/`signal` and a terminating `close` exist because the review measured the
 * previous executor: it had no way to write a child's input, and `close` only removed
 * the registry entry, so a closed task's process stayed alive (host fixture:
 * `AFTER_CLOSE taskRegistered=false childAlive=true`).
 */
object JailbreakDaemonMain {
    const val NOT_IMPLEMENTED = "JAILBREAK_EXECUTOR_NOT_IMPLEMENTED"
    private const val OK = "OK"
    private const val ERR = "ERR"
    private const val MAX_CAPTURE = 256 * 1024
    private const val MAX_FRAME = 140_000
    private const val MAX_STDIN_CHUNK = 4096
    private const val STDIN_QUEUE_CHUNKS = 16
    private const val STDIN_BACKPRESSURE = "ERR JAILBREAK_EXECUTOR_STDIN_BACKPRESSURE"
    private val STDIN_EOF = ByteArray(0)
    /** Platform helpers: the JVM cannot deliver an arbitrary signal or join a namespace. */
    private const val KILL_HELPER = "/system/bin/kill"
    private const val GLOBAL_MNT_HELPER = "/system/bin/nsenter"

    private class Task(val token: Int, val process: java.lang.Process,
                       val terminal: ParcelFileDescriptor? = null) {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        @Volatile var exit: Int? = null
        @Volatile var childExit: Int? = null
        @Volatile var waitFailure: String? = null
        @Volatile var streamFailure: String? = null
        @Volatile var drainedOut = 0
        @Volatile var drainedErr = 0
        val captureTruncated = AtomicBoolean(false)
        val finished = CountDownLatch(1)
        private val inputLock = Any()
        private val inputQueue = ArrayBlockingQueue<ByteArray>(STDIN_QUEUE_CHUNKS)
        private var inputEof = false
        private var pendingInput = 0
        @Volatile private var inputStopped = false
        @Volatile private var inputCancelled = false
        @Volatile var inputFailure: String? = null
            private set

        // Only this thread writes or closes child stdin; the command loop only offers.
        val inputThread = Thread({
            try {
                while (!inputStopped) {
                    val chunk = inputQueue.take()
                    if (chunk === STDIN_EOF || inputStopped) break
                    process.outputStream.write(chunk)
                    process.outputStream.flush()
                    synchronized(inputLock) { pendingInput -= chunk.size }
                }
            } catch (error: Throwable) {
                if (!(error is InterruptedException && inputStopped)) failInput(error)
            } finally {
                inputStopped = true
                try { process.outputStream.close() } catch (error: Throwable) { failInput(error) }
                synchronized(inputLock) {
                    if (pendingInput != 0 && !inputCancelled && inputFailure == null) {
                        inputFailure = stdinFailure("child exited with queued input")
                    }
                    inputQueue.clear()
                }
            }
        }, "maplesu-stdin-$token").apply { isDaemon = true; start() }

        fun offerInput(chunk: ByteArray): String = synchronized(inputLock) {
            inputFailure?.let { return it }
            if (inputStopped || inputEof || !process.isAlive) return "$ERR JAILBREAK_EXECUTOR_STDIN_CLOSED"
            if (!inputQueue.offer(chunk)) return STDIN_BACKPRESSURE
            pendingInput += chunk.size
            if (chunk === STDIN_EOF) inputEof = true
            "$OK queued"
        }

        fun stopInput(cancelled: Boolean = false) {
            synchronized(inputLock) {
                inputCancelled = inputCancelled || cancelled
                inputStopped = true
            }
            inputThread.interrupt()
        }

        @Synchronized fun failStream(kind: String, error: Throwable) {
            if (streamFailure == null) streamFailure = (kind + ": " + errorText(error)).take(1024)
        }

        // The leading scalar remains the aggregate result. Child facts never contain its -1 sentinel.
        fun exitFacts(code: Int? = exit): String {
            if (code == null) return ""
            return (childExit?.takeIf { it != code }?.let { " childExit=$it" } ?: "") +
                (streamFailure?.let { " streamError64=" + encodeError(it) } ?: "") +
                (waitFailure?.let { " waitError64=" + encodeError(it) } ?: "")
        }

        fun captureResult(): String = when {
            captureTruncated.get() -> "$ERR JAILBREAK_EXECUTOR_CAPTURE_LIMIT"
            waitFailure != null -> "$ERR JAILBREAK_EXECUTOR_WAIT_FAILED"
            streamFailure != null -> "$ERR JAILBREAK_EXECUTOR_STREAM_FAILED"
            inputFailure != null -> "$ERR JAILBREAK_EXECUTOR_STDIN_FAILED"
            else -> OK
        }

        private fun failInput(error: Throwable) {
            synchronized(inputLock) {
                if (!inputCancelled && inputFailure == null) {
                    inputFailure = stdinFailure(error.message ?: error.javaClass.simpleName)
                }
            }
        }
    }

    private fun errorText(error: Throwable): String = (error.message ?: error.javaClass.simpleName).take(1024)
    private fun encodeError(message: String): String = Base64.getEncoder().encodeToString(message.toByteArray(Charsets.UTF_8))
    private val tasks = ConcurrentHashMap<Int, Task>()
    private class Prepared(val uid: Int, val identity: ApplicationIdentity,
                           val child: JailbreakSupervisedChild) {
        val consumed = AtomicBoolean(false)
        var cancelled = false
    }
    private val prepared = ConcurrentHashMap<Int, Prepared>()
    private val commitWorkers = java.util.concurrent.ThreadPoolExecutor(0, 4, 30, TimeUnit.SECONDS,
        java.util.concurrent.SynchronousQueue<Runnable>(),
        { work -> Thread(work, "maplesu-su-commit").apply { isDaemon = true } })
    private var managerIdentityUid: Int = -1
    private var nativeLibraryDir: String? = null
    private var authority: AuthorizationPolicy? = null

    private fun configure(arguments: Array<String>, managerUid: Int): Int {
        if (arguments.getOrNull(1)?.startsWith("--su-native=") != true) return 1
        require(arguments.size >= 3 && arguments[2].startsWith("--su-legacy=")) { "SU_CONFIG_INVALID" }
        val library = decodeText(arguments[1].substringAfter('=')) ?: error("SU_CONFIG_INVALID")
        val legacy = decodeText(arguments[2].substringAfter('=')) ?: error("SU_CONFIG_INVALID")
        require(library.startsWith('/') && legacy.startsWith('/') && '\u0000' !in library && '\u0000' !in legacy)
        val policy = RootAuthorizationStore.open(managerUid, Paths.get(legacy),
            PackageIdentityReader(SystemPackageSnapshotSource(managerUid)))
        managerIdentityUid = managerUid
        nativeLibraryDir = library
        authority = policy
        return 3
    }
    private fun stdinFailure(message: String): String = "$ERR JAILBREAK_EXECUTOR_STDIN_FAILED error64=" +
        Base64.getEncoder().encodeToString(message.toByteArray(Charsets.UTF_8))
    /** Replies and pushed output events share one writer, so lines never interleave. */
    private val writer = Any()

    private fun emit(line: String) {
        synchronized(writer) {
            println(line)
            System.out.flush()
        }
    }
    private val nextToken = AtomicInteger(0)

    @JvmStatic
    fun main(arguments: Array<String>) {
        val managerUid = arguments.getOrNull(0)?.toIntOrNull() ?: -1
        System.err.println("maplesu-daemon: start uid=" + Process.myUid() +
            " manager=" + managerUid)
        if (Process.myUid() != 0 || managerUid <= 0) {
            System.err.println("maplesu-daemon: refused uid=${Process.myUid()} manager=$managerUid")
            System.exit(2)
        }
        val requestAt = configure(arguments, managerUid)
        val pid = Process.myPid()
        // Legacy one-shot diagnostics remain after optional trusted launch configuration.
        val single = if (arguments.size > requestAt) arguments.drop(requestAt).joinToString(" ") else null
        try {
            if (single != null) {
                println(handle(single, pid, managerUid))
                System.out.flush()
                return
            }
            val input = BufferedReader(InputStreamReader(System.`in`))
            while (true) {
                val line = input.readLine() ?: break
                val request = line.trim()
                if (request.isEmpty()) continue
                /*
                 * Replies carry the request's sequence number when the caller sends one
                 * ("#12 status" -> "#12 OK ..."), so the App can keep a single owner
                 * thread on the lease and dispatch replies instead of racing for them.
                 */
                val tag = if (request.startsWith("#")) request.substringBefore(' ') else ""
                val body = if (tag.isEmpty()) request else request.removePrefix(tag).trim()
                val respond = Runnable {
                    val payload = try {
                        handle(body, pid, managerUid)
                    } catch (error: Throwable) {
                        "$ERR JAILBREAK_EXECUTOR_FAILED " + (error.message ?: error.javaClass.simpleName)
                    }
                    emit(if (tag.isEmpty()) payload else "$tag $payload")
                }
                // Final authority I/O must not prevent this same lease receiving cancel.
                if (body.startsWith("commit ") && tag.isNotEmpty()) {
                    try { commitWorkers.execute(respond) }
                    catch (_: java.util.concurrent.RejectedExecutionException) {
                        emit("$tag $ERR SU_COMMIT_WORKER_LIMIT")
                    }
                } else respond.run()
            }
        } finally {
            // The original lease is this executor's owner. EOF, read failure or
            // one-shot return withdraws every child, never just its map entry.
            for (token in (tasks.keys + prepared.keys).toSet()) {
                val result = close(token)
                if (result != OK) System.err.println("maplesu-daemon: cleanup " + result)
            }
        }
        System.exit(0)
    }

    /** Visible to the unit tests so the real protocol can be driven on the host. */
    internal fun handle(request: String, pid: Int, managerUid: Int): String = when {
        request == "status" -> "$OK rootUid=0 rootPid=$pid managerUid=$managerUid protocol=1"
        request == "ping" -> "$OK pong"
        /*
         * Capability word: the App must be able to tell an executor that implements
         * stdin/signal from the older one that silently accepted no input at all.
         */
        request == "protocol" -> "$OK version=2 tasks=" + tasks.size +
            " stdin=1 signal=1 close=terminate pty=${if (authority != null) 1 else 0}" +
            " resize=${if (authority != null) 1 else 0} prepare=${if (authority != null) 1 else 0} startFormat=msu1" +
            " stdinAck=queued stdinMaxChunk=$MAX_STDIN_CHUNK stdinQueueChunks=$STDIN_QUEUE_CHUNKS"
        request.startsWith("prepare ") -> prepare(request.removePrefix("prepare ").split(' '))
        request.startsWith("commit ") -> commit(request.removePrefix("commit ").toIntOrNull())
        request.startsWith("terminal ") -> terminal(request.removePrefix("terminal ").split(' '), managerUid)
        request.startsWith("resize ") -> resize(request.removePrefix("resize ").split(' '))
        request.startsWith("start ") -> start(request.removePrefix("start ").trim(), push = true)
        request.startsWith("run ") -> runSync(request.removePrefix("run ").trim())
        request.startsWith("output ") -> output(request.removePrefix("output ").trim().toIntOrNull())
        request.startsWith("wait ") -> wait(request.removePrefix("wait ").trim().split(' '))
        request.startsWith("stdin ") -> stdin(request.removePrefix("stdin ").trim().split(' '))
        request.startsWith("signal ") -> signal(request.removePrefix("signal ").trim().split(' '))
        request.startsWith("cancel ") -> cancel(request.removePrefix("cancel ").trim().toIntOrNull())
        request.startsWith("close ") -> close(request.removePrefix("close ").trim().toIntOrNull())
        else -> "$ERR $NOT_IMPLEMENTED $request"
    }

    /**
     * Starts one command and returns its token immediately (streaming).
     *
     * <p>Options after the argv field are how a restricted `su` request keeps its
     * original meaning: `cwd=` sets the child's working directory, `env=` replaces the
     * inherited environment (an empty value means "no environment"), and `globmnt=1`
     * runs the child in init's mount namespace through `nsenter`. A management task
     * passes none of them and therefore keeps the executor's own environment. The
     * explicit `format=msu1` form instead carries the complete binary SU request.
     */
    private fun start(encoded: String, push: Boolean = false): String {
        val parts = encoded.split(' ').filter { it.isNotEmpty() }
        val argvEncoded = parts.firstOrNull() ?: return "$ERR JAILBREAK_EXECUTOR_BAD_REQUEST"
        var cwd: String? = null
        var environment: List<String>? = null
        var globalMnt = false
        val options = parts.drop(1)
        if (options.map { it.substringBefore('=') }.distinct().size != options.size) {
            return "$ERR JAILBREAK_EXECUTOR_BAD_REQUEST"
        }
        val argv = if ("format=argv1" in options) {
            if (options.any { it != "format=argv1" && it != "globmnt=1" }) {
                return "$ERR JAILBREAK_EXECUTOR_BAD_REQUEST"
            }
            globalMnt = "globmnt=1" in options
            try {
                JailbreakLeaseArgv.decode(argvEncoded)
            } catch (_: Exception) {
                return "$ERR JAILBREAK_EXECUTOR_BAD_REQUEST"
            }
        } else if (options.any { it.startsWith("format=") }) {
            if (options != listOf("format=msu1")) return "$ERR JAILBREAK_EXECUTOR_BAD_REQUEST"
            val request = try {
                require(argvEncoded.length <= ((MAX_FRAME + 2) / 3) * 4)
                val frame = Base64.getDecoder().decode(argvEncoded)
                require(frame.size <= MAX_FRAME)
                val input = ByteArrayInputStream(frame)
                NativeSuRequest.readFrom(input).also {
                    require(input.available() == 0 && it.terminals == 0 && it.targetUid == 0)
                }
            } catch (_: Exception) {
                return "$ERR JAILBREAK_EXECUTOR_BAD_REQUEST"
            }
            cwd = request.directory
            environment = request.environment
            globalMnt = request.globalMount
            // Keep the endpoint's existing executable/argv[0] selection semantics.
            if (request.arguments.first().startsWith('/')) request.arguments
            else listOf(request.executable) + request.arguments.drop(1)
        } else {
            for (option in options) {
                when {
                    option.startsWith("cwd=") -> cwd = decodeText(option.removePrefix("cwd="))
                        ?: return "$ERR JAILBREAK_EXECUTOR_BAD_REQUEST"
                    option.startsWith("env=") -> environment = decodeText(option.removePrefix("env="))
                        ?.split('\n')?.filter { it.isNotEmpty() }
                        ?: return "$ERR JAILBREAK_EXECUTOR_BAD_REQUEST"
                    option == "globmnt=1" -> globalMnt = true
                    else -> return "$ERR JAILBREAK_EXECUTOR_BAD_REQUEST"
                }
            }
            try {
                String(Base64.getDecoder().decode(argvEncoded), Charsets.UTF_8).split('\n')
            } catch (_: Exception) {
                return "$ERR JAILBREAK_EXECUTOR_BAD_REQUEST"
            }
        }
        if (argv.isEmpty() || argv.first().isEmpty()) return "$ERR JAILBREAK_EXECUTOR_BAD_ARGV"
        val command = if (globalMnt) listOf(GLOBAL_MNT_HELPER, "-t", "1", "-m", "--") + argv else argv
        val builder = ProcessBuilder(command).redirectErrorStream(false)
        cwd?.let { path ->
            val directory = java.io.File(path)
            if (!directory.isDirectory) return "$ERR JAILBREAK_EXECUTOR_BAD_CWD"
            builder.directory(directory)
        }
        environment?.let { entries ->
            val target = builder.environment()
            target.clear()
            for (entry in entries) {
                val index = entry.indexOf('=')
                if (index <= 0) return "$ERR JAILBREAK_EXECUTOR_BAD_ENVIRONMENT"
                target[entry.substring(0, index)] = entry.substring(index + 1)
            }
        }
        val process = try {
            builder.start()
        } catch (error: Throwable) {
            return "$ERR JAILBREAK_EXECUTOR_SPAWN_FAILED " + (error.message ?: "")
        }
        return attach(process, nextToken.incrementAndGet(), push)
    }

    private fun prepare(parts: List<String>): String {
        val policy = authority ?: return "$ERR SU_EXECUTOR_NOT_CONFIGURED"
        val library = nativeLibraryDir ?: return "$ERR SU_EXECUTOR_NOT_CONFIGURED"
        if (parts.size != 2) return "$ERR JAILBREAK_EXECUTOR_BAD_REQUEST"
        val uid = parts[0].toIntOrNull() ?: return "$ERR JAILBREAK_EXECUTOR_BAD_REQUEST"
        for ((token, pending) in prepared) {
            if (!pending.child.isAlive && prepared.remove(token, pending)) pending.child.close()
        }
        if (prepared.size + tasks.size >= 4) return "$ERR SU_SESSION_LIMIT"
        var child: JailbreakSupervisedChild? = null
        return try {
            val identity = if (uid == managerIdentityUid) policy.authorizeSelf(managerIdentityUid) else policy.authorize(uid)
            require(parts[1].length <= ((MAX_FRAME + 2) / 3) * 4)
            val frame = Base64.getDecoder().decode(parts[1])
            require(frame.size <= MAX_FRAME)
            val input = ByteArrayInputStream(frame)
            val request = NativeSuRequest.readFrom(input)
            require(input.available() == 0 && request.targetUid == 0) { "SU_TARGET_UID_UNAVAILABLE" }
            child = JailbreakSupervisedChild.prepare(library, request)
            val token = nextToken.incrementAndGet()
            prepared[token] = Prepared(uid, identity, child)
            "$OK token=$token prepared=1"
        } catch (error: Throwable) {
            child?.close()
            "$ERR SU_PREPARE_FAILED error64=" + encodeError(errorText(error))
        }
    }

    private fun commit(token: Int?): String {
        val pending = token?.let { prepared[it] } ?: return "$ERR SU_PREPARED_UNKNOWN"
        if (!pending.consumed.compareAndSet(false, true)) return "$ERR SU_PREPARED_CONSUMED"
        val child = pending.child
        var terminal: ParcelFileDescriptor? = null
        return try {
            val policy = authority ?: error("SU_EXECUTOR_NOT_CONFIGURED")
            val release = AuthorizationPolicy.Commit {
                synchronized(pending) {
                    check(!pending.cancelled) { "SU_SESSION_CANCELLED" }
                    child.commitNoWait()
                }
            }
            val released = if (pending.uid == managerIdentityUid) {
                policy.commitSelfIfEnabled(managerIdentityUid, pending.identity, release)
            } else policy.commitIfAuthorized(pending.uid, pending.identity, release)
            if (!released) {
                child.close()
                return "$ERR AUTH_REVOKED"
            }
            // The final authority lock covers only the one-byte release, never this read.
            child.awaitStarted()
            // Retain the master before waitFor closes supervisor control on a fast exit.
            terminal = child.openTerminal()
            synchronized(pending) {
                check(!pending.cancelled && prepared[token] === pending) { "SU_SESSION_CANCELLED" }
                attach(child, token, push = true, terminal = terminal).also { prepared.remove(token, pending) }
            }
        } catch (error: Throwable) {
            runCatching { terminal?.close() }
            child.close()
            "$ERR SU_COMMIT_FAILED error64=" + encodeError(errorText(error))
        }
    }

    private fun terminal(parts: List<String>, managerUid: Int): String {
        if (parts.size != 3) return "$ERR JAILBREAK_EXECUTOR_BAD_REQUEST"
        val task = parts[0].toIntOrNull()?.let { tasks[it] } ?: return "$ERR JAILBREAK_EXECUTOR_NO_TASK"
        val descriptor = task.terminal ?: return "$ERR SU_TERMINAL_UNAVAILABLE"
        return try {
            JailbreakTerminalTransfer.send(parts[1], parts[2], descriptor, managerUid)
            OK
        } catch (error: Throwable) {
            "$ERR SU_TERMINAL_TRANSFER_FAILED error64=" + encodeError(errorText(error))
        }
    }

    private fun resize(parts: List<String>): String {
        if (parts.size != 5) return "$ERR JAILBREAK_EXECUTOR_BAD_REQUEST"
        val task = parts[0].toIntOrNull()?.let { tasks[it] } ?: return "$ERR JAILBREAK_EXECUTOR_NO_TASK"
        val child = task.process as? JailbreakSupervisedChild ?: return "$ERR SU_RESIZE_UNAVAILABLE"
        if (task.terminal == null) return "$ERR SU_TERMINAL_UNAVAILABLE"
        return try {
            child.resize(parts.drop(1).map { requireNotNull(it.toIntOrNull()) }.toIntArray())
            OK
        } catch (error: Throwable) {
            "$ERR SU_RESIZE_FAILED error64=" + encodeError(errorText(error))
        }
    }

    private fun attach(process: java.lang.Process, token: Int, push: Boolean,
                       terminal: ParcelFileDescriptor? = null): String {
        val task = Task(token, process, terminal)
        tasks[token] = task
        val output = if (push) {
            /*
             * Push channel: the executor emits each chunk as its own event line, so
             * the App never polls and cannot lose a race with its own requests
             * (DEV-33). Events are ordinary `#seq`-less lines routed by token.
             */
            listOf(pump(process.inputStream, task, "out"), pump(process.errorStream, task, "err"))
        } else {
            listOf(reader(process.inputStream, task.out, task, "out"), reader(process.errorStream, task.err, task, "err"))
        }
        Thread {
            val childCode = try {
                process.waitFor().also { require(it in 0..255) { "JAILBREAK_CHILD_EXIT_INVALID:$it" } }
            } catch (error: Throwable) {
                task.waitFailure = errorText(error)
                runCatching { process.destroyForcibly() }
                null
            }
            var code = childCode ?: -1
            task.stopInput()
            var interrupted = false
            // Exit is the final event: both raw-byte streams must reach EOF first.
            for (thread in output + task.inputThread) {
                while (thread.isAlive) {
                    try {
                        thread.join()
                    } catch (_: InterruptedException) {
                        interrupted = true
                        task.failStream("drain", InterruptedException("JAILBREAK_STREAM_DRAIN_INTERRUPTED"))
                        code = -1
                        runCatching { process.destroyForcibly() }
                    }
                }
            }
            if (task.streamFailure != null) code = -1
            task.inputFailure?.let { failure ->
                if (code == 0) code = -1
                if (push) emit("EVT $token stdin-error " + Base64.getEncoder().encodeToString(failure.toByteArray(Charsets.UTF_8)))
            }
            task.childExit = childCode
            task.exit = code
            if (push) emit("EVT $token exit $code" + task.exitFacts())
            task.finished.countDown()
            if (interrupted) Thread.currentThread().interrupt()
        }.apply { isDaemon = true; start() }
        return "$OK token=$token"
    }

    /**
     * Synchronous variant: run one command to completion (bounded) and return its
     * status with the whole output. The AIDL probe needs a finished task, and this
     * keeps the reply a single line.
     */
    private fun runSync(encoded: String): String {
        val started = start(encoded)
        if (!started.startsWith("OK ")) return started
        val token = started.removePrefix("OK ").split(' ').firstOrNull { it.startsWith("token=") }
            ?.removePrefix("token=")?.toIntOrNull() ?: return "$ERR JAILBREAK_EXECUTOR_NO_TASK"
        val task = tasks[token] ?: return "$ERR JAILBREAK_EXECUTOR_NO_TASK"
        return try {
            if (!task.finished.await(10, TimeUnit.SECONDS)) return "$ERR JAILBREAK_EXECUTOR_TIMEOUT"
            val exit = task.exit ?: -1
            val out = Base64.getEncoder().encodeToString(take(task.out, 0))
            val err = Base64.getEncoder().encodeToString(take(task.err, 0))
            val result = task.captureResult()
            "$result exit=$exit" + task.exitFacts() +
                (task.inputFailure?.let { " stdinError64=" + encodeError(it) } ?: "") + " out=$out err=$err"
        } catch (error: Throwable) {
            if (error is InterruptedException) Thread.currentThread().interrupt()
            "$ERR JAILBREAK_EXECUTOR_WAIT_FAILED"
        } finally {
            close(token)
        }
    }

    private fun output(token: Int?): String {
        val task = token?.let { tasks[it] } ?: return "$ERR JAILBREAK_EXECUTOR_NO_TASK"
        val outDelta = take(task.out, task.drainedOut)
        val errDelta = take(task.err, task.drainedErr)
        task.drainedOut += outDelta.size
        task.drainedErr += errDelta.size
        val code = task.exit
        val exit = code?.toString() ?: "running"
        val result = task.captureResult()
        return "$result exit=$exit" + task.exitFacts(code) +
            (task.inputFailure?.let { " stdinError64=" + encodeError(it) } ?: "") + " out=" +
            Base64.getEncoder().encodeToString(outDelta) + " err=" +
            Base64.getEncoder().encodeToString(errDelta)
    }

    private fun wait(parts: List<String>): String {
        val token = parts.getOrNull(0)?.toIntOrNull() ?: return "$ERR JAILBREAK_EXECUTOR_NO_TASK"
        val timeout = parts.getOrNull(1)?.toLongOrNull() ?: 1000L
        val task = tasks[token] ?: return "$ERR JAILBREAK_EXECUTOR_NO_TASK"
        val deadline = System.currentTimeMillis() + timeout.coerceIn(0, 60_000)
        while (task.exit == null && System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(20)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                break
            }
        }
        val code = task.exit
        return "$OK exit=" + (code?.toString() ?: "running") + task.exitFacts(code)
    }

    private fun cancel(token: Int?): String {
        closePrepared(token)?.let { return it }
        val task = token?.let { tasks[it] } ?: return "$ERR JAILBREAK_EXECUTOR_NO_TASK"
        task.process.destroyForcibly()
        task.stopInput(cancelled = true)
        return OK
    }

    /**
     * Accepts one bounded chunk, or EOF, without waiting on the child pipe.
     *
     * <p>`-` is the end-of-input marker. Without it an interactive child (a shell, a
     * `cat`, a REPL) never learns that its caller finished, which is exactly the
     * "stdin is not connected" gap the review measured.
     */
    private fun stdin(parts: List<String>): String {
        val token = parts.getOrNull(0)?.toIntOrNull() ?: return "$ERR JAILBREAK_EXECUTOR_NO_TASK"
        val task = tasks[token] ?: return "$ERR JAILBREAK_EXECUTOR_NO_TASK"
        val payload = parts.getOrNull(1) ?: return "$ERR JAILBREAK_EXECUTOR_BAD_REQUEST"
        return try {
            require(parts.size == 2)
            val chunk = if (payload == "-") STDIN_EOF else {
                require(payload.length <= ((MAX_STDIN_CHUNK + 2) / 3) * 4)
                Base64.getDecoder().decode(payload).also { require(it.size in 1..MAX_STDIN_CHUNK) }
            }
            task.offerInput(chunk)
        } catch (error: Throwable) {
            stdinFailure(error.message ?: error.javaClass.simpleName)
        }
    }

    /** Native tasks use their existing supervisor frame; legacy tasks keep platform kill. */
    private fun signal(parts: List<String>): String {
        val token = parts.getOrNull(0)?.toIntOrNull() ?: return "$ERR JAILBREAK_EXECUTOR_NO_TASK"
        val number = parts.getOrNull(1)?.toIntOrNull() ?: return "$ERR JAILBREAK_EXECUTOR_BAD_SIGNAL"
        if (number !in 1..64) return "$ERR JAILBREAK_EXECUTOR_BAD_SIGNAL"
        val task = tasks[token] ?: return "$ERR JAILBREAK_EXECUTOR_NO_TASK"
        val supervised = task.process as? JailbreakSupervisedChild
        if (supervised != null) return try {
            if (task.exit == null) supervised.signal(number)
            OK
        } catch (error: Throwable) {
            "$ERR JAILBREAK_EXECUTOR_SIGNAL_FAILED error64=" + encodeError(errorText(error))
        }
        val pid = childPid(task.process)
        if (pid <= 0L) return "$ERR JAILBREAK_EXECUTOR_NO_TASK"
        val delivered = try {
            val kill = ProcessBuilder(KILL_HELPER, "-$number", pid.toString())
                .redirectErrorStream(true).start()
            kill.waitFor(5, java.util.concurrent.TimeUnit.SECONDS) && kill.exitValue() == 0
        } catch (error: Throwable) {
            false
        }
        return if (delivered || task.exit != null) OK else "$ERR JAILBREAK_EXECUTOR_SIGNAL_FAILED"
    }

    /**
     * Forgets one task **and terminates its child**.
     *
     * <p>The previous implementation only removed the registry entry, so the process
     * kept running after the caller closed the task (host fixture:
     * `AFTER_CLOSE taskRegistered=false childAlive=true`). A closed task is a cancelled
     * task: terminate first to unblock stdin, then recover streams and the writer.
     */
    private fun closePrepared(token: Int?): String? {
        val pending = token?.let { prepared[it] } ?: return null
        synchronized(pending) {
            if (prepared[token] !== pending) return null
            pending.consumed.set(true)
            pending.cancelled = true
        }
        pending.child.close()
        return try {
            if (!pending.child.waitFor(1, TimeUnit.SECONDS)) "$ERR JAILBREAK_EXECUTOR_CLOSE_PENDING"
            else { prepared.remove(token, pending); OK }
        } catch (error: Throwable) {
            if (error is InterruptedException) Thread.currentThread().interrupt()
            "$ERR JAILBREAK_EXECUTOR_CLOSE_PENDING error64=" + encodeError(errorText(error))
        }
    }

    private fun close(token: Int?): String {
        closePrepared(token)?.let { return it }
        val task = token?.let { tasks[it] } ?: return OK
        runCatching { task.process.destroy() }
        var reaped = task.childExit != null
        try {
            reaped = task.process.waitFor(1, TimeUnit.SECONDS)
            if (!reaped) {
                task.process.destroyForcibly()
                reaped = task.process.waitFor(1, TimeUnit.SECONDS)
            }
        } catch (error: Throwable) {
            runCatching { task.process.destroyForcibly() }
        } finally {
            task.stopInput(cancelled = true)
            runCatching { task.inputThread.join(1000) }
            runCatching { task.process.inputStream.close() }
            runCatching { task.process.errorStream.close() }
        }
        if (!reaped || task.inputThread.isAlive || task.process.isAlive || task.finished.count != 0L)
            return "$ERR JAILBREAK_EXECUTOR_CLOSE_PENDING"
        runCatching { task.terminal?.close() }
        (task.process as? JailbreakSupervisedChild)?.close()
        tasks.remove(token, task)
        return OK
    }

    private fun decodeText(encoded: String): String? = try {
        String(Base64.getDecoder().decode(encoded), Charsets.UTF_8)
    } catch (error: Throwable) {
        null
    }

    /**
     * The child's pid.
     *
     * <p>`Process.pid()` is not part of the Android SDK surface this module compiles
     * against, so the platform implementation's own method is used when it exists. A
     * missing pid is reported as "no task": the caller then gets an honest refusal
     * instead of a signal that was never delivered.
     */
    private fun childPid(process: java.lang.Process): Long = try {
        (process.javaClass.getMethod("pid").invoke(process) as? Number)?.toLong() ?: -1L
    } catch (error: Throwable) {
        -1L
    }

    private fun take(sink: ByteArrayOutputStream, from: Int): ByteArray = synchronized(sink) {
        val bytes = sink.toByteArray()
        if (from >= bytes.size) ByteArray(0) else bytes.copyOfRange(from, bytes.size)
    }

    /** Emits every chunk of one stream as a pushed event for the given task token. */
    private fun pump(stream: java.io.InputStream, task: Task, kind: String): Thread =
        Thread {
            try {
                stream.use {
                    val buffer = ByteArray(4096)
                    while (true) {
                        val read = stream.read(buffer)
                        if (read <= 0) break
                        val chunk = Base64.getEncoder().encodeToString(buffer.copyOf(read))
                        emit("EVT ${task.token} $kind $chunk")
                    }
                }
            } catch (error: Throwable) {
                task.failStream(kind, error)
            }
        }.apply { isDaemon = true; start() }

    private fun reader(stream: java.io.InputStream, sink: ByteArrayOutputStream, task: Task, kind: String): Thread = Thread {
        try {
            stream.use {
                val buffer = ByteArray(4096)
                while (true) {
                    val read = stream.read(buffer)
                    if (read <= 0) break
                    synchronized(sink) {
                        val accepted = read.coerceAtMost(MAX_CAPTURE - sink.size())
                        sink.write(buffer, 0, accepted)
                        if (accepted != read) task.captureTruncated.set(true)
                    }
                }
            }
        } catch (error: Throwable) {
            task.failStream(kind, error)
        }
    }.apply { isDaemon = true; start() }
}
