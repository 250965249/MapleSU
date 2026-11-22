package dev.maplesu.manager.jailbreak

import android.content.Context
import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.util.Log
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * M1 (report `maplesu-ultra-attestation-stability-2026-10-31.md` §5): `accept()` with a
 * deadline.
 *
 * `LocalServerSocket.accept()` has no timeout of its own, and the old loop only checked
 * the deadline *between* accepts - so a listener nobody connected to parked its thread
 * forever, and through the binder claim that parked the whole `am instrument` run
 * (regression-1: 600 s, no output). This is the one place allowed to block on accept: it
 * runs on a throw-away thread, the caller waits at most [timeoutMillis], and the timeout
 * path closes the listening descriptor (which is what makes the blocked accept return -
 * `accept()` is not an interruptible point).
 *
 * <p>Top-level on purpose: the host tests drive it without touching an Android class.
 *
 * @param acceptor the blocking accept (typically `server::accept`).
 * @param onTimeout runs exactly once on the timeout path, before this returns null.
 * @return the accepted value, or null on timeout / when the acceptor failed.
 */
internal fun <T> boundedAccept(
    acceptor: () -> T?,
    timeoutMillis: Long,
    onTimeout: () -> Unit = {},
): T? {
    if (timeoutMillis <= 0L) return null
    val pool = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "maplesu-hook-accept").apply { isDaemon = true }
    }
    val future = pool.submit(Callable { acceptor() })
    return try {
        future.get(timeoutMillis, TimeUnit.MILLISECONDS)
    } catch (timeout: TimeoutException) {
        runCatching { onTimeout() }
        null
    } catch (thrown: Throwable) {
        // A failed accept is not evidence either way; the caller falls back to the
        // record on disk instead of propagating an exception across the claim.
        null
    } finally {
        future.cancel(true)
        pool.shutdownNow()
    }
}

/**
 * The listening half of the hook attestation handshake.
 *
 * The kernel worker cannot be the listener: an AF_UNIX socket's SID is fixed at
 * `bind()` time from the creating process's own sid, so a socket created by
 * `u:r:kernel:s0` stays labelled `kernel` no matter what the inode label says, and an
 * untrusted_app is refused `connectto` (measured: `tcontext=u:r:kernel:s0`,
 * `permissive=0`). Relabelling afterwards does not help - the sid lives on the socket
 * object, not on the inode.
 *
 * So the App listens here, in its own data directory, and the worker connects. The App
 * still reads the connector's **kernel-filled** ucred, which is the F2 evidence the
 * claim needs; nothing about SELinux policy has to change and the enforcement window
 * does not have to stay open for it.
 *
 * <p>**M2: exactly one listener, one dialect.** Before this revision the claim's
 * fallback deleted whatever file was at the socket path and bound its own listener -
 * including the attempt's own 300 s listener. That unlinked a live socket out from under
 * its `accept()`, so the worker's reverse connect could only ever see `errno=2`
 * (report R2). The listener is now a process-wide singleton: `listen()` arms it,
 * [handshake] only *reads what it recorded*, and only the thread that bound a socket may
 * unlink it.
 */
object HookAttestServer {

    private const val TAG = "MapleSUHookAttest"
    private const val FILE = "maplesu-hook-attest.json"

    /** The claim polls the record, never a socket: 50 ms is short and cheap. */
    private const val POLL_MILLIS = 50L

    /** A peer that connects and says nothing must not park the accept loop (P2). */
    private const val READ_TIMEOUT_MILLIS = 5000

    /**
     * "hello\n" as bytes, so no escape survives a round trip.
     *
     * This is the *only* producer of the hello line in the App: the worker's reverse
     * connect reads it and then writes its JSON (`bootstrap.c`, DEV-174).
     */
    private val HELLO = byteArrayOf(104, 101, 108, 108, 111, 10)

    /**
     * M2: the single listener of this process.
     *
     * `deadline` is the whole window; `ownsSocket` is true only for the thread that
     * created the file, which is the only thing allowed to delete it.
     */
    private class Listener(
        val attemptId: String,
        val socket: File,
        val binding: LocalSocket,
        val server: LocalServerSocket,
        val deadline: Long,
    ) {
        var thread: Thread? = null
    }

    private val listeners = Any()

    @Volatile private var listener: Listener? = null

    /**
     * M6-lite: what the listener last did (`idle`, `bound`, `bind_failed`, `accepted`,
     * `timeout`, `error:…`). It travels into the status message, so "the listener never
     * came up" and "it came up and nobody connected" stop looking identical in the
     * evidence (report Q1/U4) without a logcat.
     */
    @Volatile var lastOutcome: String = "idle"
        private set

    fun socketFile(context: Context, attemptId: String): File =
        File(DirtyfragAttempt.hookEvidence(context), HookWorker.socketName(attemptId))

    fun recordFile(context: Context): File = File(DirtyfragAttempt.hookEvidence(context), FILE)

    /**
     * Bind this process's listener for [attemptId] if it is not already running.
     *
     * Idempotent: a second call (the claim) reuses the socket the attempt already holds
     * instead of replacing it. Returns false only when no listener could be created -
     * the caller may still find a record on disk.
     */
    @JvmStatic
    @JvmOverloads
    fun ensureListening(context: Context, attemptId: String?, bootId: String?,
                        timeoutMillis: Int = 5000): Boolean {
        if (attemptId.isNullOrBlank() || timeoutMillis <= 0) return false
        synchronized(listeners) {
            val existing = listener
            if (existing != null && stillServing(existing, attemptId)) return true
            if (existing != null) stop(existing)
            val created = bind(context, attemptId, bootId, timeoutMillis) ?: return false
            listener = created
            lastOutcome = "bound"
            created.thread?.start()
            return true
        }
    }

    /**
     * Listen for one connection from the kernel worker and persist what it proved.
     *
     * `timeoutMillis` covers the whole wait: the worker is spawned during the attempt,
     * so a listener that gave up early would report a handshake that never happened
     * rather than one that failed.
     *
     * <p>The call is bounded end to end: it arms (or reuses) the listener, polls the
     * record file every 50 ms, and returns at the deadline whatever is on disk. It never
     * binds a second listener and never unlinks the attempt's own one.
     */
    @JvmStatic
    @JvmOverloads
    fun handshake(context: Context, attemptId: String?, bootId: String?,
                  timeoutMillis: Int = 5000): HookWorker.Attestation? {
        if (attemptId.isNullOrBlank()) return null
        val deadline = System.currentTimeMillis() + timeoutMillis
        runCatching { ensureListening(context, attemptId, bootId, timeoutMillis) }
            .onFailure { Log.w(TAG, "listener not armed: " + it) }
        return awaitRecord(context, attemptId, bootId, deadline)
    }

    /**
     * Listen in the background for the whole attempt.
     *
     * The worker outlives the App's attempt call, and it may connect at any point after
     * the restore, so this cannot be tied to one blocking call. The listener thread owns
     * the socket it binds and closes/unlinks it at the deadline.
     */
    @JvmStatic
    @JvmOverloads
    fun listen(context: Context, attemptId: String?, bootId: String?,
               timeoutMillis: Int = 300000) {
        if (attemptId.isNullOrBlank()) return
        val armed = runCatching { ensureListening(context, attemptId, bootId, timeoutMillis) }
            .onFailure { Log.w(TAG, "listener failed: " + it) }
            .getOrDefault(false)
        Log.w(TAG, "listener armed=" + armed + " attempt=" + attemptId.take(8) +
            " window=" + timeoutMillis + "ms")
    }

    /** The attestation this attempt recorded, or null when nothing was recorded. */
    @JvmStatic
    fun read(context: Context, attemptId: String?, bootId: String?): HookWorker.Attestation? {
        if (attemptId.isNullOrBlank()) return null
        val file = recordFile(context)
        if (file.isFile) {
            val body = runCatching { org.json.JSONObject(file.readText()) }.getOrNull()
            if (body != null && body.optString("attempt") == attemptId &&
                body.optString("boot") == bootId) {
                attestationOf(body)?.let { return it }
            }
        }
        return readDaemonRecord(context, attemptId, bootId)
    }

    // --- listener lifecycle -------------------------------------------------

    private fun stillServing(target: Listener, attemptId: String): Boolean =
        target.attemptId == attemptId &&
            System.currentTimeMillis() < target.deadline &&
            runCatching { target.server.fileDescriptor.valid() }.getOrDefault(false)

    private fun bind(context: Context, attemptId: String, bootId: String?,
                     timeoutMillis: Int): Listener? {
        val socket = socketFile(context, attemptId)
        runCatching { socket.parentFile?.mkdirs() }
        /*
         * Reached only when no listener of ours holds this name: whatever file is there
         * is a dead socket from a previous attempt or process. A live listener of this
         * process is never deleted (M2).
         */
        if (socket.exists() && !socket.delete()) {
            Log.w(TAG, "cannot remove stale socket " + socket.path)
            lastOutcome = "stale_socket:" + socket.name
            return null
        }
        // The native worker uses a pathname sockaddr_un. The String constructor
        // binds ABSTRACT instead, so it can never accept that connector.
        val binding = LocalSocket(LocalSocket.SOCKET_STREAM)
        val server = runCatching {
            binding.bind(LocalSocketAddress(socket.path, LocalSocketAddress.Namespace.FILESYSTEM))
            LocalServerSocket(binding.fileDescriptor)
        }.getOrElse { thrown ->
            runCatching { binding.close() }
            runCatching { socket.delete() }
            // Q1: a refused bind used to be one Log.w that no acceptance script reads.
            Log.w(TAG, "bind failed: " + thrown)
            lastOutcome = "bind_failed"
            return null
        }
        val target = Listener(attemptId, socket, binding, server,
            System.currentTimeMillis() + timeoutMillis)
        target.thread = Thread({ serve(context, target, bootId) }, "maplesu-hook-attest")
            .apply { isDaemon = true }
        return target
    }

    /**
     * The accept loop. Every accept is bounded by what is left of the window, and the
     * thread leaves at the deadline even when nobody ever connects.
     */
    private fun serve(context: Context, target: Listener, bootId: String?) {
        try {
            while (true) {
                val remaining = target.deadline - System.currentTimeMillis()
                if (remaining <= 0L) {
                    lastOutcome = "timeout"
                    return
                }
                val client = boundedAccept(
                    acceptor = { acceptWithRetry(target) },
                    timeoutMillis = remaining,
                    // Closing the descriptor is what wakes the blocked accept().
                    onTimeout = {
                        runCatching { target.server.close() }
                        runCatching { target.binding.close() }
                    },
                ) ?: return
                val recorded = runCatching { serveOne(context, target.attemptId, bootId, client) }
                    .onFailure { Log.w(TAG, "serve failed: " + it) }
                    .getOrDefault(false)
                runCatching { client.close() }
                if (recorded) {
                    lastOutcome = "accepted"
                    return
                }
            }
        } catch (thrown: Throwable) {
            lastOutcome = "error:" + (thrown.message ?: thrown.javaClass.simpleName)
            Log.w(TAG, "listener failed: " + thrown)
        } finally {
            stop(target)
        }
    }

    /** EINTR is not the end of the window; a closed listener is. */
    private fun acceptWithRetry(target: Listener): LocalSocket? {
        var attempts = 0
        while (attempts < 64) {
            try {
                return target.server.accept()
            } catch (interrupted: IOException) {
                if (!runCatching { target.server.fileDescriptor.valid() }.getOrDefault(false)) {
                    return null
                }
                attempts++
                runCatching { Thread.sleep(10) }
            }
        }
        return null
    }

    /** Close and unlink a listener only while this process still owns it. */
    private fun stop(target: Listener) {
        val owned: Boolean
        synchronized(listeners) {
            owned = listener === target
            if (owned) listener = null
        }
        runCatching { target.server.close() }
        runCatching { target.binding.close() }
        if (owned) runCatching { if (target.socket.exists()) target.socket.delete() }
    }

    private fun awaitRecord(context: Context, attemptId: String, bootId: String?,
                            deadline: Long): HookWorker.Attestation? {
        while (true) {
            read(context, attemptId, bootId)?.let { return it }
            val remaining = deadline - System.currentTimeMillis()
            if (remaining <= 0L) return null
            runCatching { Thread.sleep(minOf(POLL_MILLIS, remaining)) }
        }
    }

    /** One connection: hello out, the worker's JSON in, then the record on disk. */
    private fun serveOne(context: Context, attemptId: String, bootId: String?,
                         client: LocalSocket): Boolean {
        val credentials = client.peerCredentials
        // Bound the read as well: a peer that connects and says nothing would otherwise
        // hold this thread (P2) until the socket dies.
        runCatching { client.soTimeout = READ_TIMEOUT_MILLIS }
        // The hello says the listener is up; the worker re-reads the policy after it, so
        // the value it reports is the restored one.
        client.outputStream.write(HELLO)
        client.outputStream.flush()
        val line = client.inputStream.bufferedReader().readLine() ?: return false
        val body = runCatching { org.json.JSONObject(line) }.getOrNull() ?: return false
        val attempt = body.optString("attempt")
        val boot = body.optString("boot")
        if (credentials.uid != 0 || attempt != attemptId || boot != bootId) {
            Log.w(TAG, "rejected attestation uid=" + credentials.uid +
                " attempt=" + attempt + " boot=" + boot)
            return false
        }
        // peerPid and starttime are the kernel's own answer for the connector, not the
        // worker's claim about itself.
        val document = org.json.JSONObject()
            .put("schema", body.optString("schema"))
            // M4: the evidence source travels with the record, so the acceptance script
            // reads it instead of grepping a sentence out of `status.message` (S6).
            .put("source", HookWorker.SOURCE_UCRED)
            .put("peerPid", credentials.pid)
            .put("peerUid", credentials.uid)
            .put("pid", body.optLong("pid"))
            .put("domain", body.optString("domain"))
            .put("enforcing", body.optInt("enforcing", -1))
            .put("boot", boot)
            .put("attempt", attempt)
            .put("starttime", body.optLong("starttime"))
            .put("observedAtMillis", System.currentTimeMillis())
        writeAtomically(recordFile(context), document.toString())
        Log.w(TAG, "attestation recorded peerPid=" + credentials.pid +
            " enforcing=" + body.optInt("enforcing", -1))
        return true
    }

    /**
     * Fallback evidence: the worker's own record, rewritten after the restore.
     *
     * This is deliberately weaker than the socket path - there is no kernel-filled
     * ucred, only a file that uid 0 created, so the caller can say "a root,
     * kernel-domain worker ran for this boot and attempt and reads enforcing" but not
     * "this pid answered me". It exists because BOTH socket directions can be refused
     * by SELinux (app-to-kernel-socket by type rules, kernel-to-app-socket by the MLS
     * category constraint), and a chain that only works when neither applies would be
     * untestable on a real device.
     *
     * <p>M4 (report R3): this is exactly the path that made a PASS look like a ucred
     * handshake. It is now labelled [HookWorker.SOURCE_DAEMON_RECORD] and the claim says
     * "WEAK evidence" instead of "kernel-credentialed worker answered".
     */
    private fun readDaemonRecord(
        context: Context,
        attemptId: String,
        bootId: String?,
    ): HookWorker.Attestation? {
        val file = File(DirtyfragAttempt.hookEvidence(context), "maplesu-hook-daemon.json")
        if (!file.isFile) return null
        // Owner check: the App cannot create a root-owned file, so this at least proves
        // a uid-0 process wrote it after the attempt started.
        val owner = runCatching { android.system.Os.stat(file.path).st_uid }.getOrNull()
        if (owner != 0) {
            Log.w(TAG, "daemon record ignored: owner uid=" + owner)
            return null
        }
        val body = runCatching { org.json.JSONObject(file.readText()) }.getOrNull() ?: return null
        if (body.optString("attempt") != attemptId || body.optString("bootId") != bootId) {
            return null
        }
        if (body.optInt("uid", -1) != 0 || body.optString("domain") != "u:r:kernel:s0") {
            Log.w(TAG, "daemon record ignored: uid=" + body.optInt("uid", -1) +
                " domain=" + body.optString("domain"))
            return null
        }
        val enforcing = body.optInt("enforcingFinal", -1)
        if (enforcing != 1) {
            Log.w(TAG, "daemon record ignored: enforcingFinal=" + enforcing)
            return null
        }
        val pid = body.optInt("pid", -1)
        if (pid <= 0) return null
        Log.w(TAG, "attestation taken from the worker record (no ucred): pid=" + pid)
        return HookWorker.Attestation(
            peerUid = 0,
            peerPid = pid,
            replyPid = pid,
            replyNonce = "",
            replyBootId = body.optString("bootId"),
            replyAttempt = body.optString("attempt"),
            domain = body.optString("domain"),
            enforcing = enforcing,
            starttime = body.optLong("starttime", 0L),
            nonce = "",
            bootId = body.optString("bootId"),
            attempt = body.optString("attempt"),
            // L3 ABI v1: the same record carries the su gate. Recorded as observed;
            // SuGate is what turns it into an executable decision.
            suToken = body.optString("suToken").takeIf { it.isNotEmpty() && it != "null" },
            suGate = body.optString("suGate").takeIf { it.isNotEmpty() && it != "null" },
            source = HookWorker.SOURCE_DAEMON_RECORD,
        )
    }

    /**
     * The App's own record, written by [serveOne].
     *
     * Its source is structural, not a field to trust: only the listener writes this
     * file, and only after it accepted a connection whose ucred the kernel filled in.
     * The `source` key inside the JSON is for the evidence scripts (S2/S6), never a
     * decision input here.
     */
    private fun attestationOf(body: org.json.JSONObject): HookWorker.Attestation? {
        val peerPid = body.optInt("peerPid", -1)
        if (peerPid <= 0 || body.optInt("peerUid", -1) != 0) return null
        return HookWorker.Attestation(
            peerUid = body.optInt("peerUid", -1),
            peerPid = peerPid,
            replyPid = body.optInt("pid", -1),
            replyNonce = "",
            replyBootId = body.optString("boot"),
            replyAttempt = body.optString("attempt"),
            domain = body.optString("domain"),
            enforcing = body.optInt("enforcing", -1),
            starttime = body.optLong("starttime", 0L),
            nonce = "",
            bootId = body.optString("boot"),
            attempt = body.optString("attempt"),
            source = HookWorker.SOURCE_UCRED,
        )
    }

    private fun writeAtomically(target: File, text: String) {
        val temporary = File(target.parentFile, target.name + ".tmp")
        RandomAccessFile(temporary, "rws").use { handle ->
            handle.write(text.toByteArray(Charsets.UTF_8))
        }
        if (!temporary.renameTo(target)) {
            target.delete()
            temporary.renameTo(target)
        }
    }
}
