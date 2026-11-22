package dev.maplesu.manager.runtime

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import dev.maplesu.manager.jailbreak.JailbreakLeaseTransport
import java.io.FileDescriptor
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.ExecutionException
import java.util.concurrent.Future
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** FD-only adjunct to an already authorized private lease, never an execution channel.
 * Frame: 0x54 + exactly one SCM_RIGHTS FD on that first read, 32 raw challenge
 * bytes, then EOF. Caller retains send's PFD; receive returns a new CLOEXEC PFD.
 * Both phases share one 10-second deadline; overload fails instead of adding threads. */
internal object JailbreakTerminalTransfer {
    private const val MARKER = 0x54
    private const val TIMEOUT_SECONDS = 10L
    private val random = SecureRandom()
    private val workers = ThreadPoolExecutor(0, 8, 30, TimeUnit.SECONDS,
        SynchronousQueue<Runnable>(), { action -> Thread(action, "maplesu-terminal-transfer").apply { isDaemon = true } })
    // A stalled original lease write needs its actual owner closed, not another transport.
    private val closers = ThreadPoolExecutor(2, 2, 30, TimeUnit.SECONDS,
        ArrayBlockingQueue<Runnable>(16), { action -> Thread(action, "maplesu-terminal-cancel").apply { isDaemon = true } })

    @JvmStatic
    @Throws(IOException::class)
    fun send(name: String, challenge: String, terminal: ParcelFileDescriptor, expectedManagerUid: Int) {
        require(name.matches(Regex("[A-Za-z0-9._-]{1,100}"))) { "JAILBREAK_TERMINAL_NAME_INVALID" }
        val secret = decode(challenge)
        require(expectedManagerUid >= 0) { "JAILBREAK_TERMINAL_MANAGER_UID_INVALID" }
        if (Os.getuid() != 0 || Os.geteuid() != 0) throw IOException("JAILBREAK_TERMINAL_ROOT_REQUIRED")
        if (!Os.isatty(terminal.fileDescriptor)) throw IOException("JAILBREAK_TERMINAL_NOT_TTY")
        val deadline = Deadline()
        val resources = Resources()
        var task: Future<Unit>? = null
        try {
            task = submit {
                val socket = resources.socket(LocalSocket())
                // The deadline owner closes the socket even if connect/write blocks.
                socket.connect(LocalSocketAddress(name, LocalSocketAddress.Namespace.ABSTRACT))
                if (socket.peerCredentials.uid != expectedManagerUid)
                    throw IOException("JAILBREAK_TERMINAL_MANAGER_PEER_MISMATCH")
                socket.setFileDescriptorsForSend(arrayOf(terminal.fileDescriptor))
                try { socket.outputStream.write(MARKER) }
                finally { socket.setFileDescriptorsForSend(null) }
                socket.outputStream.write(secret)
                socket.shutdownOutput()
            }
            deadline.await(task)
        } finally {
            resources.close()
            task?.cancel(true)
        }
    }

    @JvmStatic
    @Throws(IOException::class)
    fun receive(transport: JailbreakLeaseTransport, token: Int, managerUid: Int): ParcelFileDescriptor {
        require(token > 0 && managerUid >= 0) { "JAILBREAK_TERMINAL_REQUEST_INVALID" }
        val deadline = Deadline()
        val resources = Resources()
        val tasks = ArrayList<Future<*>>(3)
        var completed = false
        var failure: Throwable? = null
        try {
            val status = submit { transport.request("status", deadline.seconds()) }.also { tasks += it }
            val pid = rootPid(deadline.await(status), managerUid)
            val name = "maplesu-pty-" + hex(ByteArray(16).also(random::nextBytes))
            val secret = ByteArray(32).also(random::nextBytes)
            val challenge = hex(secret)
            val server = resources.server(LocalServerSocket(name))
            val completions = ExecutorCompletionService<Unit>(workers)
            tasks += completions.submit(Callable {
                val socket = resources.socket(server.accept())
                val peer = socket.peerCredentials
                if (peer.uid != 0 || peer.pid != pid) throw IOException("JAILBREAK_TERMINAL_ROOT_PEER_MISMATCH")
                readTerminal(socket, secret, resources)
            })
            tasks += completions.submit(Callable {
                val reply = transport.request("terminal $token $name $challenge", deadline.seconds())
                if (reply != "OK") throw IOException(reply.ifEmpty { "JAILBREAK_TERMINAL_NO_REPLY" })
            })
            repeat(2) {
                val result = completions.poll(deadline.remaining(), TimeUnit.NANOSECONDS)
                    ?: throw IOException("JAILBREAK_TERMINAL_TIMEOUT")
                deadline.await(result)
            }
            val terminal = resources.takeTerminal()
            completed = true
            return terminal
        } catch (error: Throwable) {
            val original = when (error) {
                is InterruptedException -> {
                    Thread.currentThread().interrupt()
                    IOException("JAILBREAK_TERMINAL_INTERRUPTED", error)
                }
                is java.util.concurrent.RejectedExecutionException -> IOException("JAILBREAK_TERMINAL_WORKER_LIMIT", error)
                else -> error
            }
            failure = original
            throw original
        } finally {
            resources.close()
            if (!completed) {
                tasks.forEach { it.cancel(true) }
                if (tasks.isNotEmpty() && transport.failure == null) {
                    // Do not let a provider's close callback extend the caller's deadline.
                    try { closers.execute { transport.close("JAILBREAK_TERMINAL_TRANSFER_CANCELLED") } }
                    catch (error: java.util.concurrent.RejectedExecutionException) { failure?.addSuppressed(error) }
                }
            }
        }
    }

    private fun readTerminal(socket: LocalSocket, secret: ByteArray, resources: Resources) {
        val input = socket.inputStream
        var held = emptyArray<FileDescriptor>()
        try {
            val marker = input.read()
            // No readFully here: LocalSocket ancillary state belongs to the LAST read.
            held = socket.ancillaryFileDescriptors ?: emptyArray()
            if (marker != MARKER || held.size != 1) throw IOException("JAILBREAK_TERMINAL_FD_FRAME_INVALID")
            val descriptor = held.single()
            cloexec(descriptor)
            if (!Os.isatty(descriptor)) throw IOException("JAILBREAK_TERMINAL_NOT_TTY")
            val received = ByteArray(32)
            var offset = 0
            while (offset < received.size) {
                val count = input.read(received, offset, received.size - offset)
                rejectExtra(socket)
                if (count <= 0) throw IOException("JAILBREAK_TERMINAL_CHALLENGE_TRUNCATED")
                offset += count
            }
            if (!MessageDigest.isEqual(received, secret)) throw IOException("JAILBREAK_TERMINAL_CHALLENGE_MISMATCH")
            val tail = input.read()
            rejectExtra(socket)
            if (tail != -1) throw IOException("JAILBREAK_TERMINAL_TRAILING_DATA")
            val copy = ParcelFileDescriptor.dup(descriptor)
            try { cloexec(copy.fileDescriptor); resources.terminal(copy) }
            catch (error: Throwable) { runCatching { copy.close() }; throw error }
        } finally {
            held.forEach { runCatching { Os.close(it) } }
            // Also clean ancillary data if a read or frame validation itself failed.
            runCatching { socket.ancillaryFileDescriptors?.forEach { runCatching { Os.close(it) } } }
        }
    }

    private fun rejectExtra(socket: LocalSocket) {
        val extra = socket.ancillaryFileDescriptors ?: return
        if (extra.isNotEmpty()) {
            extra.forEach { runCatching { Os.close(it) } }
            throw IOException("JAILBREAK_TERMINAL_EXTRA_FD")
        }
    }

    private fun cloexec(fd: FileDescriptor) {
        Os.fcntlInt(fd, OsConstants.F_SETFD, Os.fcntlInt(fd, OsConstants.F_GETFD, 0) or OsConstants.FD_CLOEXEC)
    }

    private fun rootPid(reply: String, managerUid: Int): Int {
        if (!reply.startsWith("OK ")) throw IOException(reply.ifEmpty { "JAILBREAK_TERMINAL_STATUS_MISSING" })
        val fields = LinkedHashMap<String, String>()
        for (part in reply.substring(3).split(' ')) {
            val split = part.indexOf('=')
            if (split <= 0 || fields.put(part.substring(0, split), part.substring(split + 1)) != null)
                throw IOException("JAILBREAK_TERMINAL_STATUS_INVALID")
        }
        fun number(name: String): Int? = fields[name]?.let { value ->
            value.toIntOrNull()?.takeIf { it.toString() == value }
        }
        val pid = number("rootPid")
        if (fields.keys != setOf("rootUid", "rootPid", "managerUid", "protocol") ||
            number("rootUid") != 0 || pid == null || pid <= 1 || number("managerUid") != managerUid || number("protocol") != 1)
            throw IOException("JAILBREAK_TERMINAL_STATUS_INVALID")
        return pid
    }

    private fun decode(value: String): ByteArray {
        require(value.matches(Regex("[0-9a-f]{64}"))) { "JAILBREAK_TERMINAL_CHALLENGE_INVALID" }
        return ByteArray(32) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
    private fun hex(value: ByteArray): String = value.joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun <T> submit(action: () -> T): Future<T> = try { workers.submit(Callable(action)) }
        catch (error: java.util.concurrent.RejectedExecutionException) { throw IOException("JAILBREAK_TERMINAL_WORKER_LIMIT", error) }

    private class Deadline {
        private val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(TIMEOUT_SECONDS)
        fun remaining(): Long = (end - System.nanoTime()).takeIf { it > 0 }
            ?: throw IOException("JAILBREAK_TERMINAL_TIMEOUT")
        fun seconds(): Long = TimeUnit.NANOSECONDS.toSeconds(remaining()).coerceAtLeast(1)
        fun <T> await(task: Future<T>): T = try { task.get(remaining(), TimeUnit.NANOSECONDS) }
            catch (error: TimeoutException) { throw IOException("JAILBREAK_TERMINAL_TIMEOUT", error) }
            catch (error: InterruptedException) { Thread.currentThread().interrupt(); throw IOException("JAILBREAK_TERMINAL_INTERRUPTED", error) }
            catch (error: ExecutionException) { throw (error.cause ?: error) }
    }

    /** Registration and result publication race with cancellation under the same lock. */
    private class Resources : AutoCloseable {
        private val cleanup = ArrayList<() -> Unit>()
        private var closed = false
        private var result: ParcelFileDescriptor? = null
        private fun <T> own(value: T, close: (T) -> Unit): T = synchronized(this) {
            if (closed) { runCatching { close(value) }; throw IOException("JAILBREAK_TERMINAL_CANCELLED") }
            cleanup += { close(value) }
            value
        }
        fun socket(value: LocalSocket): LocalSocket = own(value) {
            runCatching { it.shutdownInput() }; runCatching { it.shutdownOutput() }; it.close()
        }
        fun server(value: LocalServerSocket): LocalServerSocket = own(value) {
            runCatching { Os.shutdown(it.fileDescriptor, OsConstants.SHUT_RDWR) }; it.close()
        }
        fun terminal(value: ParcelFileDescriptor) = synchronized(this) {
            if (closed) { value.close(); throw IOException("JAILBREAK_TERMINAL_CANCELLED") }
            result = value
        }
        fun takeTerminal(): ParcelFileDescriptor = synchronized(this) {
            if (closed) throw IOException("JAILBREAK_TERMINAL_CANCELLED")
            val value = result ?: throw IOException("JAILBREAK_TERMINAL_FD_MISSING")
            result = null
            value
        }
        override fun close() {
            val actions = synchronized(this) {
                if (closed) return
                closed = true
                val terminal = result
                result = null
                cleanup.asReversed().toList() + listOf({ terminal?.close(); Unit })
            }
            actions.forEach { runCatching { it() } }
        }
    }
}
