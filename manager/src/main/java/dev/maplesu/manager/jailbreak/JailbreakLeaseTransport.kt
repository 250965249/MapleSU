package dev.maplesu.manager.jailbreak

import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.util.ArrayDeque
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** One original authenticated lease. No callback runs on its sole reader.
 * Finite queues fail the transport; they never turn shortened output into exit 0.
 * A blocked callback must be released by its owner's pipe close; it cannot be
 * killed safely here. Pools are process-wide, including retired lease workers. */
internal class JailbreakLeaseTransport(
    private val lease: RootShellLease,
    private val sequence: AtomicInteger,
    private val onFailure: (JailbreakLeaseTransport, String) -> Unit,
) {
    private val state = Any()
    private val writeLock = Any()
    private val channels = HashMap<Int, Channel>()
    private val waiters = ConcurrentHashMap<Int, ArrayBlockingQueue<Reply>>()
    private var activeChannels = 0
    private var queuedChars = 0
    private var readerStarted = false
    @Volatile var failure: String? = null
        private set

    private class Reply(val line: String? = null, val failure: String? = null)
    private class Channel {
        val events = ArrayDeque<String>()
        var chars = 0
        var listener: ((String) -> Unit)? = null
        var scheduled = false
        var retired = false
        var completed = false
        var errorDelivered = false
        var failure: String? = null
    }

    internal class Registration internal constructor(
        private val transport: JailbreakLeaseTransport,
        private val token: Int,
    ) : AutoCloseable {
        val failure: String? get() = transport.tokenFailure(token)
        override fun close() = transport.unregisterEvents(token)
    }

    fun registerEvents(token: Int, listener: (String) -> Unit): Registration {
        require(token > 0) { "JAILBREAK_EVENT_TOKEN_INVALID" }
        var schedule: Channel? = null
        var problem: String? = null
        synchronized(state) {
            val channel = channelLocked(token)
            if (channel == null) problem = "JAILBREAK_EVENT_TOKEN_LIMIT"
            else {
                check(!channel.retired && channel.listener == null) { "JAILBREAK_EVENT_ALREADY_REGISTERED" }
                channel.listener = listener
                if (!channel.scheduled && (channel.events.isNotEmpty() || failure != null)) {
                    channel.scheduled = true
                    schedule = channel
                }
            }
        }
        if (problem != null) {
            fail(problem)
            throw IOException(problem)
        }
        schedule?.let { schedule(token, it) }
        return Registration(this, token)
    }

    private fun tokenFailure(token: Int): String? = synchronized(state) {
        val channel = channels[token]
        channel?.failure ?: if (channel?.completed == true) null else failure
    }

    fun unregisterEvents(token: Int) {
        synchronized(state) {
            val channel = channels[token] ?: return
            retireLocked(channel)
        }
    }

    private fun channelLocked(token: Int): Channel? {
        channels[token]?.let { return it }
        if (activeChannels >= MAX_ACTIVE_TOKENS || channels.size >= MAX_TRACKED_TOKENS) return null
        return Channel().also { channels[token] = it; ++activeChannels }
    }

    private fun retireLocked(channel: Channel) {
        if (channel.retired) return
        channel.retired = true
        channel.listener = null
        --activeChannels
        queuedChars -= channel.chars
        channel.chars = 0
        channel.events.clear()
    }

    private fun acceptEvent(token: Int, event: String) {
        var schedule: Channel? = null
        var problem: String? = null
        synchronized(state) {
            if (failure != null) return
            val channel = channelLocked(token)
            if (channel == null) problem = "JAILBREAK_EVENT_TOKEN_LIMIT"
            else if (!channel.retired) {
                if (channel.events.size >= MAX_TOKEN_EVENTS ||
                    event.length > MAX_TOKEN_CHARS - channel.chars ||
                    event.length > MAX_TOTAL_CHARS - queuedChars) {
                    problem = "JAILBREAK_EVENT_BUFFER_LIMIT"
                } else {
                    channel.events.addLast(event)
                    channel.chars += event.length
                    queuedChars += event.length
                    if (channel.listener != null && !channel.scheduled) {
                        channel.scheduled = true
                        schedule = channel
                    }
                }
            }
        }
        if (problem != null) fail(problem)
        else schedule?.let { schedule(token, it) }
    }

    private fun schedule(token: Int, channel: Channel) {
        try { DELIVERIES.execute { drain(token, channel) } }
        catch (_: java.util.concurrent.RejectedExecutionException) {
            fail("JAILBREAK_EVENT_WORKER_LIMIT")
        }
    }

    private fun drain(token: Int, channel: Channel) {
        while (true) {
            val delivery = synchronized(state) {
                if (channels[token] !== channel || channel.retired || channel.listener == null) {
                    channel.scheduled = false
                    return
                }
                val terminal = failure
                if (terminal != null) {
                    if (channel.errorDelivered) {
                        channel.scheduled = false
                        return
                    }
                    channel.errorDelivered = true
                    channel.listener!! to "transport-error $terminal"
                } else {
                    val event = channel.events.pollFirst()
                    if (event == null) {
                        channel.scheduled = false
                        return
                    }
                    channel.chars -= event.length
                    queuedChars -= event.length
                    channel.listener!! to event
                }
            }
            try { delivery.first(delivery.second) }
            catch (_: Throwable) {
                synchronized(state) {
                    if (channel.failure == null)
                        channel.failure = failure ?: "JAILBREAK_EVENT_LISTENER_FAILED"
                    retireLocked(channel)
                    channel.scheduled = false
                }
                return
            }
            if (delivery.second.startsWith("exit ") || delivery.second.startsWith("transport-error ")) {
                synchronized(state) {
                    if (delivery.second.startsWith("exit ") && channel.failure == null)
                        channel.completed = true
                    retireLocked(channel)
                    channel.scheduled = false
                }
                return
            }
        }
    }

    fun request(line: String, timeoutSeconds: Long = 10): String =
        exchange(line, timeoutSeconds).firstOrNull().orEmpty()

    fun exchange(line: String, timeoutSeconds: Long): List<String> {
        require(line.length <= MAX_LINE_CHARS && '\n' !in line && '\r' !in line) {
            "JAILBREAK_REQUEST_FRAME_INVALID"
        }
        val queue = ArrayBlockingQueue<Reply>(1)
        val id: Int
        synchronized(state) {
            failure?.let { throw IOException(it) }
            if (waiters.size >= MAX_WAITERS) throw IOException("JAILBREAK_REQUEST_LIMIT")
            id = sequence.incrementAndGet()
            if (id <= 0) throw IOException("JAILBREAK_REQUEST_SEQUENCE_EXHAUSTED")
            waiters[id] = queue
        }
        try {
            ensureReader()
            synchronized(writeLock) {
                failure?.let { throw IOException(it) }
                lease.outputStream.write(("#$id $line" + System.lineSeparator()).toByteArray(Charsets.UTF_8))
                lease.outputStream.flush()
            }
            val reply = queue.poll(timeoutSeconds.coerceAtLeast(0), TimeUnit.SECONDS)
            failure?.let { throw IOException(it) }
            reply?.failure?.let { throw IOException(it) }
            if (reply == null) {
                fail("JAILBREAK_LEASE_REPLY_TIMEOUT")
                throw IOException(failure)
            }
            return listOf(reply.line.orEmpty())
        } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            fail("JAILBREAK_LEASE_REQUEST_INTERRUPTED")
            throw error
        } catch (error: IOException) {
            fail("JAILBREAK_LEASE_IO_FAILED")
            throw error
        } finally {
            waiters.remove(id, queue)
        }
    }

    private fun ensureReader() {
        val start = synchronized(state) {
            failure?.let { throw IOException(it) }
            if (readerStarted) false else { readerStarted = true; true }
        }
        if (start) {
            try { READERS.execute { readLoop() } }
            catch (_: java.util.concurrent.RejectedExecutionException) {
                fail("JAILBREAK_DISPATCHER_LIMIT")
                throw IOException(failure)
            }
        }
    }

    private fun readLoop() {
        try {
            val decoder = Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
            val reader = BufferedReader(InputStreamReader(lease.inputStream, decoder))
            while (failure == null) {
                val line = readLine(reader) ?: break
                if (line.startsWith("EVT ")) {
                    val split = line.indexOf(' ', 4)
                    val token = if (split > 4) line.substring(4, split).toIntOrNull() else null
                    if (token != null && token > 0) acceptEvent(token, line.substring(split + 1))
                } else if (line.startsWith("#")) {
                    val split = line.indexOf(' ')
                    val id = if (split > 1) line.substring(1, split).toIntOrNull() else null
                    if (id != null) waiters[id]?.offer(Reply(line.substring(split + 1)))
                }
            }
            fail("JAILBREAK_LEASE_EOF")
        } catch (_: CharacterCodingException) {
            fail("JAILBREAK_LEASE_FRAME_ENCODING_INVALID")
        } catch (_: Throwable) {
            fail("JAILBREAK_LEASE_READ_FAILED")
        }
    }

    private fun readLine(reader: BufferedReader): String? {
        val line = StringBuilder()
        while (true) {
            val char = reader.read()
            if (char < 0) {
                if (line.isNotEmpty()) throw IOException("JAILBREAK_LEASE_PARTIAL_FRAME")
                return null
            }
            if (char == 10) return line.toString().removeSuffix("\r")
            if (line.length >= MAX_LINE_CHARS) {
                fail("JAILBREAK_LEASE_FRAME_LIMIT")
                throw IOException("JAILBREAK_LEASE_FRAME_LIMIT")
            }
            line.append(char.toChar())
        }
    }

    /** Unknown completion is terminal for this lease, never replayed on another. */
    fun close(reason: String = "JAILBREAK_LEASE_RELEASED") = fail(reason)

    private fun fail(reason: String) {
        val deliveries = ArrayList<Pair<Int, Channel>>()
        synchronized(state) {
            if (failure != null) return
            failure = reason
            waiters.values.forEach { queue ->
                queue.poll()
                queue.offer(Reply(failure = reason))
            }
            channels.forEach { (token, channel) ->
                /* Output is explicitly failed, never reported as complete. Do
                 * not retain megabytes behind an irrecoverably blocked sink. */
                channel.events.clear()
                channel.chars = 0
                if (!channel.completed && channel.failure == null) channel.failure = reason
                if (!channel.retired && channel.listener != null && !channel.scheduled) {
                    channel.scheduled = true
                    deliveries.add(token to channel)
                }
            }
            queuedChars = 0
        }
        onFailure(this, reason)
        /* Closing the original lease unblocks only its reader/writer. A listener's
         * caller-owned pipe is closed by its Session observing failure. */
        runCatching { lease.close() }
        deliveries.forEach { (token, channel) -> schedule(token, channel) }
    }

    private companion object {
        const val MAX_ACTIVE_TOKENS = 32
        const val MAX_TRACKED_TOKENS = 4096
        const val MAX_TOKEN_EVENTS = 2048
        const val MAX_TOKEN_CHARS = 2 * 1024 * 1024
        const val MAX_TOTAL_CHARS = 8 * 1024 * 1024
        const val MAX_LINE_CHARS = 1024 * 1024
        const val MAX_WAITERS = 64
        val DELIVERIES = ThreadPoolExecutor(4, 4, 30, TimeUnit.SECONDS,
            ArrayBlockingQueue<Runnable>(32), { runnable ->
                Thread(runnable, "maplesu-lease-events").apply { isDaemon = true }
            })
        val READERS = ThreadPoolExecutor(2, 2, 30, TimeUnit.SECONDS,
            SynchronousQueue<Runnable>(), { runnable ->
                Thread(runnable, "maplesu-lease-reader").apply { isDaemon = true }
            })
    }
}
