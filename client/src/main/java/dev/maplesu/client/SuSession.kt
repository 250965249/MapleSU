package dev.maplesu.client

import android.os.ParcelFileDescriptor
import android.system.OsConstants
import dev.maplesu.manager.runtime.INativeSuSession
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicBoolean

/**
 * One authorized Root session.
 *
 * <p>Ownership: the three stdio streams and the optional terminal descriptor belong
 * to this object and are closed by [close]. Data flows over those descriptors; the
 * Binder object only carries control (signal, resize, cancel) and the exit status,
 * so a chatty child cannot starve the control channel.
 *
 * <p>Local state is authoritative for "this session is finished": after [close] the
 * session rejects further data calls with `SU_SESSION_CLOSED` without an IPC round
 * trip, so a caller cannot mistake a transport failure for a live session.
 */
class SuSession internal constructor(
    val stdin: OutputStream,
    val stdout: InputStream,
    val stderr: InputStream,
    private val remote: INativeSuSession,
) : AutoCloseable {

    private val closed = AtomicBoolean(false)

    @Volatile
    private var observedExit: Int? = null

    /** The exit status once [awaitExit] has observed one, otherwise null. */
    val exitCode: Int?
        get() = observedExit

    /**
     * Claims the PTY master. At most once per session, and only when the request
     * asked for a terminal.
     */
    fun openTerminal(): ParcelFileDescriptor? {
        enforceOpen()
        return call("SU_TERMINAL_CLAIM_FAILED") { remote.openTerminal() }
    }

    /**
     * Waits up to [timeoutMillis] for the child to exit.
     *
     * @return the exit status (0..255), or null when the child was still running
     * when the timeout expired.
     */
    fun awaitExit(timeoutMillis: Int): Int? {
        enforceOpen()
        if (timeoutMillis !in 0..MAX_WAIT_MILLIS) {
            throw CooperativeSuException("SU_WAIT_TIMEOUT_INVALID", "timeout=$timeoutMillis")
        }
        val result = call("SU_WAIT_FAILED") { remote.awaitExit(timeoutMillis) }
        if (!result.getBoolean("finished")) return null
        val code = result.getInt("exitCode", -1)
        if (code !in 0..255) throw CooperativeSuException("SU_EXIT_CODE_INVALID", "exit=$code")
        observedExit = code
        return code
    }

    fun signal(signal: Int) {
        enforceOpen()
        if (signal !in ALLOWED_SIGNALS) {
            throw CooperativeSuException("SU_SIGNAL_INVALID", "signal=$signal")
        }
        call("SU_SIGNAL_FAILED") { remote.signal(signal) }
    }

    fun resize(rows: Int, cols: Int, xpixel: Int = 0, ypixel: Int = 0) {
        enforceOpen()
        val window = intArrayOf(rows, cols, xpixel, ypixel)
        if (window.any { it !in 0..MAX_WINDOW }) {
            throw CooperativeSuException("SU_WINDOW_INVALID", window.joinToString("x"))
        }
        call("SU_RESIZE_FAILED") { remote.resize(window) }
    }

    /** Requests cancellation; the Root side terminates the child's process group. */
    fun cancel() {
        if (closed.get()) return
        call("SU_CANCEL_FAILED") { remote.cancel() }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { remote.close() }
        runCatching { stdin.close() }
        runCatching { stdout.close() }
        runCatching { stderr.close() }
    }

    private fun enforceOpen() {
        if (closed.get()) throw CooperativeSuException("SU_SESSION_CLOSED")
    }

    private inline fun <T> call(fallback: String, block: () -> T): T = try {
        block()
    } catch (failure: Throwable) {
        throw CooperativeSuException.normalize(failure, fallback)
    }

    private companion object {
        const val MAX_WAIT_MILLIS = 30_000
        const val MAX_WINDOW = 65_535

        /** Mirrors the Root side's accepted set; anything else is rejected there too. */
        val ALLOWED_SIGNALS = setOf(
            OsConstants.SIGINT, OsConstants.SIGTERM, OsConstants.SIGHUP,
            OsConstants.SIGQUIT, OsConstants.SIGTSTP, OsConstants.SIGCONT,
        )
    }
}
