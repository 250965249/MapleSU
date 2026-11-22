package dev.maplesu.manager.runtime

import android.os.Binder
import android.os.IBinder
import android.os.ParcelFileDescriptor
import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** A real Process adapter for libsu Shell.Builder.build(process), with independent stdio. */
internal class RootManagementProcess private constructor(
    private val task: IRootTask,
    @Suppress("unused") private val owner: IBinder,
    private val onClose: () -> Unit,
) : Process(), Closeable {
    private val closed = AtomicBoolean(false)
    private val stdin: OutputStream
    private val stdout: InputStream
    private val stderr: InputStream
    @Volatile private var status: Int? = null

    init {
        val opened = ArrayList<ParcelFileDescriptor>(3)
        try {
            val input = task.openStdin().also { opened.add(it) }
            val output = task.openStdout().also { opened.add(it) }
            val error = task.openStderr().also { opened.add(it) }
            stdin = ParcelFileDescriptor.AutoCloseOutputStream(input)
            stdout = ParcelFileDescriptor.AutoCloseInputStream(output)
            stderr = ParcelFileDescriptor.AutoCloseInputStream(error)
        } catch (error: Exception) {
            runCatching { task.close() }
            opened.forEach { runCatching { it.close() } }
            throw error
        }
    }

    override fun getOutputStream(): OutputStream = stdin
    override fun getInputStream(): InputStream = stdout
    override fun getErrorStream(): InputStream = stderr

    override fun waitFor(): Int {
        while (true) {
            if (Thread.interrupted()) throw InterruptedException()
            status?.let { return it }
            poll(1000)?.let { return it }
        }
    }

    override fun waitFor(timeout: Long, unit: TimeUnit): Boolean {
        if (Thread.interrupted()) throw InterruptedException()
        if (status != null || poll(0) != null) return true
        val nanos = unit.toNanos(timeout)
        if (nanos <= 0) return false
        val started = System.nanoTime()
        while (true) {
            if (Thread.interrupted()) throw InterruptedException()
            val remaining = nanos - (System.nanoTime() - started)
            if (remaining <= 0) return status != null
            val millis = TimeUnit.NANOSECONDS.toMillis(remaining).coerceIn(1, 1000).toInt()
            if (poll(millis) != null) return true
        }
    }

    override fun exitValue(): Int = status ?: poll(0) ?: throw IllegalThreadStateException("MANAGEMENT_TASK_RUNNING")
    override fun isAlive(): Boolean = status == null && poll(0) == null
    override fun destroy() { close() }
    override fun destroyForcibly(): Process { close(); return this }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        try {
            runCatching { poll(0) }
            task.close()
        } finally {
            listOf(stdin, stdout, stderr).forEach { runCatching { it.close() } }
            onClose()
        }
    }

    private fun poll(timeoutMillis: Int): Int? {
        status?.let { return it }
        val result = task.awaitExit(timeoutMillis)
        return if (result.getBoolean("finished")) result.getInt("exitCode").also { status = it } else null
    }

    companion object {
        fun start(service: IRootManagementService, argv: List<String>, globalMnt: Boolean = false): RootManagementProcess {
            return start({ owner -> service.start(argv.toTypedArray(), owner, globalMnt) })
        }

        fun start(launch: (IBinder) -> IRootTask, onClose: () -> Unit = {}): RootManagementProcess {
            val owner = Binder()
            return RootManagementProcess(launch(owner), owner, onClose)
        }
    }
}
