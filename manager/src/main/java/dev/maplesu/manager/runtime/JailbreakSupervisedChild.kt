package dev.maplesu.manager.runtime

import android.os.ParcelFileDescriptor
import android.system.Os
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** User streams belong to the transferred pipes, never the supervisor's stdio. */
internal class JailbreakSupervisedChild private constructor(
    private val supervisor: MapleSuSupervisedProcess,
    stdin: ParcelFileDescriptor,
    stdout: ParcelFileDescriptor,
    stderr: ParcelFileDescriptor,
) : Process(), AutoCloseable {
    private val input = ParcelFileDescriptor.AutoCloseInputStream(stdout)
    private val error = ParcelFileDescriptor.AutoCloseInputStream(stderr)
    private val output = ParcelFileDescriptor.AutoCloseOutputStream(stdin)
    private val closed = AtomicBoolean(false)

    fun commitNoWait() = supervisor.commitNoWait()
    fun awaitStarted() = supervisor.awaitStarted()
    fun openTerminal(): ParcelFileDescriptor? = supervisor.openTerminal()
    fun signal(signal: Int) = supervisor.signal(signal)
    fun resize(window: IntArray) = supervisor.resize(window)
    fun cancel() = supervisor.cancel()

    override fun getInputStream() = input
    override fun getErrorStream() = error
    override fun getOutputStream() = output
    override fun waitFor(): Int = supervisor.process.waitFor().also { supervisor.closeControl() }
    override fun waitFor(timeout: Long, unit: TimeUnit): Boolean =
        supervisor.process.waitFor(timeout, unit).also { if (it) supervisor.closeControl() }
    override fun exitValue(): Int = supervisor.process.exitValue().also { supervisor.closeControl() }
    override fun isAlive(): Boolean = supervisor.process.isAlive
    override fun destroy() = cancel()
    override fun destroyForcibly(): Process { cancel(); return this }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        cancel()
        runCatching { output.close() }
        runCatching { input.close() }
        runCatching { error.close() }
    }

    companion object {
        /** No user command runs until the root authorization owner commits this handle. */
        fun prepare(nativeLibraryDir: String, request: NativeSuRequest): JailbreakSupervisedChild {
            check(Os.getuid() == 0 && Os.geteuid() == 0) { "SU_ROOT_OWNER_REQUIRED" }
            val pipes = ArrayList<Array<ParcelFileDescriptor>>(3)
            var supervisor: MapleSuSupervisedProcess? = null
            var accepted = false
            try {
                repeat(3) { pipes += ParcelFileDescriptor.createPipe() }
                supervisor = MapleSuSupervisedProcess.prepareRootSu(nativeLibraryDir, request,
                    arrayOf(pipes[0][0].fileDescriptor, pipes[1][1].fileDescriptor, pipes[2][1].fileDescriptor))
                // The MSU1 request and all descriptor transfers are complete at PREPARED.
                supervisor.process.outputStream.close()
                supervisor.process.inputStream.close()
                supervisor.process.errorStream.close()
                val child = JailbreakSupervisedChild(supervisor, pipes[0][1], pipes[1][0], pipes[2][0])
                accepted = true
                return child
            } finally {
                if (!accepted) supervisor?.cancel()
                pipes.forEachIndexed { index, pair ->
                    pair.forEachIndexed { end, descriptor ->
                        if (!accepted || end == (if (index == 0) 0 else 1)) runCatching { descriptor.close() }
                    }
                }
            }
        }
    }
}
