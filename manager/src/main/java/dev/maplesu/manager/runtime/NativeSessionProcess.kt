package dev.maplesu.manager.runtime

import android.content.Context
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import android.system.StructTimeval
import java.io.File
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean

/** Explicit native file actions, not ProcessBuilder's unspecified extra-FD inheritance. */
internal class NativeSessionProcess private constructor(
    private val descriptors: IntArray,
    private val observeAndReap: (Int) -> Int,
) : Process() {
    private val child = descriptors[0]
    private val input = ParcelFileDescriptor.AutoCloseInputStream(ParcelFileDescriptor.adoptFd(descriptors[2]))
    private val error = ParcelFileDescriptor.AutoCloseInputStream(ParcelFileDescriptor.adoptFd(descriptors[3]))
    private val output = ParcelFileDescriptor.AutoCloseOutputStream(ParcelFileDescriptor.adoptFd(descriptors[1]))
    val control = Control(ParcelFileDescriptor.adoptFd(descriptors[4]))
    private val exited = CompletableFuture<Int>()
    private val reaped = AtomicBoolean(false)
    private val retireOnExit = AtomicBoolean(false)
    private val streamsClosed = AtomicBoolean(false)

    init {
        Thread({
            try {
                val code = observeAndReap(child)
                reaped.set(true)
                exited.complete(code)
                closeStreamsIfRetired()
            } catch (failure: Throwable) { exited.completeExceptionally(failure) }
        }, "maplesu-session-wait").apply { isDaemon = true; start() }
    }

    override fun getInputStream() = input
    override fun getErrorStream() = error
    override fun getOutputStream() = output
    override fun waitFor(): Int = exited.get()
    override fun waitFor(timeout: Long, unit: TimeUnit): Boolean = try {
        exited.get(timeout, unit)
        true
    } catch (_: TimeoutException) { false }
    override fun exitValue(): Int {
        if (!reaped.get()) throw IllegalThreadStateException("SESSION_RUNNING")
        return exited.get()
    }
    override fun isAlive(): Boolean = !reaped.get()
    override fun destroy() { control.close() }
    override fun destroyForcibly(): Process { control.close(); return this }

    internal fun retireAfterExit() {
        retireOnExit.set(true)
        runCatching { control.close() }
        closeStreamsIfRetired()
    }

    private fun closeStreamsIfRetired() {
        if (!retireOnExit.get() || !reaped.get() || !streamsClosed.compareAndSet(false, true)) return
        runCatching { input.close() }
        runCatching { error.close() }
        runCatching { output.close() }
    }

    internal class Control(private val descriptor: ParcelFileDescriptor) : AutoCloseable {
        private val lifecycle = Any()
        private var closed = false
        val inputStream = FileInputStream(descriptor.fileDescriptor)
        val outputStream = FileOutputStream(descriptor.fileDescriptor)
        private fun duplicate() = synchronized(lifecycle) {
            check(!closed) { "MAPLESU_SESSION_CONTROL_CLOSED" }
            ParcelFileDescriptor.dup(descriptor.fileDescriptor)
        }
        fun timeout(milliseconds: Int) = duplicate().use {
            Os.setsockoptTimeval(it.fileDescriptor, OsConstants.SOL_SOCKET, OsConstants.SO_RCVTIMEO,
                StructTimeval.fromMillis(milliseconds.toLong()))
        }
        fun sendDescriptors(streams: Array<FileDescriptor>) {
            val copies = ArrayList<ParcelFileDescriptor>(streams.size)
            try {
                streams.forEach { copies += ParcelFileDescriptor.dup(it) }
                duplicate().use {
                    SessionProcessLauncher.sendDescriptors(it.fd, copies.map { copy -> copy.fd }.toIntArray())
                }
            } finally { copies.forEach { runCatching { it.close() } } }
        }
        fun receiveTerminal(): FileDescriptor = duplicate().use { socket ->
            ParcelFileDescriptor.adoptFd(SessionProcessLauncher.receiveTerminal(socket.fd)).use {
                Os.dup(it.fileDescriptor)
            }
        }
        override fun close() = synchronized(lifecycle) {
            if (closed) return
            closed = true
            runCatching { Os.shutdown(descriptor.fileDescriptor, OsConstants.SHUT_RDWR) }
            descriptor.close()
        }
    }

    companion object {
        fun start(context: Context, argv: List<String>): NativeSessionProcess {
            return launch(context.applicationInfo.nativeLibraryDir, argv)
        }

        fun start(nativeLibraryDir: String, argv: List<String>): NativeSessionProcess {
            check(Os.getuid() == 0 && Os.geteuid() == 0) { "SU_ROOT_OWNER_REQUIRED" }
            return launch(nativeLibraryDir, argv)
        }

        fun startModule(nativeLibraryDir: String, argv: List<String>, environment: List<String>): NativeSessionProcess {
            check(Os.getuid() == 0 && Os.geteuid() == 0) { "SU_ROOT_OWNER_REQUIRED" }
            return launch(nativeLibraryDir, argv, environment)
        }

        private fun launch(nativeLibraryDir: String, argv: List<String>, moduleEnvironment: List<String>? = null): NativeSessionProcess {
            System.load(File(nativeLibraryDir, "libmaplesu_bootstrap.so").absolutePath)
            return NativeSessionProcess(
                argv.map { it.toByteArray(Charsets.UTF_8) }.toTypedArray().let { encoded ->
                    if (moduleEnvironment == null) SessionProcessLauncher.launch(encoded)
                    else SessionProcessLauncher.launchModule(encoded,
                        moduleEnvironment.map { it.toByteArray(Charsets.UTF_8) }.toTypedArray())
                },
            ) { child ->
                val code = SessionProcessLauncher.observeExit(child)
                SessionProcessLauncher.reap(child)
                code
            }
        }

        internal fun forTesting(descriptors: IntArray, observeAndReap: (Int) -> Int) =
            NativeSessionProcess(descriptors, observeAndReap)

        internal fun retireAndAwait(process: NativeSessionProcess): Boolean {
            process.retireAfterExit()
            return try { process.waitFor(1, TimeUnit.SECONDS) } catch (_: Exception) { false }
        }
    }
}

internal object SessionProcessLauncher {
    external fun launch(argv: Array<ByteArray>): IntArray
    external fun launchModule(argv: Array<ByteArray>, environment: Array<ByteArray>): IntArray
    external fun observeExit(child: Int): Int
    external fun reap(child: Int)
    // Diagnostic only: killing the owner bypasses su_session descendant cleanup.
    external fun terminate(child: Int, signal: Int)
    external fun sendDescriptors(control: Int, descriptors: IntArray)
    external fun receiveTerminal(control: Int): Int
}
