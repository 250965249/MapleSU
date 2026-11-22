package dev.maplesu.manager.runtime

import android.content.Context
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.Os
import android.system.OsConstants
import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean

/** Root-owned management tasks, separate from the ordinary application authorization surface. */
internal class RootManagementTasks(
    private val context: Context,
    private val verifier: ManagerCallerVerifier,
) : Closeable {
    private val tasks = HashSet<Task>()
    private val handles = HashSet<Task>()
    private var closed = false
    private val workers = Executors.newCachedThreadPool { runnable ->
        Thread(runnable, "maplesu-management-task").apply { isDaemon = true }
    }

    fun start(argv: Array<out String>?, owner: IBinder?, globalMnt: Boolean): IRootTask =
        startInternal(argv, owner, globalMnt, null)

    fun startModule(argv: Array<out String>?, owner: IBinder?, environment: Array<out String>?): IRootTask =
        startInternal(argv, owner, false, requireNotNull(environment) { "MODULE_ENVIRONMENT_REQUIRED" }.toList())

    private fun startInternal(argv: Array<out String>?, owner: IBinder?, globalMnt: Boolean,
        moduleEnvironment: List<String>?): IRootTask {
        val uid = Binder.getCallingUid()
        return verifier.withCallingManager {
            check(Process.myUid() == 0) { "MANAGEMENT_ROOT_REQUIRED" }
            val arguments = requireNotNull(argv) { "MANAGEMENT_ARGUMENTS_REQUIRED" }.toList()
            val task = Task(uid, requireNotNull(owner) { "MANAGEMENT_OWNER_REQUIRED" }, arguments, globalMnt, moduleEnvironment)
            synchronized(tasks) {
                check(!closed) { "MANAGEMENT_CLOSED" }
                check(tasks.size < 4) { "MANAGEMENT_TASK_LIMIT" }
                tasks.add(task)
                handles.add(task)
            }
            try { task.start(); task }
            catch (error: Exception) { task.release(); throw error }
        }
    }

    override fun close() {
        val active = synchronized(tasks) { closed = true; handles.toList() }
        active.forEach { it.release() }
        workers.shutdownNow()
    }

    private inner class Task(
        private val uid: Int,
        private val owner: IBinder,
        private val argv: List<String>,
        private val globalMnt: Boolean,
        private val moduleEnvironment: List<String>?,
    ) : IRootTask.Stub(), IBinder.DeathRecipient {
        private val released = AtomicBoolean(false)
        private val cancelRequested = AtomicBoolean(false)
        private val exited = CompletableFuture<Int>()
        private val endpoints = arrayOfNulls<ParcelFileDescriptor>(3)
        private val resources = ArrayList<ParcelFileDescriptor>()
        private val serverSockets = ArrayList<ParcelFileDescriptor>()
        private var running: MapleSuSupervisedProcess? = null
        private var linked = false
        private var processEnded = false
        private var pumpsRemaining = 3

        @Synchronized fun start() {
            check(!released.get()) { "MANAGEMENT_OWNER_DIED" }
            owner.linkToDeath(this, 0)
            linked = true
            val stdin = ParcelFileDescriptor.createSocketPair().also { resources.addAll(it) }
            val stdout = ParcelFileDescriptor.createSocketPair().also { resources.addAll(it) }
            val stderr = ParcelFileDescriptor.createSocketPair().also { resources.addAll(it) }
            serverSockets.addAll(listOf(stdin[0], stdout[1], stderr[1]))
            endpoints[0] = stdin[1]
            endpoints[1] = stdout[0]
            endpoints[2] = stderr[0]
            val process = if (moduleEnvironment == null) MapleSuSupervisedProcess.startRoot(context, argv, globalMnt)
                else MapleSuSupervisedProcess.startRootModule(context, argv, moduleEnvironment)
            running = process
            pump(ParcelFileDescriptor.AutoCloseInputStream(stdin[0]), process.process.outputStream)
            pump(process.process.inputStream, ParcelFileDescriptor.AutoCloseOutputStream(stdout[1]))
            pump(process.process.errorStream, ParcelFileDescriptor.AutoCloseOutputStream(stderr[1]))
            workers.execute {
                var code: Int? = null
                var failure: Exception? = null
                try { code = process.process.waitFor() }
                catch (error: Exception) {
                    process.cancel()
                    failure = error
                    if (error is InterruptedException) Thread.currentThread().interrupt()
                } finally {
                    process.closeControl()
                    synchronized(this) {
                        processEnded = true
                        // No command remains to consume input. Wake only the stdin
                        // pump; output sockets must still drain buffered command data.
                        runCatching { Os.shutdown(stdin[0].fileDescriptor, OsConstants.SHUT_RDWR) }
                        synchronized(tasks) { tasks.remove(this) }
                        finishDrained()
                    }
                    if (failure == null) exited.complete(checkNotNull(code))
                    else exited.completeExceptionally(failure)
                }
            }
        }

        override fun openStdin(): ParcelFileDescriptor = claim(0)
        override fun openStdout(): ParcelFileDescriptor = claim(1)
        override fun openStderr(): ParcelFileDescriptor = claim(2)

        private fun claim(index: Int): ParcelFileDescriptor {
            enforceOwner()
            synchronized(this) {
                check(!released.get()) { "MANAGEMENT_TASK_CLOSED" }
                val endpoint = checkNotNull(endpoints[index]) { "MANAGEMENT_STREAM_CLAIMED" }
                // Return an independent descriptor: cleanup may run before AIDL
                // serializes its result, so it must not close the returned object.
                val claimed = ParcelFileDescriptor.dup(endpoint.fileDescriptor)
                endpoints[index] = null
                endpoint.close()
                finishDrained()
                return claimed
            }
        }

        override fun awaitExit(timeoutMillis: Int): Bundle {
            enforceOwner()
            require(timeoutMillis in 0..30_000) { "MANAGEMENT_WAIT_INVALID" }
            return try {
                Bundle().apply {
                    putInt("exitCode", exited.get(timeoutMillis.toLong(), TimeUnit.MILLISECONDS))
                    putBoolean("finished", true)
                    putBoolean("cancelRequested", cancelRequested.get())
                }
            } catch (_: TimeoutException) {
                Bundle().apply { putBoolean("finished", false) }
            } catch (error: Exception) {
                if (error is InterruptedException) Thread.currentThread().interrupt()
                throw IllegalStateException("MANAGEMENT_WAIT_FAILED", error)
            }
        }

        override fun cancel() {
            enforceOwner()
            if (cancelRequested.compareAndSet(false, true)) running?.cancel()
        }

        override fun close() { enforceOwner(); release() }
        override fun binderDied() { release() }

        @Synchronized fun release() {
            if (!released.compareAndSet(false, true)) return
            serverSockets.forEach { descriptor ->
                runCatching { Os.shutdown(descriptor.fileDescriptor, OsConstants.SHUT_RDWR) }
            }
            running?.let { process ->
                process.cancel()
                process.closeControl()
                runCatching { process.process.outputStream.close() }
                runCatching { process.process.inputStream.close() }
                runCatching { process.process.errorStream.close() }
            }
            resources.forEach { runCatching { it.close() } }
            if (linked) runCatching { owner.unlinkToDeath(this, 0) }
            synchronized(tasks) { tasks.remove(this); handles.remove(this) }
        }

        private fun enforceOwner() {
            if (Binder.getCallingUid() != uid) throw SecurityException("MANAGEMENT_OWNER_MISMATCH")
            verifier.withCallingManager { }
        }

        private fun pump(input: InputStream, output: OutputStream) {
            workers.execute {
                try { input.use { source -> output.use { destination -> source.copyTo(destination) } } }
                catch (_: Exception) { if (!released.get() && !exited.isDone) running?.cancel() }
                finally {
                    synchronized(this) { pumpsRemaining--; finishDrained() }
                }
            }
        }

        @Synchronized private fun finishDrained() {
            if (released.get() || !processEnded || pumpsRemaining != 0 || endpoints.any { it != null }) return
            // All bytes have reached the client's socket buffers. Close our
            // originals without shutdown(), which would discard unread output.
            resources.forEach { runCatching { it.close() } }
            if (linked) {
                runCatching { owner.unlinkToDeath(this, 0) }
                linked = false
            }
            synchronized(tasks) { handles.remove(this) }
        }
    }
}
