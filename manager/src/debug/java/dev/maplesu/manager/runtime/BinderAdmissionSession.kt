package dev.maplesu.manager.runtime

import android.content.Context
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.OsConstants
import java.io.File
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean

/** Debug-only fixed commands. No production grants, client command text, credentials or policy edits. */
internal class BinderAdmissionSessions(private val context: Context) {
    private val lock = Any()
    private val sessions = HashSet<Session>()
    private val started = HashMap<Int, Int>()
    private val completed = HashMap<Int, Int>()
    private val workers = Executors.newFixedThreadPool(4) { task ->
        Thread(task, "binder-admission-session").apply { isDaemon = true }
    }
    private val deadlines = Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "binder-admission-session-deadline").apply { isDaemon = true }
    }

    fun start(caller: Int, caseId: Int, streams: List<ParcelFileDescriptor>, owner: IBinder): INativeSuSession {
        require(caseId in 0..3 && streams.size == 3) { "BINDER_ADMISSION_FIXED_CASE_INVALID" }
        val session = Session(caller, owner, caseId)
        synchronized(lock) {
            check(sessions.size < 4) { "BINDER_ADMISSION_SESSION_LIMIT" }
            sessions.add(session)
        }
        try {
            session.start(streams)
            synchronized(lock) { started[caller] = (started[caller] ?: 0) + 1 }
            return session
        } catch (error: Exception) {
            session.release()
            synchronized(lock) { sessions.remove(session) }
            throw error
        }
    }

    fun stats(caller: Int): Bundle = synchronized(lock) {
        Bundle().apply {
            putInt("callingUid", caller)
            putInt("rootUid", Process.myUid())
            putInt("rootPid", Process.myPid())
            putInt("active", sessions.count { it.caller == caller })
            putInt("started", started[caller] ?: 0)
            putInt("completed", completed[caller] ?: 0)
            putInt("rootFdCount", File("/proc/self/fd").list()?.size ?: -1)
            val children = File("/proc/self/task").listFiles().orEmpty().flatMap { task ->
                runCatching { File(task, "children").readText().trim().split(Regex("\\s+")) }
                    .getOrDefault(emptyList()).mapNotNull(String::toIntOrNull)
            }.distinct().take(16).toIntArray()
            putIntArray("supervisorPids", children)
        }
    }

    fun close() {
        val live = synchronized(lock) { sessions.toList() }
        live.forEach { it.release() }
        deadlines.shutdown()
        workers.shutdown()
    }

    private inner class Session(val caller: Int, private val owner: IBinder, private val caseId: Int) :
        INativeSuSession.Stub(), IBinder.DeathRecipient {
        private val closed = AtomicBoolean(false)
        private val exited = CompletableFuture<Int>()
        private var running: MapleSuSupervisedProcess? = null
        private var terminal: ParcelFileDescriptor? = null
        private var terminalClaimed = false
        private var linked = false

        @Synchronized fun start(streams: List<ParcelFileDescriptor>) {
            owner.linkToDeath(this, 0)
            linked = true
            check(!closed.get()) { "BINDER_ADMISSION_OWNER_DEAD" }
            val process = MapleSuSupervisedProcess.startRootSu(context, request(caseId),
                streams.map { it.fileDescriptor }.toTypedArray())
            running = process
            try {
                terminal = process.terminal?.let { ParcelFileDescriptor.dup(it) }
                val timeout = deadlines.schedule({ release() }, 30, TimeUnit.SECONDS)
                workers.execute {
                    try {
                        if (!process.process.waitFor(40, TimeUnit.SECONDS)) {
                            process.cancel()
                            process.closeControl()
                            if (!process.process.waitFor(3, TimeUnit.SECONDS)) {
                                process.process.destroyForcibly()
                                check(process.process.waitFor(2, TimeUnit.SECONDS)) { "BINDER_ADMISSION_REAP_TIMEOUT" }
                            }
                        }
                        exited.complete(process.process.exitValue())
                    } catch (error: Exception) {
                        exited.completeExceptionally(error)
                    } finally {
                        timeout.cancel(false)
                        synchronized(this) { cleanResources() }
                        synchronized(lock) {
                            sessions.remove(this)
                            completed[caller] = (completed[caller] ?: 0) + 1
                        }
                    }
                }
            } catch (error: Exception) {
                process.cancel()
                process.closeControl()
                process.process.destroyForcibly()
                cleanResources()
                throw error
            }
        }

        override fun openTerminal(): ParcelFileDescriptor? {
            enforceOwner()
            return synchronized(this) {
                check(!closed.get() && !terminalClaimed) { "BINDER_ADMISSION_TERMINAL_CLAIMED" }
                terminalClaimed = true
                terminal.also { terminal = null }
            }
        }

        override fun awaitExit(timeoutMillis: Int): Bundle {
            enforceOwner()
            require(timeoutMillis in 0..10_000) { "BINDER_ADMISSION_WAIT_BOUND" }
            return Bundle().apply {
                putInt("callingUid", caller)
                putInt("rootUid", Process.myUid())
                putInt("rootPid", Process.myPid())
                putInt("caseId", caseId)
                try {
                    putInt("exitCode", exited.get(timeoutMillis.toLong(), TimeUnit.MILLISECONDS))
                    putBoolean("finished", true)
                } catch (_: TimeoutException) {
                    putBoolean("finished", false)
                }
            }
        }

        override fun signal(signal: Int) {
            enforceOwner()
            require(caseId == 2 && signal == OsConstants.SIGINT) { "BINDER_ADMISSION_FIXED_SIGNAL_ONLY" }
            synchronized(this) { checkNotNull(running).signal(signal) }
        }

        override fun resize(window: IntArray?) {
            enforceOwner()
            require(caseId == 1 && window != null && window.contentEquals(intArrayOf(35, 110, 0, 0))) {
                "BINDER_ADMISSION_FIXED_WINDOW_ONLY"
            }
            synchronized(this) { checkNotNull(running).resize(window) }
        }

        override fun cancel() { enforceOwner(); release() }
        override fun close() { enforceOwner(); release() }
        override fun binderDied() { release() }

        @Synchronized fun release() {
            if (!closed.compareAndSet(false, true)) return
            running?.cancel()
            cleanResources()
        }

        @Synchronized private fun cleanResources() {
            runCatching { terminal?.close() }
            terminal = null
            running?.let { process ->
                process.closeControl()
                runCatching { process.process.outputStream.close() }
                runCatching { process.process.inputStream.close() }
                runCatching { process.process.errorStream.close() }
            }
            if (linked) {
                runCatching { owner.unlinkToDeath(this, 0) }
                linked = false
            }
        }

        private fun enforceOwner() {
            if (Binder.getCallingUid() != caller) throw SecurityException("BINDER_ADMISSION_SESSION_OWNER")
        }
    }

    private fun request(caseId: Int): NativeSuRequest {
        val command = when (caseId) {
            0 -> "printf 'PID=%s\\nUID=%s\\nCWD=%s\\nENV=%s\\n' \"\$\$\" \"\$(/system/bin/id -u)\" \"\$PWD\" \"\$MAPLESU_ADMISSION\" >&2; /system/bin/cat; exit 37"
            1 -> "printf 'PID=%s\\nUID=%s\\n' \"\$\$\" \"\$(/system/bin/id -u)\"; /system/bin/stty size; IFS= read -r line; /system/bin/stty size; exit 37"
            else -> "printf 'PID=%s\\nUID=%s\\nREADY\\n' \"\$\$\" \"\$(/system/bin/id -u)\"; exec /system/bin/sleep 30"
        }
        return NativeSuRequest(if (caseId == 1) 7 else 0, 0, false, intArrayOf(25, 80, 0, 0),
            "/system/bin/sh", "/data/local/tmp", listOf("sh", "-c", command),
            listOf("PATH=/system/bin:/system/xbin", "MAPLESU_ADMISSION=fixture", "TERM=xterm-256color"))
    }
}
