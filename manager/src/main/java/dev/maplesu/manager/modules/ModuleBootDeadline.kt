package dev.maplesu.manager.modules

import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.TimeUnit

/** Owns the foreground lifetime independently of a root IPC that may never return. */
internal class ModuleBootDeadline(
    private val finish: (String?) -> Unit,
    private val timer: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "maplesu-module-deadline").apply { isDaemon = true }
    },
) : AutoCloseable {
    private val finished = AtomicBoolean(false)
    private val lock = Any()
    private var activeStep: Any? = null

    fun <T> step(label: String, timeoutMillis: Long, work: () -> T): T {
        val token = Any()
        synchronized(lock) {
            check(!finished.get()) { "MODULE_BOOT_CANCELLED" }
            activeStep = token
        }
        val deadline = timer.schedule({ complete(label, token) }, timeoutMillis, TimeUnit.MILLISECONDS)
        return try {
            work().also { check(!finished.get()) { "MODULE_BOOT_CANCELLED" } }
        } finally {
            synchronized(lock) { if (activeStep === token) activeStep = null }
            deadline.cancel(false)
        }
    }

    private fun complete(timeoutStage: String?, token: Any? = null) {
        synchronized(lock) {
            if (token != null && activeStep !== token) return
            if (!finished.compareAndSet(false, true)) return
            activeStep = null
        }
        timer.shutdownNow()
        finish(timeoutStage)
    }

    override fun close() = complete(null)
}
