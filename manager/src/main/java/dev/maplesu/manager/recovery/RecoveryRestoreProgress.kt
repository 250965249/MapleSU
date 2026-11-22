package dev.maplesu.manager.recovery

import java.util.concurrent.atomic.AtomicBoolean

/** Readable while pm install is running; a lost HTTP reply must not lose its result. */
class RecoveryRestoreProgress(
    private val handover: ManagerRestoreHandover,
    private val hiddenOff: () -> Boolean,
) {
    private val running = AtomicBoolean(false)
    @Volatile private var result: RecoveryRestoreReport? = null

    fun status(): RecoveryRestoreReport {
        if (running.get()) return RecoveryRestoreReport(true, restoring = true)
        val saved = result
        if (saved?.ok == false) return saved
        if (hiddenOff() && handover.confirmed()) {
            return (saved ?: RecoveryRestoreReport(true)).copy(awaitingConfirmation = false, completed = true)
        }
        if (handover.pending()) {
            return (saved ?: RecoveryRestoreReport(true)).copy(awaitingConfirmation = true)
        }
        return saved ?: RecoveryRestoreReport(true)
    }

    fun restore(action: () -> RecoveryRestoreReport): RecoveryRestoreReport {
        if (!running.compareAndSet(false, true)) return status()
        return try {
            action().also { result = it }
        } catch (_: Exception) {
            RecoveryRestoreReport(false, "RECOVERY_RESTORE_EXCEPTION").also { result = it }
        } finally {
            running.set(false)
        }
    }

    fun confirmed(report: RecoveryRestoreReport) {
        result = report
    }
}
