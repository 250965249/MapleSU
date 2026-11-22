package dev.maplesu.manager.jailbreak

import java.util.concurrent.Callable
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit

/** UI ownership only: late callbacks from an older task cannot change a newer task. */
internal data class JailbreakTaskUiState(
    val runId: Long = 0,
    val running: Boolean = false,
    val outcome: JailbreakController.Outcome? = null,
    val cancellationPending: Boolean = false,
    val cancellationFailed: Boolean = false,
    val startedAtMillis: Long = 0,
) {
    fun started() = JailbreakTaskUiState(runId = runId + 1, running = true,
        startedAtMillis = System.currentTimeMillis())

    fun completed(id: Long, result: JailbreakController.Outcome): JailbreakTaskUiState {
        if (id != runId || outcome != null) return this
        val displayed = if (result.stage == JailbreakStatus.STAGE_CANCELLED) {
            result.copy(failure = "JAILBREAK_CANCELLED")
        } else result
        return copy(running = false, outcome = displayed,
            cancellationPending = false, cancellationFailed = false)
    }

    fun finished(id: Long): JailbreakTaskUiState =
        if (id == runId) copy(running = false, cancellationPending = false) else this

    fun cancellationRequested(): JailbreakTaskUiState =
        if (running) copy(cancellationPending = true, cancellationFailed = false) else this

    fun cancellationFinished(id: Long, accepted: Boolean): JailbreakTaskUiState =
        if (id == runId && running) copy(cancellationPending = false, cancellationFailed = !accepted)
        else this
}

/** A blocked cancellation request must release the UI caller with failure feedback. */
internal fun jailbreakCancellationAccepted(
    budgetMillis: Long = 3_000,
    cancel: () -> Boolean,
): Boolean {
    val task = FutureTask(Callable(cancel))
    Thread(task, "maplesu-cancel-request").apply { isDaemon = true }.start()
    return try {
        task.get(budgetMillis, TimeUnit.MILLISECONDS)
    } catch (_: Exception) {
        false
    } finally {
        task.cancel(true)
    }
}
