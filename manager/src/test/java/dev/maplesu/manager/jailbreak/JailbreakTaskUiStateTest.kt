package dev.maplesu.manager.jailbreak

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class JailbreakTaskUiStateTest {
    private fun failed() = JailbreakController.Outcome(JailbreakStatus.STAGE_FAILED,
        "failed", "HOOK_PREPARE_TIMEOUT")

    @Test fun completedResultReleasesRunningWithoutAnotherStatusRead() {
        val running = JailbreakTaskUiState().started()
        val completed = running.completed(running.runId, failed())
        assertFalse(completed.running)
        assertEquals(failed(), completed.outcome)
        val ready = failed().copy(stage = JailbreakStatus.STAGE_DAEMON_READY, failure = null)
        assertEquals(ready, running.completed(running.runId, ready).outcome)
        val source = dialogSource()
        val completion = source.substringAfter("val completed = withContext(Dispatchers.IO)")
            .substringBefore("onMethodSelected =")
        assertFalse(completion.contains("JailbreakController.status(context)"))
    }

    @Test fun cancelledOutcomeKeepsCancellationInsteadOfALateTimeoutReason() {
        val running = JailbreakTaskUiState().started()
        val completed = running.completed(running.runId,
            failed().copy(stage = JailbreakStatus.STAGE_CANCELLED))
        assertFalse(completed.running)
        assertEquals(JailbreakStatus.STAGE_CANCELLED, completed.outcome?.stage)
        assertEquals("JAILBREAK_CANCELLED", completed.outcome?.failure)
    }

    @Test fun cancellationFailureIsVisibleAndAllowsRetry() {
        val running = JailbreakTaskUiState().started()
        val pending = running.cancellationRequested()
        assertTrue(pending.cancellationPending)
        val failed = pending.cancellationFinished(pending.runId, false)
        assertTrue(failed.running)
        assertFalse(failed.cancellationPending)
        assertTrue(failed.cancellationFailed)
        assertFalse(failed.cancellationRequested().cancellationFailed)
        assertTrue(dialogSource().contains("if (ui.cancellationFailed)"))
    }

    @Test fun acceptedCancellationWaitsForTheRealResult() {
        val running = JailbreakTaskUiState().started().cancellationRequested()
        val accepted = running.cancellationFinished(running.runId, true)
        assertTrue(accepted.running)
        assertFalse(accepted.cancellationPending)
        assertFalse(accepted.cancellationFailed)
        assertEquals(null, accepted.outcome)
    }

    @Test fun lateCancellationAndFinalizersDoNotChangeCompletedOrNewerTasks() {
        val first = JailbreakTaskUiState().started().cancellationRequested()
        val completed = first.completed(first.runId, failed())
        assertSame(completed, completed.cancellationFinished(first.runId, false))
        assertSame(completed, completed.completed(first.runId,
            failed().copy(stage = JailbreakStatus.STAGE_CANCELLED)))
        val second = completed.started()
        assertSame(second, second.cancellationFinished(first.runId, false))
        assertSame(second, second.completed(first.runId, failed()))
        assertSame(second, second.finished(first.runId))
        assertTrue(second.running)
    }

    @Test fun blockedCancellationHasABudgetAndReportsFailure() {
        val started = System.nanoTime()
        assertFalse(jailbreakCancellationAccepted(50) { Thread.sleep(60_000); true })
        assertTrue((System.nanoTime() - started) / 1_000_000 < 2_000)
        assertFalse(jailbreakCancellationAccepted { false })
        assertFalse(jailbreakCancellationAccepted { throw IllegalStateException("binder died") })
        assertTrue(jailbreakCancellationAccepted { true })
    }

    private fun dialogSource(): String {
        val root = sequenceOf(File("."), File("..")).first { File(it, "manager").isDirectory }
        return File(root, "manager/src/main/java/dev/maplesu/manager/jailbreak/JailbreakSelectionDialog.kt").readText()
    }
}
