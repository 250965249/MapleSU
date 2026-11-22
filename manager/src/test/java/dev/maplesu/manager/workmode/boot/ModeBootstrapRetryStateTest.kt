package dev.maplesu.manager.workmode.boot

import org.junit.Assert.*
import org.junit.Test

class ModeBootstrapRetryStateTest {
    private fun state() = ModeBootstrapRetryState(maxAttempts = 3, retryDelayMillis = 750)

    @Test fun warmupRetryAfterFinalDetectionSignalSurvivesUntilExecutionIsReleased() {
        val state = state()
        repeat(2) { state.tryStart(); state.finish(resolved = false) }
        assertEquals(3, state.tryStart())
        // finishDetection() has woken SDK warmup, but the phase-two finally has not run yet.
        assertFalse(state.requestRetry())
        assertNull(state.tryStart())
        assertEquals(0L, state.finish(resolved = false))
        assertEquals(1, state.tryStart())
    }

    @Test fun repeatedInFlightRequestsMergeIntoOneFreshBoundedRetrySeries() {
        val state = state()
        state.tryStart()
        repeat(16) { assertFalse(state.requestRetry()) }
        assertEquals(0L, state.finish(resolved = false))
        assertEquals(1, state.tryStart())
        assertEquals(750L, state.finish(resolved = false))
        assertEquals(2, state.tryStart())
        assertEquals(1_500L, state.finish(resolved = false))
        assertEquals(3, state.tryStart())
        assertNull(state.finish(resolved = false))
    }

    @Test fun automaticFailuresStopAfterThreeAttempts() {
        val state = state()
        assertEquals(1, state.tryStart())
        assertEquals(750L, state.finish(resolved = false))
        assertEquals(2, state.tryStart())
        assertEquals(1_500L, state.finish(resolved = false))
        assertEquals(3, state.tryStart())
        assertNull(state.finish(resolved = false))
    }

    @Test fun idleManualRequestStartsANewBudget() {
        val state = state()
        repeat(3) { state.tryStart(); state.finish(resolved = false) }
        assertTrue(state.requestRetry())
        assertEquals(1, state.tryStart())
    }

    @Test fun resolvedModeDropsPendingRetry() {
        val state = state()
        state.tryStart()
        assertFalse(state.requestRetry())
        assertNull(state.finish(resolved = true))
    }

    @Test fun concurrentStartIsRejectedUntilTheAttemptFinishes() {
        val state = state()
        assertEquals(1, state.tryStart())
        repeat(16) { assertNull(state.tryStart()) }
        state.finish(resolved = false)
        assertEquals(2, state.tryStart())
    }
}
