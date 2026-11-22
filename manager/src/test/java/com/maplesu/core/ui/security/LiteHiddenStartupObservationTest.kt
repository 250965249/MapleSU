package com.maplesu.core.ui.security

import dev.maplesu.manager.litehidden.LiteHiddenState
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class LiteHiddenStartupObservationTest {
    @Before fun reset() = LiteHiddenRuntime.resetForTest()
    @After fun cleanup() = LiteHiddenRuntime.resetForTest()

    @Test fun failedReadDoesNotConfirmTheFirstObservation() {
        LiteHiddenRuntime.markRealReadAttempted()
        LiteHiddenRuntime.update(LiteHiddenState.UNKNOWN)
        assertFalse(LiteHiddenRuntime.hasRealObservation())
        assertFalse(LiteHiddenRuntime.hasObservation())
        assertTrue(LiteHiddenRuntime.needsRealRead())
    }

    @Test fun failedRefreshDoesNotReplaceConfirmedHiddenOn() {
        LiteHiddenRuntime.update(LiteHiddenState.ON)
        LiteHiddenRuntime.update(LiteHiddenState.UNKNOWN)
        assertEquals(LiteHiddenState.ON, LiteHiddenRuntime.currentState())
        assertTrue(LiteHiddenRuntime.hasRealObservation())
    }

    @Test fun failedRefreshDoesNotReplaceConfirmedHiddenOff() {
        LiteHiddenRuntime.update(LiteHiddenState.OFF)
        LiteHiddenRuntime.update(LiteHiddenState.UNKNOWN)
        assertEquals(LiteHiddenState.OFF, LiteHiddenRuntime.currentState())
    }
}
