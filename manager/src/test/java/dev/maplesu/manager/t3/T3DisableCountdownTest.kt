package dev.maplesu.manager.t3

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class T3DisableCountdownTest {
    @Test fun confirmedDisableExpiresAfterThreeSeconds() {
        var now = 50_000L
        val countdown = T3DisableCountdown { now }
        assertNull(countdown.remainingSeconds())
        countdown.confirm()
        assertEquals(3, countdown.remainingSeconds())
        now += 999L
        assertEquals(3, countdown.remainingSeconds())
        now += 1L
        assertEquals(2, countdown.remainingSeconds())
        now += 1_000L
        assertEquals(1, countdown.remainingSeconds())
        now += 1_000L
        assertEquals(0, countdown.remainingSeconds())
        now += 10_000L
        assertEquals(0, countdown.remainingSeconds())
    }

    @Test fun recreationAndRepeatedResponsesDoNotRestartDeadline() {
        var now = 0L
        val countdown = T3DisableCountdown { now }
        countdown.confirm()
        now = 2_500L
        countdown.confirm()
        assertEquals(1, countdown.remainingSeconds())
        now = 3_000L
        countdown.confirm()
        assertEquals(0, countdown.remainingSeconds())
    }
}
