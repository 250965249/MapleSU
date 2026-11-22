package com.maplesu.core.ui.component.maple

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UltraIntroTimelineTest {
    @Test fun sweepReachesBothEdgesAndClampsOutsideProgress() {
        assertEquals(-44f, UltraIntroTimeline.front(-1f, -44f, 600f), .001f)
        assertEquals(-44f, UltraIntroTimeline.front(0f, -44f, 600f), .001f)
        assertEquals(600f, UltraIntroTimeline.front(1f, -44f, 600f), .001f)
        assertEquals(600f, UltraIntroTimeline.front(2f, -44f, 600f), .001f)
    }

    @Test fun revealAlwaysMovesToTheRight() {
        var previous = -44f
        for (step in 0..1000) {
            val position = UltraIntroTimeline.front(step / 1000f, -44f, 600f)
            assertTrue("step=$step, previous=$previous, position=$position", position >= previous)
            previous = position
        }
    }

    @Test fun glowSettlesWithoutASuddenPersistentOvershoot() {
        assertEquals(0f, UltraIntroTimeline.bloomBump(0f), .001f)
        assertEquals(0f, UltraIntroTimeline.bloomBump(.45f), .001f)
        assertEquals(1f, UltraIntroTimeline.bloomBump(.725f), .001f)
        assertEquals(0f, UltraIntroTimeline.bloomBump(1f), .001f)
        for (step in 0..1000) {
            val glow = UltraIntroTimeline.bloomBump(step / 1000f)
            assertTrue(glow >= -.0001f && glow <= 1.0001f)
        }
    }
}
