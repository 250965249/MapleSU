package com.maplesu.core.ui.screen.executemoduleaction

import org.junit.Assert.assertEquals
import org.junit.Test

class ModuleActionStartGateTest {
    @Test fun aNewEntryStartsExactlyOnce() {
        val gate = ModuleActionStartGate(false, false)
        assertEquals(ModuleActionStart.START, gate.claim())
        repeat(10) { assertEquals(ModuleActionStart.ALREADY_STARTED, gate.claim()) }
    }

    @Test fun aRestoredRunningCommandIsReportedRatherThanRepeated() {
        val gate = ModuleActionStartGate(true, false)
        assertEquals(ModuleActionStart.RESTORED_RUNNING, gate.claim())
        assertEquals(ModuleActionStart.ALREADY_STARTED, gate.claim())
    }

    @Test fun aCompletedCommandIsNotRunAgainAfterProcessRestoration() {
        val gate = ModuleActionStartGate(true, true)
        assertEquals(ModuleActionStart.RESTORED_COMPLETE, gate.claim())
        assertEquals(ModuleActionStart.ALREADY_STARTED, gate.claim())
    }

    @Test fun completionMarkerAloneStillPreventsReplay() {
        assertEquals(ModuleActionStart.RESTORED_COMPLETE, ModuleActionStartGate(false, true).claim())
    }
}
