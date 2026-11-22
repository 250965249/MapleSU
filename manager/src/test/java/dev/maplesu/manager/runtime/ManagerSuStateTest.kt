package dev.maplesu.manager.runtime

import org.junit.Assert.assertEquals
import org.junit.Test

class ManagerSuStateTest {
    @Test fun hookGrantNeedsARealEntryBeforeReportingActive() {
        assertEquals(State.ENTRY_UNAVAILABLE, managerSuState(true, false, false, false))
        assertEquals(State.WIRED, managerSuState(true, false, false, true))
    }

    @Test fun pendingAuthorizationNeverPrescribesLaunchingTheTarget() {
        for (ready in listOf(false, true)) {
            assertEquals(State.AUTHORIZATION_PENDING, managerSuState(true, false, true, ready))
        }
    }

    @Test fun staleAndRevokedGrantsStayDistinctFromPublication() {
        for (ready in listOf(false, true)) {
            assertEquals(State.STALE, managerSuState(true, true, false, ready))
            assertEquals(State.NOT_AUTHORIZED, managerSuState(false, false, true, ready))
        }
    }
}
