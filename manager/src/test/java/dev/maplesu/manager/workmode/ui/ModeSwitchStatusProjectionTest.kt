package dev.maplesu.manager.workmode.ui

import dev.maplesu.manager.workmode.service.ClientStatus
import dev.maplesu.manager.workmode.service.SwitchOutcome
import dev.maplesu.manager.workmode.recovery.DiagnosticsSnapshot
import dev.maplesu.manager.workmode.recovery.DiagnosticsSwitchHead
import org.junit.Assert.*
import org.junit.Test

class ModeSwitchStatusProjectionTest {
    private fun status(
        state: String = "COMMIT", id: String = "switch-1",
        error: String = "", reboot: Boolean = false,
    ) = ClientStatus(
        switchId = id, state = state, stage = "S4", step = "4c",
        fromMode = "lite", toMode = "ksu", error = error, errorDetail = "",
        planSha256 = "", rebootRequired = reboot, bootObserved = false,
        canRollback = false, canResumeReboot = false, verifyFailures = 0, partitions = emptyList(),
    )

    @Test fun wrongIdAndReadFailureRetainKnownRunningState() {
        val previous = ModeSwitchUiState(switchId = "switch-1", phase = ModeSwitchPhase.RUNNING)
        assertEquals(previous, projectModeSwitchStatus(previous, null, "switch-1"))
        assertEquals(previous, projectModeSwitchStatus(previous, status(id = "other"), "switch-1"))
    }

    @Test fun initialReadFailureOnlyUnlocksWhenNoPendingFactExists() {
        val initial = ModeSwitchUiState(switchId = "switch-1")
        assertEquals(ModeSwitchPhase.MISSING, projectModeSwitchStatus(initial, null, "switch-1").phase)
        assertTrue(projectModeSwitchStatus(initial, null, "switch-1", knownPending = true).blocksBack)
    }

    @Test fun errorAndRebootFlagDoNotFinishAnActiveWrite() {
        val initial = ModeSwitchUiState(switchId = "switch-1")
        assertTrue(projectModeSwitchStatus(initial, status(error = "RETRYING", reboot = true), "switch-1").blocksBack)
        assertTrue(projectModeSwitchStatus(initial, status(state = "FUTURE"), "switch-1").blocksBack)
        assertTrue(projectModeSwitchStatus(initial, status(state = "REBOOT_REQUIRED", reboot = true),
            "switch-1", facadeExecuting = true).blocksBack)
    }

    @Test fun onlyKnownStatesProduceAnOutcomeAndIncompleteVerificationStaysFailed() {
        val initial = ModeSwitchUiState(switchId = "switch-1")
        assertEquals(ModeSwitchPhase.SUCCEEDED,
            projectModeSwitchStatus(initial, status("REBOOT_REQUIRED", reboot = true), "switch-1").phase)
        assertEquals(ModeSwitchPhase.SUCCEEDED,
            projectModeSwitchStatus(initial, status("VERIFIED"), "switch-1").phase)
        assertEquals(ModeSwitchPhase.FAILED,
            projectModeSwitchStatus(initial, status("VERIFIED"), "switch-1",
                completionFailureCode = "VERIFY_SUPERUSER_FAILED").phase)
        assertEquals(ModeSwitchPhase.NEEDS_RECOVERY,
            projectModeSwitchStatus(initial, status("RECOVERY_REQUIRED"), "switch-1").phase)
    }

    @Test fun restoredPartitionRetainsItsRebootActionUntilTheRestoredBootIsObserved() {
        val initial = ModeSwitchUiState(switchId = "switch-1")
        val waiting = projectModeSwitchStatus(initial, status("ROLLED_BACK", reboot = true), "switch-1")
        assertEquals(ModeSwitchPhase.FAILED, waiting.phase)
        assertEquals("ROLLED_BACK", waiting.stateWire)
        assertTrue(waiting.rebootRequired)
        assertFalse(waiting.blocksBack)
        assertFalse(projectModeSwitchStatus(waiting, status("ROLLED_BACK"), "switch-1").rebootRequired)
        assertFalse(projectModeSwitchStatus(initial, status("RECOVERY_REQUIRED", reboot = true), "switch-1").rebootRequired)
    }

    @Test fun pendingFlowTracksExecutionAndDoesNotClearForUnknownWireState() {
        WorkModeSwitchSession.finish(SwitchOutcome.Blocked("", "", emptyList()))
        WorkModeSwitchSession.begin()
        assertTrue(WorkModeSwitchSession.pendingFlow.value)
        WorkModeSwitchSession.finish(SwitchOutcome.AwaitingReboot("switch-1", status("REBOOT_REQUIRED")))
        WorkModeSwitchSession.observe(status("FUTURE"))
        assertTrue(WorkModeSwitchSession.pending)
        WorkModeSwitchSession.finish(SwitchOutcome.Verified("switch-1", status("VERIFIED")))
        assertFalse(WorkModeSwitchSession.pendingFlow.value)
    }

    @Test fun localRequestIdentityIsPreservedWhenAnOlderServiceRecordIsRead() {
        WorkModeSwitchSession.begin("new-request")
        try {
            WorkModeSwitchSession.observe(status(id = "old-task"))
            assertEquals("new-request", WorkModeSwitchSession.switchId)
            assertTrue(WorkModeSwitchSession.executing)
            assertTrue(WorkModeSwitchSession.pending)
        } finally {
            WorkModeSwitchSession.finish(SwitchOutcome.Blocked("", "", emptyList()))
        }
    }

    @Test fun diagnosticsNeedReadableMatchingKnownFacts() {
        val snapshot = DiagnosticsSnapshot(switchHead = DiagnosticsSwitchHead(
            switchId = "switch-1", state = "VERIFIED",
        ))
        assertEquals(DiagnosisSummary.UNAVAILABLE, diagnosisSummary(snapshot, "switch-1", false))
        assertEquals(DiagnosisSummary.UNKNOWN, diagnosisSummary(snapshot, "other", true))
        assertEquals(DiagnosisSummary.FINISHED, diagnosisSummary(snapshot, "switch-1", true))
        assertEquals(DiagnosisSummary.UNKNOWN, diagnosisSummary(snapshot.copy(
            switchHead = snapshot.switchHead!!.copy(state = "FUTURE"),
        ), "switch-1", true))
    }
}
