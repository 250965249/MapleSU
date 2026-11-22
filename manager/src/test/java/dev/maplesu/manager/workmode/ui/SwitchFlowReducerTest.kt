package dev.maplesu.manager.workmode.ui

import dev.maplesu.manager.workmode.ModeCapabilities
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.detect.ModeState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** W08 切换流程的 reducer 表驱动（状态→UI 元素可见性）。 */
class SwitchFlowReducerTest {

    private fun ready(availability: SwitchAvailability): WorkModeUiState =
        WorkModeUiState()
            .reduce(
                WorkModeEvent.Detected(
                    state = ModeState.MODE_A_ACTIVE,
                    capabilities = ModeCapabilities.forMode(WorkMode.LITE),
                    current = WorkMode.LITE,
                    masked = false,
                    switchSupported = true,
                )
            )
            .reduce(WorkModeEvent.Availability(availability))

    private val canSwitch = SwitchAvailability(
        canSwitch = true,
        current = WorkMode.LITE,
        target = WorkMode.KSU,
        baselineId = "b-1",
    )

    @Test
    fun availabilityDoesNotGateOpeningProgress() {
        assertTrue(ready(canSwitch).canStartSwitch)
        val blocked = ready(canSwitch.copy(canSwitch = false, blockers = listOf(SwitchBlocker("X"))))
        assertTrue(blocked.canStartSwitch)
        assertTrue(blocked.availabilityCodes.contains("X"))
    }

    @Test
    fun backendUnavailableClearsSwitchSupportedFlag() {
        val blocked = ready(
            canSwitch.copy(
                canSwitch = false,
                blockers = listOf(SwitchBlocker(SwitchBlockerCodes.BACKEND_UNAVAILABLE)),
            )
        )
        assertFalse(blocked.switchSupported)
    }

    /** The backend evaluates the request after the progress route opens. */
    @Test
    fun tapStartsTheSwitchOnlyWhenStartable() {
        val running = ready(canSwitch).reduce(WorkModeEvent.StartSwitch(WorkMode.KSU))
        assertEquals(WorkModePhase.RUNNING, running.phase)

        val blocked = ready(canSwitch.copy(canSwitch = false))
        assertEquals(WorkModePhase.RUNNING, blocked.reduce(WorkModeEvent.StartSwitch(WorkMode.KSU)).phase)
    }

    @Test
    fun startThenStartedEntersRunningWithSwitchId() {
        val running = ready(canSwitch)
            .reduce(WorkModeEvent.StartSwitch(WorkMode.KSU))
            .reduce(WorkModeEvent.Started("sw-123"))
        assertEquals(WorkModePhase.RUNNING, running.phase)
        assertEquals("sw-123", running.runningSwitchId)
        assertTrue(running.blocksBack)
    }

    @Test
    fun startedKeepsRunningSwitchIdForProgressEntry() {
        val running = ready(canSwitch).reduce(WorkModeEvent.Started("sw-9"))
        assertEquals("sw-9", running.runningSwitchId)
    }

    @Test
    fun incompleteBeginShowsFailureWithoutManualRecovery() {
        val failed = ready(canSwitch)
            .reduce(WorkModeEvent.StartSwitch(WorkMode.KSU))
            .reduce(WorkModeEvent.Incomplete("SWITCH_PREFLIGHT_FAILED", "baseline stale"))
        assertEquals(WorkModePhase.FAILED, failed.phase)
        assertEquals("SWITCH_PREFLIGHT_FAILED", failed.failure?.code)
        assertFalse(failed.needsManualRecovery)
    }

    @Test
    fun failedRequiresExternalRecoveryKeepsNeedsManualFlag() {
        val failed = ready(canSwitch)
            .reduce(WorkModeEvent.StartSwitch(WorkMode.KSU))
            .reduce(
                WorkModeEvent.Failed(
                    WorkModeFailure("WRITE_ROLLBACK_FAILED", "rollback failed", rolledBack = false)
                )
            )
        assertEquals(WorkModePhase.FAILED, failed.phase)
        assertTrue(failed.needsManualRecovery)
    }

    @Test
    fun dismissClearsRunningSwitchIdAndAvailabilitySurface() {
        val done = ready(canSwitch)
            .reduce(WorkModeEvent.Started("sw-1"))
            .reduce(WorkModeEvent.Completed("sw-1", rebootRequired = true))
            .reduce(WorkModeEvent.DismissResult)
        assertEquals(WorkModePhase.READY, done.phase)
        assertNull(done.runningSwitchId)
        assertFalse(done.rebootRequired)
    }
}
