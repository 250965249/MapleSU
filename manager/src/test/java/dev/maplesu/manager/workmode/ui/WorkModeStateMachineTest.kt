package dev.maplesu.manager.workmode.ui

import dev.maplesu.manager.workmode.ModeCapabilities
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.detect.ModeState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 工作模式页 reducer 转移表。纯 JVM 测试，无 Android 依赖。
 */
class WorkModeStateMachineTest {

    private val capsLite = ModeCapabilities.forMode(WorkMode.LITE)
    private val capsKsu = ModeCapabilities.forMode(WorkMode.KSU)

    private fun readyA(): WorkModeUiState =
        WorkModeUiState().reduce(
            WorkModeEvent.Detected(ModeState.MODE_A_ACTIVE, capsLite, WorkMode.LITE, masked = false, switchSupported = true)
        )

    @Test
    fun initialStateIsAnalyzingAndNotSwitchable() {
        val state = WorkModeUiState()
        assertEquals(WorkModePhase.ANALYZING, state.phase)
        assertFalse(state.switchable)
    }

    @Test
    fun detectionMovesToReadyWithSwitchTarget() {
        val ready = readyA()
        assertEquals(WorkModePhase.READY, ready.phase)
        assertEquals(WorkMode.LITE, ready.current)
        assertEquals(WorkMode.KSU, ready.switchTarget)
        assertTrue(ready.switchable)
    }

    /** D (2026-11-01): one tap reaches RUNNING directly — no CONFIRM phase, no second click. */
    @Test
    fun oneTapStartsRunningImmediately() {
        val running = readyA().reduce(WorkModeEvent.StartSwitch(WorkMode.KSU))
        assertEquals(WorkModePhase.RUNNING, running.phase)
        assertEquals(WorkMode.KSU, running.target)
    }

    /** D: the second confirmation layer must not come back. */
    @Test
    fun thereIsNoSecondConfirmationLayer() {
        val phases = WorkModePhase.values().map { it.name }
        assertFalse("CONFIRM phase came back: $phases", "CONFIRM" in phases)
        val events = WorkModeEvent::class.java.classes.map { it.simpleName }.toSet()
        assertFalse("Confirm event came back: $events", "Confirm" in events)
        assertFalse("TapSwitch event came back: $events", "TapSwitch" in events)
    }

    @Test
    fun startSwitchToCurrentModeStaysReady() {
        val state = readyA().reduce(WorkModeEvent.StartSwitch(WorkMode.LITE))
        assertEquals(WorkModePhase.READY, state.phase)
        assertNull(state.target)
    }

    @Test
    fun blockersKeepReadyButDisableSwitch() {
        val blocked = readyA().reduce(
            WorkModeEvent.Preflight(listOf(GateItem("S0-BASELINE", "baseline missing")), emptyList())
        )
        assertEquals(WorkModePhase.READY, blocked.phase)
        assertFalse(blocked.switchable)
    }

    @Test
    fun stageDuringRunningUpdatesProgressOnly() {
        val running = readyA()
            .reduce(WorkModeEvent.StartSwitch(WorkMode.KSU))
            .reduce(WorkModeEvent.Stage(SwitchProgress("S4", "4d", 0.6f, "writing init_boot")))
        assertEquals(WorkModePhase.RUNNING, running.phase)
        assertEquals("4d", running.progress?.step)
        assertTrue(running.logText.contains("writing init_boot"))
    }

    @Test
    fun completedMovesToSucceededWithRebootRequired() {
        val done = readyA()
            .reduce(WorkModeEvent.StartSwitch(WorkMode.KSU))
            .reduce(WorkModeEvent.Completed("sw-1", rebootRequired = true))
        assertEquals(WorkModePhase.SUCCEEDED, done.phase)
        assertTrue(done.rebootRequired)
    }

    @Test
    fun failedRolledBackNeedsNoManualRecovery() {
        val running = readyA()
            .reduce(WorkModeEvent.StartSwitch(WorkMode.KSU))
        val rolled = running.reduce(
            WorkModeEvent.Failed(WorkModeFailure("SWITCH_WRITE", "io error", rolledBack = true, restoredPartitions = listOf("init_boot")))
        )
        assertEquals(WorkModePhase.FAILED, rolled.phase)
        assertTrue(rolled.failure?.rolledBack == true)
        assertFalse(rolled.needsManualRecovery)
    }

    @Test
    fun failedWithoutRollbackNeedsManualRecovery() {
        val running = readyA()
            .reduce(WorkModeEvent.StartSwitch(WorkMode.KSU))
        val failed = running.reduce(WorkModeEvent.Failed(WorkModeFailure("SWITCH_WRITE", null, rolledBack = false)))
        assertTrue(failed.needsManualRecovery)
    }

    @Test
    fun dismissResultReturnsToReadyAndRetryToAnalyzing() {
        val done = readyA()
            .reduce(WorkModeEvent.StartSwitch(WorkMode.KSU))
            .reduce(WorkModeEvent.Completed("sw-1", rebootRequired = false))
        assertEquals(WorkModePhase.READY, done.reduce(WorkModeEvent.DismissResult).phase)

        val failed = readyA()
            .reduce(WorkModeEvent.StartSwitch(WorkMode.KSU))
            .reduce(WorkModeEvent.Failed(WorkModeFailure("X", null, rolledBack = false)))
        assertEquals(WorkModePhase.ANALYZING, failed.reduce(WorkModeEvent.Retry).phase)
    }

    @Test
    fun detectionDuringRunningDoesNotInterruptProgress() {
        val running = readyA()
            .reduce(WorkModeEvent.StartSwitch(WorkMode.KSU))
            .reduce(
                WorkModeEvent.Detected(ModeState.MODE_B_ACTIVE, capsKsu, WorkMode.KSU, masked = false, switchSupported = true)
            )
        assertEquals(WorkModePhase.RUNNING, running.phase)
    }

    @Test
    fun indeterminateStateIsNotSwitchable() {
        val state = WorkModeUiState().reduce(
            WorkModeEvent.Detected(ModeState.INDETERMINATE, ModeCapabilities.NONE, null, masked = false, switchSupported = true)
        )
        assertFalse(state.switchable)
        assertNull(state.switchTarget)
    }

    @Test
    fun foreignRootIsNotSwitchable() {
        val state = WorkModeUiState().reduce(
            WorkModeEvent.Detected(ModeState.FOREIGN_SU, ModeCapabilities.NONE, null, masked = false, switchSupported = true)
        )
        assertFalse(state.switchable)
    }

    @Test
    fun stealthMaskingDisablesSwitchEvenWhenDetected() {
        val masked = readyA().copy(masked = true)
        assertFalse(masked.switchable)
        assertEquals(WorkModePhase.READY, masked.phase)
    }
}
