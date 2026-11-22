package dev.maplesu.manager.installer

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InstallerTaskPresentationTest {
    @Test
    fun settledTasksDoNotAddACardToTheInstallPage() {
        for (state in listOf("", "NONE", "VERIFIED", "BOOT_VERIFIED", "CANCELLED", "RESTORED", "ROLLED_BACK")) {
            assertFalse(state, InstallerTaskPresentation(state = state).visible)
        }
    }

    @Test
    fun interruptedTasksAndReadFailuresRemainReachable() {
        for (state in listOf("PREPARED", "PREPARING", "WRITING", "RESTORING", "RECOVERY_REQUIRED",
            "FAILED_PRE_WRITE", "FAILED_BEFORE_WRITE", "REBOOT_REQUIRED")) {
            assertTrue(state, InstallerTaskPresentation(state = state).visible)
        }
        assertTrue(InstallerTaskPresentation(loading = true).visible)
        assertTrue(InstallerTaskPresentation(readFailed = true).visible)
    }

    @Test
    fun nativeInterruptedPreparationOnlyAllowsDiscard() {
        val prepared = InstallerTaskPresentation(state = "PREPARED", kind = "NATIVE", canCancel = true)
        assertTrue(prepared.showCancel)
        assertFalse(prepared.showContinue)
        assertFalse(prepared.showRestore)
        assertTrue(prepared.copy(kind = "LEGACY").showContinue)
    }

    @Test
    fun modeSwitchButtonsUseReportedCapabilities() {
        val mode = InstallerTaskPresentation(state = "RECOVERY_REQUIRED", kind = "MODE_SWITCH")
        assertFalse(mode.showRestore)
        assertFalse(mode.showCancel)
        assertFalse(mode.showContinue)
        assertTrue(mode.copy(canRestore = true).showRestore)
        assertTrue(mode.copy(canCancel = true).showCancel)
        assertFalse(mode.copy(canRestore = true, operationActive = true).showRestore)
        assertFalse(mode.copy(canCancel = true, readFailed = true).showCancel)
    }

    @Test
    fun completedRestorationKeepsRestartUntilItIsObserved() {
        val restored = InstallerTaskPresentation(state = "RESTORED", rebootRequired = true)
        assertTrue(restored.visible)
        assertTrue(restored.showReboot)
        assertFalse(restored.showRestore)
        assertFalse(restored.copy(rebootRequired = false).visible)
    }

    @Test
    fun ownedRemovalIsTerminalEvenWhenAnOldActiveFlagRemains() {
        val removed = InstallerTaskPresentation(state = "OWNED_WRITES_REMOVED", operationActive = true)
        assertFalse(removed.visible)
        assertTrue(removed.copy(rebootRequired = true).visible)
    }
}
