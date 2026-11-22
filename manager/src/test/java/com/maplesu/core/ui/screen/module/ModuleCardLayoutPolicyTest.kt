package com.maplesu.core.ui.screen.module

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ModuleCardLayoutPolicyTest {
    @Test fun missingLateScriptReceiptDoesNotClaimANextBootIsRequired() {
        assertFalse(moduleCardStatus("late_pending", false).needsAttention)
    }

    @Test fun narrowAndLargeFontHeadersGiveTheToggleItsOwnRow() {
        assertTrue(moduleCardNeedsOwnToggleRow(304f, 1f))
        assertTrue(moduleCardNeedsOwnToggleRow(380f, 1.3f))
        assertTrue(moduleCardNeedsOwnToggleRow(480f, 2f))
        assertFalse(moduleCardNeedsOwnToggleRow(360f, 1f))
        assertFalse(moduleCardNeedsOwnToggleRow(720f, 2f))
    }

    @Test fun nativeModuleRunningIsNotDescribedAsAnExecutingScript() {
        assertEquals(ModuleCardStatus.MODULE_RUNNING, moduleCardStatus("running", true))
        assertEquals(ModuleCardStatus.SCRIPT_RUNNING, moduleCardStatus("running", false))
    }

    @Test fun everyObservedSdkStateHasAnHonestPresentation() {
        assertEquals(ModuleCardStatus.MODULE_NOT_RUNNING, moduleCardStatus("not_running", true))
        assertEquals(ModuleCardStatus.MODULE_ABNORMAL, moduleCardStatus("abnormal", true))
        assertEquals(ModuleCardStatus.REMOVE_PENDING, moduleCardStatus("removed_pending_reboot", true))
        assertEquals(ModuleCardStatus.MODULE_UNKNOWN, moduleCardStatus("unknown", true))
        assertEquals(ModuleCardStatus.MODULE_UNKNOWN, moduleCardStatus("", true))
    }

    @Test fun interruptedScriptDoesNotLeaveAnErrorOnTheModuleCard() {
        val status = moduleCardStatus("interrupted", false)
        assertEquals(ModuleCardStatus.NONE, status)
        assertFalse(status.isError)
        assertFalse(status.needsAttention)
    }

    @Test fun scriptFailuresAndDeferredStatesStayVisible() {
        assertEquals(ModuleCardStatus.FAILED, moduleCardStatus("failed", false))
        assertEquals(ModuleCardStatus.REMOVE_PENDING, moduleCardStatus("remove_pending", false))
        assertEquals(ModuleCardStatus.LATE_PENDING, moduleCardStatus("late_pending", false))
        assertTrue(ModuleCardStatus.FAILED.isError)
        assertFalse(ModuleCardStatus.LATE_PENDING.isError)
    }

    @Test fun blankKernelSuStatusDoesNotInventRuntimeSuccess() {
        assertEquals(ModuleCardStatus.NONE, moduleCardStatus("", false))
        assertEquals(ModuleCardStatus.NONE, moduleCardStatus("future_state", false))
        assertEquals(ModuleCardStatus.INSTALLED, moduleCardStatus("installed", false))
        assertEquals(ModuleCardStatus.DISABLED, moduleCardStatus("disabled", false))
        assertEquals(ModuleCardStatus.LATE_COMPLETED, moduleCardStatus("late_completed", false))
    }

    @Test fun compactCardKeepsFailuresAndDeferredChangesButOmitsRoutineRuntimeText() {
        listOf(ModuleCardStatus.FAILED, ModuleCardStatus.MODULE_ABNORMAL,
            ModuleCardStatus.REMOVE_PENDING,
            ModuleCardStatus.STORED_ULTRA, ModuleCardStatus.STORED).forEach {
            assertTrue(it.name, it.needsAttention)
        }
        listOf(ModuleCardStatus.NONE, ModuleCardStatus.MODULE_RUNNING, ModuleCardStatus.MODULE_NOT_RUNNING,
            ModuleCardStatus.MODULE_UNKNOWN, ModuleCardStatus.SCRIPT_RUNNING, ModuleCardStatus.INSTALLED,
            ModuleCardStatus.LATE_COMPLETED, ModuleCardStatus.DISABLED, ModuleCardStatus.LATE_PENDING).forEach {
            assertFalse(it.name, it.needsAttention)
        }
    }
}
