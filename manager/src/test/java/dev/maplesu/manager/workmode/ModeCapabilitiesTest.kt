package dev.maplesu.manager.workmode

import dev.maplesu.manager.workmode.ModeCapabilities
import dev.maplesu.manager.workmode.ModuleBackendKind
import dev.maplesu.manager.workmode.SuBackendKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 01 §8.1 `ModeCapabilitiesTest`。 */
class ModeCapabilitiesTest {
    @Test
    fun liteMatrix() {
        val lite = ModeCapabilities.forMode(WorkMode.LITE)
        assertEquals(SuBackendKind.LITE_RUNTIME, lite.suBackend)
        assertEquals(ModuleBackendKind.LITE_SCRIPT, lite.moduleBackend)
        assertFalse(lite.supportsKernelUmount)
        assertFalse(lite.supportsSelinuxHide)
        assertFalse(lite.supportsSulog)
        assertFalse(lite.supportsAdbRoot)
        assertFalse(lite.supportsShellSuAdbOnly)
        assertFalse(lite.supportsStealth)
        assertFalse(lite.supportsWebAdmin)
        assertFalse(lite.supportsAppLock)
        assertFalse(lite.supportsMagica)
        assertTrue(lite.supportsJailbreak)
        assertTrue(lite.supportsUltraEnvironment)
        assertTrue(lite.supportsUltraModules)
    }

    @Test
    fun ksuMatrix() {
        val ksu = ModeCapabilities.forMode(WorkMode.KSU)
        assertEquals(SuBackendKind.KSU_KERNEL, ksu.suBackend)
        assertEquals(ModuleBackendKind.KSU_KDSU, ksu.moduleBackend)
        assertTrue(ksu.supportsKernelUmount)
        assertTrue(ksu.supportsSelinuxHide)
        assertTrue(ksu.supportsSulog)
        assertTrue(ksu.supportsAdbRoot)
        assertTrue(ksu.supportsShellSuAdbOnly)
        assertTrue(ksu.supportsStealth)
        assertTrue(ksu.supportsWebAdmin)
        assertTrue(ksu.supportsAppLock)
        assertTrue(ksu.supportsMagica)
        assertFalse(ksu.supportsJailbreak)
        assertFalse(ksu.supportsUltraEnvironment)
        assertFalse(ksu.supportsUltraModules)
    }

    @Test
    fun noneAllFalse() {
        val none = ModeCapabilities.NONE
        assertFalse(none.supportsKernelUmount)
        assertFalse(none.supportsSelinuxHide)
        assertFalse(none.supportsSulog)
        assertFalse(none.supportsAdbRoot)
        assertFalse(none.supportsShellSuAdbOnly)
        assertFalse(none.supportsStealth)
        assertFalse(none.supportsWebAdmin)
        assertFalse(none.supportsAppLock)
        assertFalse(none.supportsMagica)
        assertFalse(none.supportsJailbreak)
        assertFalse(none.supportsUltraEnvironment)
        assertFalse(none.supportsUltraModules)
    }

    @Test
    fun noCapabilityIsTrueForBothExclusiveGroups() {
        val lite = ModeCapabilities.forMode(WorkMode.LITE)
        val ksu = ModeCapabilities.forMode(WorkMode.KSU)
        // B 独占组
        for (value in listOf(
            ksu.supportsKernelUmount, ksu.supportsSelinuxHide, ksu.supportsSulog,
            ksu.supportsAdbRoot, ksu.supportsShellSuAdbOnly, ksu.supportsStealth,
            ksu.supportsWebAdmin, ksu.supportsAppLock, ksu.supportsMagica,
        )) {
            assertTrue(value)
        }
        for (value in listOf(
            lite.supportsKernelUmount, lite.supportsSelinuxHide, lite.supportsSulog,
            lite.supportsAdbRoot, lite.supportsShellSuAdbOnly, lite.supportsStealth,
            lite.supportsWebAdmin, lite.supportsAppLock, lite.supportsMagica,
        )) {
            assertFalse(value)
        }
        // A 独占组
        assertTrue(lite.supportsJailbreak)
        assertTrue(lite.supportsUltraEnvironment)
        assertTrue(lite.supportsUltraModules)
        assertFalse(ksu.supportsJailbreak)
        assertFalse(ksu.supportsUltraEnvironment)
        assertFalse(ksu.supportsUltraModules)
    }

    @Test
    fun workModeWireParsingIsExplicit() {
        assertEquals(WorkMode.LITE, WorkMode.fromWire("a"))
        assertEquals(WorkMode.LITE, WorkMode.fromWire(" LITE "))
        assertEquals(WorkMode.KSU, WorkMode.fromWire("b"))
        assertEquals(WorkMode.KSU, WorkMode.fromWire("ksu"))
        assertEquals(null, WorkMode.fromWire(null))
        assertEquals(null, WorkMode.fromWire(""))
        assertEquals(null, WorkMode.fromWire("NONE"))
        assertEquals(WorkMode.LITE, WorkMode.fromSuffix("A"))
        assertEquals(null, WorkMode.fromSuffix("C"))
        assertEquals(null, WorkMode.fromSuffix(null))
    }
}
