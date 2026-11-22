package dev.maplesu.manager.runtime

import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.gating.ModeComponentIds
import org.junit.Assert.*
import org.junit.Test

class HookComponentPreparationTest {
    @Test fun explicitHookRestoresItsDirectoryBrokerAndLifetimeAfterStockReboot() {
        for (mode in listOf(null, WorkMode.LITE)) {
            val enabled = mutableListOf<String>()
            enableHookComponents(mode, enabled::add)
            assertEquals(listOf(ModeComponentIds.COMPONENT_NATIVE_SU_DIRECTORY_PROVIDER,
                ModeComponentIds.COMPONENT_NATIVE_SU_BROKER_SERVICE,
                ModeComponentIds.COMPONENT_HOOK_SU_KEEPER_SERVICE,
                ModeComponentIds.COMPONENT_LITE_MODULE_BOOT_RECEIVER,
                ModeComponentIds.COMPONENT_LITE_MODULE_BOOT_SERVICE), enabled)
        }
    }

    @Test fun activeNormalKeepsHookComponentsDisabled() {
        val enabled = mutableListOf<String>()
        try {
            enableHookComponents(WorkMode.KSU, enabled::add)
            fail("Normal must retain its component gate")
        } catch (expected: IllegalStateException) {
            assertEquals("SU_HOOK_ACTIVE_KSU", expected.message)
        }
        assertTrue(enabled.isEmpty())
    }

    @Test fun componentFailureStopsPreparationBeforeBrokerPublication() {
        val enabled = mutableListOf<String>()
        try {
            enableHookComponents(WorkMode.LITE) {
                enabled += it
                throw IllegalArgumentException("component missing")
            }
            fail("component failure must propagate")
        } catch (expected: IllegalArgumentException) {
            assertEquals("component missing", expected.message)
        }
        assertEquals(listOf(ModeComponentIds.COMPONENT_NATIVE_SU_DIRECTORY_PROVIDER), enabled)
    }
}
