package dev.maplesu.manager.modules

import org.junit.Assert.*
import org.junit.Test

class LiteModuleBootEpochTest {
    private val kernel = "202519fe-1328-4663-b93d-870787c98dab"

    @Test fun frameworkRestartAdvancesTheModuleEpochWithoutExpiringKernelRoot() {
        val installed = LiteModuleBootEpoch.id(kernel, 193)
        val restarted = LiteModuleBootEpoch.id(kernel, 194)
        assertNotEquals(installed, restarted)
        assertEquals(listOf("service", "boot-completed"), LiteModuleRuntimeState(installed)
            .pendingStages(restarted, true, listOf("boot-completed", "service")))
    }

    @Test fun appRestartDoesNotReloadAlreadyObservedStages() {
        val epoch = LiteModuleBootEpoch.id(kernel, 194)
        assertEquals(epoch, LiteModuleBootEpoch.id(kernel, 194))
        val state = LiteModuleRuntimeState(LiteModuleBootEpoch.id(kernel, 193))
            .withStage("service", epoch, "ok", 0)
        assertTrue(state.pendingStages(epoch, true, listOf("service")).isEmpty())
    }

    @Test fun installationAndRemovalWaitForAFrameworkRestart() {
        val before = LiteModuleBootEpoch.id(kernel, 193)
        val after = LiteModuleBootEpoch.id(kernel, 194)
        val state = LiteModuleRuntimeState(before, remove = true, removeRequestedBootId = before)
        assertTrue(state.pendingStages(before, true, listOf("service")).isEmpty())
        assertEquals(listOf("uninstall"), state.pendingStages(after, false, listOf("service")))
    }

    @Test fun fullBootAndLegacyReceiptsRemainCompatible() {
        val nextKernel = "202519fe-1328-4663-b93d-870787c98dac"
        assertNotEquals(LiteModuleBootEpoch.id(kernel, 194), LiteModuleBootEpoch.id(nextKernel, 194))
        assertEquals(listOf("service"), LiteModuleRuntimeState(kernel)
            .pendingStages(LiteModuleBootEpoch.id(kernel, 194), true, listOf("service")))
        assertEquals(kernel, LiteModuleBootEpoch.id(kernel, null))
    }
}
