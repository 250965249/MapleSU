package com.maplesu.core.ui.screen.module

import com.maplesu.core.data.model.Module
import org.junit.Assert.*
import org.junit.Test

class ModuleToggleStateTest {
    private val module = Module("fixture", "Fixture", "MapleSU", "1", 1, "", true, false,
        false, "", false, false, false, null, null, runtimeStatus = "late_completed")
    private fun state() = ModuleUiState(modules = listOf(module), moduleList = listOf(module), searchResults = listOf(module))

    @Test fun toggleImmediatelyUpdatesAllVisibleListsWithoutStartingRefresh() {
        val requested = state().withModuleToggleRequest(module.id, false)
        for (list in listOf(requested.modules, requested.moduleList, requested.searchResults)) {
            assertFalse(list.single().enabled)
            assertTrue(list.single().needsReboot)
        }
        assertFalse(requested.isRefreshing)
    }

    @Test fun successfulWriteSettlesTheDesiredStateWithoutAListRead() {
        val settled = state().withModuleToggleRequest(module.id, false).finishModuleToggle(module.id, true)
        assertTrue(settled.toggleChanges.isEmpty())
        assertFalse(settled.modules.single().enabled)
        assertFalse(settled.moduleList.single().enabled)
        assertTrue(settled.modules.single().needsReboot)
    }

    @Test fun failedWriteRestoresOnlyThisModulesToggleFacts() {
        val settled = state().withModuleToggleRequest(module.id, false)
            .withModuleLoadResult(Result.success(listOf(module.copy(version = "2"))))
            .finishModuleToggle(module.id, false)
        assertTrue(settled.modules.single().enabled)
        assertFalse(settled.modules.single().needsReboot)
        assertEquals("2", settled.modules.single().version)
        assertTrue(settled.toggleChanges.isEmpty())
    }

    @Test fun aReloadWhileQueuedPreservesTheOptimisticToggle() {
        val refreshed = state().withModuleToggleRequest(module.id, false)
            .withModuleLoadResult(Result.success(listOf(module)))
        assertFalse(refreshed.modules.single().enabled)
        assertTrue(refreshed.modules.single().needsReboot)
    }

    @Test fun anotherModulesRemovalDoesNotChangeThisModulesToggle() {
        val other = module.copy(id = "second")
        val original = ModuleUiState(modules = listOf(module, other), moduleList = listOf(module, other))
        val settled = original.withModuleToggleRequest(module.id, false)
            .withModuleRemovalRequest(other.id, true)
            .finishModuleToggle(module.id, false)
        assertTrue(settled.modules.first().enabled)
        assertTrue(settled.modules.last().remove)
        assertTrue(settled.removalChanges.containsKey(other.id))
    }

    @Test fun nativeToggleUsesTheSameImmediatePresentation() {
        val native = module.copy(id = "maplesu:fixture")
        val requested = ModuleUiState(modules = listOf(native)).withModuleToggleRequest(native.id, false)
        assertFalse(requested.modules.single().enabled)
        assertTrue(requested.modules.single().needsReboot)
    }
}
