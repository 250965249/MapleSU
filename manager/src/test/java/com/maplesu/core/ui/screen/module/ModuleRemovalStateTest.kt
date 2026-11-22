package com.maplesu.core.ui.screen.module

import com.maplesu.core.data.model.Module
import org.junit.Assert.*
import org.junit.Test

class ModuleRemovalStateTest {
    private val module = Module("fixture", "Fixture", "MapleSU", "1", 1, "", true, false,
        false, "", false, false, false, null, null, runtimeStatus = "late_completed")
    private fun state(module: Module = this.module) = ModuleUiState(
        modules = listOf(module), moduleList = listOf(module), searchResults = listOf(module))

    @Test fun removalAndCancellationImmediatelyChangeSourceDisplayAndSearch() {
        val requested = state().withModuleRemovalRequest(module.id, true)
        for (list in listOf(requested.modules, requested.moduleList, requested.searchResults)) assertTrue(list.single().remove)
        val undone = requested.withModuleRemovalRequest(module.id, false)
        for (list in listOf(undone.modules, undone.moduleList, undone.searchResults)) assertFalse(list.single().remove)
    }

    @Test fun anOldRefreshCannotUndoTheLatestUserIntent() {
        val requested = state().withModuleRemovalRequest(module.id, true)
        val refreshed = requested.withModuleLoadResult(Result.success(listOf(module)))
        assertTrue(refreshed.modules.single().remove)
        val cancelled = refreshed.withModuleRemovalRequest(module.id, false)
        val oldReceipt = cancelled.withModuleRemovalResult(module.id, true, true)
        assertFalse(oldReceipt.modules.single().remove)
        assertFalse(oldReceipt.removalChanges.getValue(module.id).remove)
        assertTrue(oldReceipt.removalChanges.getValue(module.id).confirmed.remove)
    }

    @Test fun successfulUndoAfterAnInFlightRemovalWinsAndSettles() {
        val state = state().withModuleRemovalRequest(module.id, true)
            .withModuleRemovalRequest(module.id, false)
            .withModuleRemovalResult(module.id, true, true)
            .withModuleRemovalResult(module.id, false, true)
            .finishModuleRemoval(module.id)
        assertTrue(state.removalChanges.isEmpty())
        assertFalse(state.modules.single().remove)
        assertEquals("late_completed", state.moduleList.single().runtimeStatus)
    }

    @Test fun failedRemovalRestoresOriginalStateWithoutErasingOtherModuleFacts() {
        val original = state()
        val result = original.withModuleRemovalRequest(module.id, true)
            .withModuleLoadResult(Result.success(listOf(module.copy(version = "2"))))
            .withModuleRemovalResult(module.id, true, false)
            .finishModuleRemoval(module.id)
        assertFalse(result.modules.single().remove)
        assertEquals("2", result.modules.single().version)
        assertEquals(module.runtimeStatus, result.modules.single().runtimeStatus)
        assertTrue(result.removalChanges.isEmpty())
    }

    @Test fun failedUndoRestoresTheSuccessfullyAcknowledgedRemoval() {
        val result = state().withModuleRemovalRequest(module.id, true)
            .withModuleRemovalResult(module.id, true, true)
            .withModuleRemovalRequest(module.id, false)
            .withModuleRemovalResult(module.id, false, false)
            .finishModuleRemoval(module.id)
        assertTrue(result.modules.single().remove)
        assertTrue(result.moduleList.single().remove)
    }

    @Test fun undoOfAnExistingMarkerImmediatelyClearsItsStatusAndRestoresToggle() {
        val removed = module.copy(remove = true, runtimeStatus = "remove_pending", canToggle = false)
        val result = state(removed).withModuleRemovalRequest(module.id, false)
        assertFalse(result.moduleList.single().remove)
        assertEquals("", result.moduleList.single().runtimeStatus)
        assertTrue(result.moduleList.single().canToggle)
        val failed = result.withModuleRemovalResult(module.id, false, false).finishModuleRemoval(module.id)
        assertEquals(removed, failed.modules.single())
    }

    @Test fun nativeUltraRemovalIsAlsoImmediateAndRollsBackOnFailure() {
        val original = state(module.copy(id = "maplesu:fixture"))
        val pending = original.withModuleRemovalRequest("maplesu:fixture", true)
        assertTrue(pending.modules.single().remove)
        assertTrue(pending.moduleList.single().remove)
        assertEquals(original, pending.withModuleRemovalResult("maplesu:fixture", true, false)
            .finishModuleRemoval("maplesu:fixture"))
    }
}
