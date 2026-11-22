package com.maplesu.core.ui.screen.module

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

class ModuleOptimisticRemovalWiringTest {
    private fun source(path: String) = File("src/main/java/$path").readText()

    @Test fun uninstallAndUndoPublishDesiredRemovalBeforeLaunchingBackendWork() {
        val source = source("com/maplesu/core/ui/viewmodel/ModuleViewModel.kt")
        assertTrue(source.contains("setModuleRemoval(current, remove = true)"))
        assertTrue(source.contains("setModuleRemoval(current, remove = false)"))
        val operation = source.substringAfter("private fun setModuleRemoval(")
            .substringBefore("private fun runModuleOperation(")
        assertTrue(operation.indexOf("withModuleRemovalRequest(") in 0 until operation.indexOf("viewModelScope.launch"))
        assertTrue(operation.contains("withModuleRemovalResult("))
        assertTrue(operation.contains("finishModuleRemoval("))
    }

    @Test fun staleListResultsKeepTheLatestRemovalIntent() {
        val state = source("com/maplesu/core/ui/screen/module/ModuleUiState.kt")
        assertTrue(state.contains("removalChanges[module.id]?.present(toggled) ?: toggled"))
    }

    @Test fun bothCardsAllowCancellationWhileTheRemovalRequestIsInFlight() {
        for (skin in listOf("Material", "Miuix")) {
            val source = source("com/maplesu/core/ui/screen/module/Module$skin.kt")
            assertTrue(skin, source.contains("removalPending = module.id in removalChanges"))
            assertTrue(skin, source.contains("(!isPending || removalPending)"))
        }
    }
}
