package com.maplesu.core.ui.screen.module

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class ModulePendingStateTest {
    @Test
    fun pendingStartsEmptyAndSurvivesSuccessfulOrFailedReloads() {
        assertTrue(ModuleUiState().pendingModuleIds.isEmpty())
        val state = ModuleUiState(pendingModuleIds = setOf("module"))
        assertEquals(setOf("module"), state.withModuleLoadResult(Result.success(emptyList())).pendingModuleIds)
        assertEquals(setOf("module"), state.withModuleLoadResult(Result.failure(IOException("offline"))).pendingModuleIds)
    }

    @Test
    fun pendingFeedbackDoesNotInvalidateAnOtherwiseCurrentListProjection() {
        val state = ModuleUiState()
        val before = state.moduleListInputs()
        val pending = state.copy(pendingModuleIds = setOf("module"))
        assertTrue(before.matches(pending.moduleListInputs()))
    }
}
