package com.maplesu.core.ui.screen.module

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/** Complements helper behavior tests by guarding their real ViewModel publication boundaries. */
class ModuleAsyncWiringTest {
    private fun viewModel(): String {
        val file = File("src/main/java/com/maplesu/core/ui/viewmodel/ModuleViewModel.kt")
        assumeTrue(file.path, file.isFile)
        return file.readText()
    }

    @Test
    fun newRefreshInvalidatesThePreviousRequestBeforeCancellationAndOnlyLatestFinishes() {
        val source = viewModel().substringAfter("fun fetchModuleList(").substringBefore("private fun Module.toSignature")
        assertTrue(source.indexOf("refreshRequests.next()") < source.indexOf("fetchJob?.cancel()"))
        val cleanup = source.substringAfter("finally {")
        assertTrue(cleanup.indexOf("refreshRequests.isCurrent(request)") < cleanup.indexOf("isRefreshing = false"))
    }

    @Test
    fun loadResultIsCheckedBeforePublishingBackendFacts() {
        val source = viewModel().substringAfter("private suspend fun loadModuleList(").substringBefore("fun fetchModuleList(")
        assertTrue(source.indexOf("if (!refreshRequests.isCurrent(request))") < source.indexOf("it.withModuleLoadResult(result)"))
        assertTrue(source.contains("updateModuleList(resort).join()"))
        assertTrue(source.indexOf("operationGeneration != moduleOperationGeneration") < source.indexOf("it.withModuleLoadResult(result)"))
    }

    @Test
    fun visibleListHasOneLatestRequestAndInputSnapshotGuard() {
        val source = viewModel().substringAfter("private fun updateModuleList(").substringBefore("private fun moduleComparator(")
        assertTrue(source.indexOf("listRequests.next()") < source.indexOf("listJob?.cancel()"))
        assertTrue(source.indexOf("val snapshot = _uiState.value") < source.indexOf("withContext(Dispatchers.IO)"))
        assertTrue(source.contains("!listRequests.isCurrent(request) || !inputs.matches(state.moduleListInputs())"))
    }

    @Test
    fun searchReusesTheGuardedListProjectionAndRejectsSupersededQueries() {
        val source = viewModel().substringAfter("private suspend fun applySearchText(").substringBefore("private fun updateModuleList(")
        assertTrue(source.contains("if (text != _uiState.value.searchStatus.searchText) return"))
        assertTrue(source.contains("updateModuleList().join()"))
        assertFalse(source.contains("searchResults ="))
        val input = viewModel().substringAfter("fun updateSearchStatus(").substringBefore("fun updateSearchText(")
        assertTrue(input.contains("searchJob?.cancel()"))
        assertTrue(input.contains("delay(150)"))
    }

    @Test
    fun operationsPublishPendingBeforeLaunchingAndAlwaysReleaseIt() {
        val source = viewModel().substringAfter("private fun runModuleOperation(").substringBefore("private suspend fun buildUpdateConfirmDialogState(")
        assertTrue(source.indexOf("if (!moduleOperations.begin(module.id)) return") < source.indexOf("viewModelScope.launch"))
        assertTrue(source.indexOf("pendingModuleIds = moduleOperations.ids") < source.indexOf("viewModelScope.launch"))
        val cleanup = source.substringAfter("finally {")
        assertTrue(cleanup.contains("moduleOperations.finish(module.id)"))
        assertTrue(cleanup.contains("pendingModuleIds = moduleOperations.ids"))
        assertTrue(source.indexOf("withModuleToggleRequest(") < source.indexOf("viewModelScope.launch"))
        assertTrue(source.indexOf("withModuleRemovalRequest(") < source.indexOf("viewModelScope.launch"))
        assertTrue(source.contains("moduleOperations.execute"))
        assertTrue(source.contains("finishModuleToggle(module.id, success)"))
        assertFalse(source.contains("refreshAfterModuleOperation"))
    }

    @Test
    fun remoteUpdateMetadataDoesNotHoldOperationFeedbackOrListLoading() {
        val source = viewModel().substringAfter("private fun runModuleOperation(").substringBefore("private suspend fun buildUpdateConfirmDialogState(")
        assertFalse(source.contains("syncModuleUpdateInfo("))
        val readback = source.substringAfter("private fun readbackAfterModuleOperations()")
        assertTrue(readback.contains("moduleOperations.ids.isNotEmpty()"))
        assertTrue(readback.contains("fetchModuleList(checkUpdate = false, resort = false, showRefreshing = false)"))
        val fetch = viewModel().substringAfter("fun fetchModuleList(").substringBefore("private fun Module.toSignature")
        assertTrue(fetch.indexOf("isRefreshing = false") < fetch.indexOf("syncModuleUpdateInfo("))
    }
}
