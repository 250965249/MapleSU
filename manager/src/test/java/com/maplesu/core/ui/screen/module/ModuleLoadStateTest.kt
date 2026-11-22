package com.maplesu.core.ui.screen.module

import com.maplesu.core.R
import com.maplesu.core.data.model.Module
import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import java.util.concurrent.CancellationException

class ModuleLoadStateTest {
    private val module = Module(
        id = "fixture", name = "Fixture", author = "MapleSU", version = "1", versionCode = 1,
        description = "", enabled = true, update = false, remove = false, updateJson = "",
        hasWebUi = false, hasActionScript = false, metamodule = false,
        actionIconPath = null, webUiIconPath = null,
    )

    @Test fun initialFailureIsAnErrorRatherThanSuccessfulEmptiness() {
        val failure = IOException("module backend unavailable")
        val state = ModuleUiState(hasLoaded = true)
            .withModuleLoadResult(Result.failure(failure))

        assertSame(failure, state.loadError)
        assertEquals(R.string.module_load_failed, state.emptyStateMessage)
        assertNotEquals(R.string.module_empty, state.emptyStateMessage)
    }

    @Test fun successfulEmptyQueryShowsEmptyState() {
        val state = ModuleUiState(hasLoaded = true)
            .withModuleLoadResult(Result.success(emptyList()))

        assertNull(state.loadError)
        assertEquals(R.string.module_empty, state.emptyStateMessage)
    }

    @Test fun failedRefreshRetainsPreviousSourceDisplayAndSearchResults() {
        val previous = listOf(module)
        val old = ModuleUiState(
            hasLoaded = true, modules = previous, moduleList = previous, searchResults = previous,
        )
        val failure = IOException("refresh failed")
        val state = old.withModuleLoadResult(Result.failure(failure))

        assertSame(failure, state.loadError)
        assertSame(previous, state.modules)
        assertSame(previous, state.moduleList)
        assertSame(previous, state.searchResults)
        assertNull(state.emptyStateMessage)
    }

    @Test fun successfulRetryClearsThePreviousError() {
        val state = ModuleUiState(hasLoaded = true, loadError = IOException("previous failure"))
            .withModuleLoadResult(Result.success(listOf(module)))

        assertNull(state.loadError)
        assertEquals(listOf(module), state.modules)
        assertNull(state.emptyStateMessage)
    }

    @Test fun firstLoadAndRefreshDoNotAnnounceEmptySuccess() {
        assertNull(ModuleUiState().emptyStateMessage)
        assertNull(ModuleUiState(hasLoaded = true, isRefreshing = true).emptyStateMessage)
    }

    @Test fun cancelledQueryDoesNotBecomeAUserVisibleLoadFailure() {
        val cancelled = CancellationException("request superseded")
        val thrown = assertThrows(CancellationException::class.java) {
            ModuleUiState().withModuleLoadResult(Result.failure(cancelled))
        }
        assertSame(cancelled, thrown)
    }
}
