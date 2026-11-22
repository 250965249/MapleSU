package dev.maplesu.manager.modules

import androidx.lifecycle.ViewModelStore
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.data.model.Module
import com.maplesu.core.data.repository.ModuleRepositoryImpl
import com.maplesu.core.ui.screen.module.ModuleUiState
import com.maplesu.core.ui.viewmodel.ModuleViewModel
import dev.maplesu.manager.workmode.WorkMode
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Production ViewModel -> repository -> router, with writes confined to a blocked in-memory port. */
class ModuleOptimisticOperationsAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()

    @Test fun tapsProjectImmediatelyWhileWritesQueueAndUndoCanReplaceTheLatestIntent() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = Collections.synchronizedList(mutableListOf<String>())
        var reads = 0
        val port = object : ModuleOpsPort {
            override fun isAvailable() = true
            override fun listJson(): String { reads++; error("Operations must not refresh the whole list") }
            override fun toggle(id: String, enable: Boolean): Boolean {
                calls += "toggle:$id:$enable"
                if (id == "first") { entered.countDown(); check(release.await(8, TimeUnit.SECONDS)) }
                return id != "failed"
            }
            override fun uninstall(id: String): Boolean { calls += "remove:$id"; return true }
            override fun undoUninstall(id: String): Boolean { calls += "undo:$id"; return true }
            override fun install(zip: File) = error("Fixture never installs modules")
        }
        val repo = ModuleRepositoryImpl(mode = { WorkMode.LITE }, litePort = port)
        val model = ModuleViewModel(repo = repo)
        val store = ViewModelStore()
        val rows = listOf("first", "second", "third", "failed").map(::fixture)
        @Suppress("UNCHECKED_CAST")
        val state = model.javaClass.getDeclaredField("_uiState").apply { isAccessible = true }.get(model)
            as MutableStateFlow<ModuleUiState>
        try {
            instrumentation.runOnMainSync {
                store.put("fixture", model)
                state.value = ModuleUiState(hasLoaded = true, modules = rows, moduleList = rows, searchResults = rows)
                model.toggleModule(rows[0])
                assertProjected(model, "first", enabled = false, remove = false)
                // A duplicate tap is ignored, but other cards remain available.
                model.toggleModule(rows[0])
            }
            assertTrue("First backend write did not start", entered.await(3, TimeUnit.SECONDS))
            instrumentation.runOnMainSync {
                model.uninstallModule(rows[1])
                assertProjected(model, "second", enabled = true, remove = true)
                model.undoUninstallModule(rows[1])
                assertProjected(model, "second", enabled = true, remove = false)
                model.toggleModule(rows[2])
                assertProjected(model, "third", enabled = false, remove = false)
                assertEquals(setOf("first", "second", "third"), model.uiState.value.pendingModuleIds)
                assertFalse(model.uiState.value.isRefreshing)
            }
            assertEquals(listOf("toggle:first:false"), synchronized(calls) { calls.toList() })
            release.countDown()
            awaitDrained(model)
            instrumentation.runOnMainSync {
                assertProjected(model, "first", enabled = false, remove = false)
                assertProjected(model, "second", enabled = true, remove = false)
                assertProjected(model, "third", enabled = false, remove = false)
                assertEquals(0, reads)
                model.toggleModule(rows[3])
                assertProjected(model, "failed", enabled = false, remove = false)
            }
            awaitDrained(model)
            instrumentation.runOnMainSync {
                assertProjected(model, "failed", enabled = true, remove = false)
                assertProjected(model, "third", enabled = false, remove = false)
                assertFalse(model.uiState.value.isRefreshing)
                assertEquals(0, reads)
            }
            assertEquals(listOf("toggle:first:false", "remove:second", "toggle:third:false", "undo:second", "toggle:failed:false"),
                synchronized(calls) { calls.toList() })
        } finally {
            release.countDown()
            instrumentation.runOnMainSync { store.clear() }
        }
    }

    private fun awaitDrained(model: ModuleViewModel) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (model.uiState.value.pendingModuleIds.isNotEmpty() && System.nanoTime() < deadline) Thread.sleep(10)
        assertTrue("Fixture operations did not drain", model.uiState.value.pendingModuleIds.isEmpty())
    }

    private fun assertProjected(model: ModuleViewModel, id: String, enabled: Boolean, remove: Boolean) {
        val state = model.uiState.value
        for (list in listOf(state.modules, state.moduleList, state.searchResults)) {
            val row = list.single { it.id == id }
            assertEquals("$id enabled projection", enabled, row.enabled)
            assertEquals("$id removal projection", remove, row.remove)
        }
    }

    private fun fixture(id: String) = Module(id, id, "QA", "1", 1, "In-memory fixture", true,
        false, false, "", false, false, false, null, null)
}
