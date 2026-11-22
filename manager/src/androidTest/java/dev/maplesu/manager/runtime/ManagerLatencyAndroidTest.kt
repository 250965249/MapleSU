package dev.maplesu.manager.runtime

import android.os.Bundle
import android.os.SystemClock
import android.view.accessibility.AccessibilityNodeInfo
import androidx.lifecycle.ViewModelStore
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.ui.MainActivity
import com.maplesu.core.ui.viewmodel.HomeViewModel
import com.maplesu.core.ui.viewmodel.ModuleViewModel
import dev.maplesu.manager.workmode.ModeRuntime
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Opt-in measurements using the production Activity, models and device backends. */
class ManagerLatencyAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val args get() = InstrumentationRegistry.getArguments()

    @Test fun coldHomePublishesLiveModeVersionAndSelinux() {
        assumeTrue(args.getString("verifyHomeStartup") == "true")
        val started = SystemClock.elapsedRealtime()
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            var modeAt = 0L
            var versionAt = 0L
            var selinuxAt = 0L
            lateinit var home: HomeViewModel
            scenario.onActivity { home = models(it).filterIsInstance<HomeViewModel>().single() }
            waitUntil(started + 7_500) {
                val at = SystemClock.elapsedRealtime() - started
                if (modeAt == 0L && ModeRuntime.active != null) modeAt = at
                if (versionAt == 0L && visibleVersion()) versionAt = at
                if (selinuxAt == 0L && home.uiState.value.systemInfo.selinuxStatus in
                    listOf("Enforcing", "Permissive", "Disabled")) selinuxAt = at
                modeAt > 0 && versionAt > 0 && selinuxAt > 0
            }
            assertEquals("LITE", ModeRuntime.active?.name)
            assertFalse(home.uiState.value.environmentChecking)
            instrumentation.sendStatus(2, Bundle().apply {
                putLong("modeMillis", modeAt)
                putLong("visibleVersionMillis", versionAt)
                putLong("selinuxPublishedMillis", selinuxAt)
                putString("selinux", home.uiState.value.systemInfo.selinuxStatus)
            })
        }
    }

    @Test fun ksuRemovalAndImmediateUndoPublishBeforeTheirBackendFinishes() {
        assumeTrue(args.getString("verifyModuleRemovalFixture") == "true")
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            lateinit var modules: ModuleViewModel
            scenario.onActivity {
                modules = models(it).filterIsInstance<ModuleViewModel>().single()
                modules.fetchModuleList(checkUpdate = false)
            }
            val id = "zz_maplesu_removal_qa"
            waitUntil(SystemClock.elapsedRealtime() + 10_000) {
                modules.uiState.value.modules.any { it.id == id } && !modules.uiState.value.isRefreshing
            }
            var markMillis = 0L
            var undoMillis = 0L
            scenario.onActivity {
                val fixture = modules.uiState.value.modules.single { row -> row.id == id }
                assertFalse(fixture.enabled)
                assertFalse(fixture.remove)
                var at = SystemClock.elapsedRealtime()
                modules.uninstallModule(fixture)
                markMillis = SystemClock.elapsedRealtime() - at
                assertTrue(modules.uiState.value.modules.single { row -> row.id == id }.remove)
                assertTrue(id in modules.uiState.value.removalChanges)
                at = SystemClock.elapsedRealtime()
                modules.undoUninstallModule(fixture)
                undoMillis = SystemClock.elapsedRealtime() - at
                assertFalse(modules.uiState.value.modules.single { row -> row.id == id }.remove)
            }
            waitUntil(SystemClock.elapsedRealtime() + 10_000) {
                id !in modules.uiState.value.pendingModuleIds && id !in modules.uiState.value.removalChanges
            }
            assertFalse(modules.uiState.value.modules.single { it.id == id }.remove)
            assertTrue("Mark must publish synchronously", markMillis < 100)
            assertTrue("Undo must publish synchronously", undoMillis < 100)
            instrumentation.sendStatus(2, Bundle().apply {
                putLong("markPublishedMillis", markMillis)
                putLong("undoPublishedMillis", undoMillis)
            })
        }
    }

    private fun models(activity: MainActivity): List<Any> {
        val result = mutableListOf<Any>()
        val stores = ArrayDeque<ViewModelStore>().apply { add(activity.viewModelStore) }
        while (stores.isNotEmpty()) {
            val store = stores.removeFirst()
            for (key in store.keys()) {
                val model = store[key] ?: continue
                result += model
                if (model.javaClass.name.endsWith("NavEntryViewModelStores")) {
                    val field = model.javaClass.getDeclaredField("stores").apply { isAccessible = true }
                    (field.get(model) as Map<*, *>).values.filterIsInstance<ViewModelStore>().forEach(stores::add)
                }
            }
        }
        return result
    }

    private fun visibleVersion(): Boolean {
        val nodes = ArrayDeque<AccessibilityNodeInfo>()
        instrumentation.uiAutomation.rootInActiveWindow?.let(nodes::add)
        while (nodes.isNotEmpty()) {
            val node = nodes.removeFirst()
            if (node.isVisibleToUser && node.text?.contains("MapleSU_Ultra 5.1.0") == true) return true
            repeat(node.childCount) { node.getChild(it)?.let(nodes::add) }
        }
        return false
    }

    private fun waitUntil(deadline: Long, condition: () -> Boolean) {
        while (!condition()) {
            assertTrue("Startup condition exceeded its budget", SystemClock.elapsedRealtime() < deadline)
            SystemClock.sleep(20)
        }
    }
}
