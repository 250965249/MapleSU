package dev.maplesu.manager.runtime

import android.graphics.Rect
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.InputDevice
import android.view.MotionEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.lifecycle.ViewModelStore
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.R
import com.maplesu.core.ui.MainActivity
import com.maplesu.core.ui.viewmodel.ModuleViewModel
import com.maplesu.core.ui.viewmodel.SuperUserViewModel
import dev.maplesu.manager.workmode.ModeRuntime
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Opt-in real navigation and backends. Run each method in a fresh instrumentation process. */
class ManagementPagesNavigationAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val args get() = InstrumentationRegistry.getArguments()
    private val context get() = instrumentation.targetContext

    @Test fun modulesFirstThenSuperusers() = verifyNavigation(modulesFirst = true)

    @Test fun superusersFirstThenModules() = verifyNavigation(modulesFirst = false)

    private fun verifyNavigation(modulesFirst: Boolean) {
        assumeTrue(args.getString("verifyManagementPagesNavigation") == "true")
        val launchAt = SystemClock.elapsedRealtime()
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            val first = if (modulesFirst) R.string.module else R.string.superuser
            val second = if (modulesFirst) R.string.superuser else R.string.module
            // Tap as soon as navigation exists, without waiting for mode/SDK preparation.
            val firstTapAt = tapTab(first)
            lateinit var modules: ModuleViewModel
            lateinit var superusers: SuperUserViewModel
            scenario.onActivity { activity ->
                // MainScreen belongs to a navigation-entry store, not the Activity store.
                // Observe its real models instead of constructing unused test instances.
                val models = mutableListOf<Any>()
                val stores = ArrayDeque<ViewModelStore>().apply { add(activity.viewModelStore) }
                while (stores.isNotEmpty()) {
                    val store = stores.removeFirst()
                    for (key in store.keys()) {
                        val model = store[key] ?: continue
                        models.add(model)
                        if (model.javaClass.name.endsWith("NavEntryViewModelStores")) {
                            val nested = model.javaClass.getDeclaredField("stores").apply { isAccessible = true }
                            (nested.get(model) as Map<*, *>).values.filterIsInstance<ViewModelStore>()
                                .forEach(stores::add)
                        }
                    }
                }
                modules = models.filterIsInstance<ModuleViewModel>().single()
                superusers = models.filterIsInstance<SuperUserViewModel>().single()
            }
            waitUntil(firstTapAt + 5_000) {
                if (modulesFirst) modules.uiState.value.let { it.isRefreshing || it.pending || it.hasLoaded }
                else superusers.uiState.value.let { it.isRefreshing || it.hasLoaded }
            }
            val mainThreadAt = SystemClock.elapsedRealtime()
            val mainResponse = CountDownLatch(1)
            Handler(Looper.getMainLooper()).post { mainResponse.countDown() }
            assertTrue("Backend loading blocked the main thread", mainResponse.await(1, TimeUnit.SECONDS))
            val mainResponseMillis = SystemClock.elapsedRealtime() - mainThreadAt
            tapTab(second)
            waitUntil(firstTapAt + 7_500) {
                val moduleState = modules.uiState.value
                val suState = superusers.uiState.value
                moduleState.hasLoaded && !moduleState.isRefreshing && !moduleState.pending &&
                    suState.hasLoaded && !suState.isRefreshing
            }
            val readyAt = SystemClock.elapsedRealtime()
            assertTrue("Cold pages exceeded the navigation budget: ${readyAt - firstTapAt}ms",
                readyAt - firstTapAt < 7_500)
            assertEquals(args.getString("expectedWorkMode") ?: "LITE", ModeRuntime.active?.name)
            val moduleState = modules.uiState.value
            val suState = superusers.uiState.value
            assertNull("Module page must not end in an error", moduleState.loadError)
            assertNull("Superuser page must not end in an error", suState.error)
            assertNull("Superuser page must not stay blocked", suState.blockedReason)
            assertTrue("Installed modules must be visible",
                moduleState.moduleList.size >= (args.getString("minimumModules")?.toInt() ?: 1))
            assertTrue("Installed application rows must be visible", suState.groupedApps.isNotEmpty())
            args.getString("expectedModuleCount")?.toInt()?.let { assertEquals(it, moduleState.moduleList.size) }
            args.getString("expectedApplicationGroupCount")?.toInt()?.let { assertEquals(it, suState.groupedApps.size) }
            repeat(2) {
                tapTab(R.string.module)
                waitUntil(SystemClock.elapsedRealtime() + 2_000) {
                    visibleNode { it.text?.toString() == moduleState.moduleList.first().name } != null
                }
                tapTab(R.string.superuser)
                val group = suState.groupedApps.first()
                val label = if (group.apps.size > 1) {
                    context.getString(R.string.group_contains_apps, group.apps.size)
                } else group.primary.label
                waitUntil(SystemClock.elapsedRealtime() + 2_000) {
                    visibleNode { it.text?.toString() == label } != null
                }
            }
            assertFalse(modules.uiState.value.isRefreshing)
            assertFalse(superusers.uiState.value.isRefreshing)
            instrumentation.sendStatus(2, Bundle().apply {
                putBoolean("modulesFirst", modulesFirst)
                putLong("coldNavigationReadyMillis", readyAt - firstTapAt)
                putLong("launchToReadyMillis", readyAt - launchAt)
                putLong("launchToFirstTapMillis", firstTapAt - launchAt)
                putLong("mainResponseMillis", mainResponseMillis)
                putInt("moduleCount", moduleState.moduleList.size)
                putInt("applicationGroupCount", suState.groupedApps.size)
            })
        }
    }

    private fun tapTab(id: Int): Long {
        val label = context.getString(id)
        var bounds: Rect? = null
        waitUntil(SystemClock.elapsedRealtime() + 5_000) {
            bounds = visibleNode { it.contentDescription?.toString() == label }
                ?.let { Rect().also(it::getBoundsInScreen) }
            bounds != null
        }
        // Native input preserves the production frame clock, including splash readiness.
        val target = checkNotNull(bounds)
        val tappedAt = SystemClock.elapsedRealtime()
        val downAt = SystemClock.uptimeMillis()
        for (action in listOf(MotionEvent.ACTION_DOWN, MotionEvent.ACTION_UP)) {
            val event = MotionEvent.obtain(downAt, SystemClock.uptimeMillis(), action,
                target.exactCenterX(), target.exactCenterY(), 0).apply { source = InputDevice.SOURCE_TOUCHSCREEN }
            try { assertTrue(instrumentation.uiAutomation.injectInputEvent(event, true)) }
            finally { event.recycle() }
        }
        return tappedAt
    }

    private fun visibleNode(matches: (AccessibilityNodeInfo) -> Boolean): AccessibilityNodeInfo? {
        val nodes = ArrayDeque<AccessibilityNodeInfo>()
        instrumentation.uiAutomation.rootInActiveWindow?.let(nodes::add)
        while (nodes.isNotEmpty()) {
            val node = nodes.removeFirst()
            if (node.isVisibleToUser && matches(node)) return node
            repeat(node.childCount) { node.getChild(it)?.let(nodes::add) }
        }
        return null
    }

    private fun waitUntil(deadline: Long, condition: () -> Boolean) {
        while (!condition()) {
            assertTrue("Cold page condition did not complete within its budget",
                SystemClock.elapsedRealtime() < deadline)
            SystemClock.sleep(20)
        }
    }
}
