package dev.maplesu.manager.runtime

import android.graphics.Rect
import android.os.Bundle
import android.os.SystemClock
import android.view.InputDevice
import android.view.MotionEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.lifecycle.ViewModelStore
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.R
import com.maplesu.core.ui.MainActivity
import com.maplesu.core.ui.viewmodel.SettingsViewModel
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Real pager warm-up and a rendered settings-tab tap; no environment mutation. */
class SettingsPageStartupAndroidTest {
    @Test fun precomposedSettingsReadsRuntimeOnlyAfterItsFirstVisit() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySettingsStartup") == "true")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            assertEquals(WorkMode.LITE, runBlocking { ModeRuntime.awaitPageMode(5_000) })
            val models = mutableListOf<SettingsViewModel>()
            fun collectModels() = scenario.onActivity { activity ->
                models.clear()
                val pending = ArrayDeque<ViewModelStore>().apply { add(activity.viewModelStore) }
                while (pending.isNotEmpty()) {
                    val store = pending.removeFirst()
                    for (key in store.keys()) {
                        val model = store[key] ?: continue
                        if (model is SettingsViewModel) models.add(model)
                        if (model.javaClass.name.endsWith("NavEntryViewModelStores")) {
                            val nested = model.javaClass.getDeclaredField("stores").apply { isAccessible = true }
                            (nested.get(model) as Map<*, *>).values.filterIsInstance<ViewModelStore>()
                                .forEach(pending::add)
                        }
                    }
                }
            }
            val warmDeadline = SystemClock.uptimeMillis() + 5_000
            while (SystemClock.uptimeMillis() < warmDeadline) {
                collectModels()
                if (models.isNotEmpty()) break
                SystemClock.sleep(50)
            }
            assertEquals("Settings must remain precomposed, not become a blank first swipe", 1, models.size)
            val refresh = SettingsViewModel::class.java.getDeclaredField("refreshJob").apply { isAccessible = true }
            assertNull("Unvisited settings submitted an SDK/root refresh", refresh.get(models.single()))
            var label = ""
            scenario.onActivity { label = it.getString(R.string.settings) }
            var bounds: Rect? = null
            val tabDeadline = SystemClock.uptimeMillis() + 5_000
            while (bounds == null && SystemClock.uptimeMillis() < tabDeadline) {
                val nodes = ArrayDeque<AccessibilityNodeInfo>().apply {
                    instrumentation.uiAutomation.rootInActiveWindow?.let(::add)
                }
                while (nodes.isNotEmpty()) {
                    val node = nodes.removeFirst()
                    if (node.isVisibleToUser && (node.text?.toString() == label || node.contentDescription?.toString() == label)) {
                        bounds = Rect().also(node::getBoundsInScreen)
                        break
                    }
                    repeat(node.childCount) { node.getChild(it)?.let(nodes::add) }
                }
                if (bounds == null) SystemClock.sleep(50)
            }
            val target = checkNotNull(bounds) { "Settings tab is not rendered" }
            val started = SystemClock.uptimeMillis()
            for (action in listOf(MotionEvent.ACTION_DOWN, MotionEvent.ACTION_UP)) {
                val event = MotionEvent.obtain(started, SystemClock.uptimeMillis(), action,
                    target.exactCenterX(), target.exactCenterY(), 0).apply { source = InputDevice.SOURCE_TOUCHSCREEN }
                try { assertTrue(instrumentation.uiAutomation.injectInputEvent(event, true)) } finally { event.recycle() }
            }
            val model = models.single()
            val deadline = started + 5_000
            while (SystemClock.uptimeMillis() < deadline) {
                val state = model.uiState.value
                if (refresh.get(model) != null && state.managerValid && !state.hiddenMasked &&
                    state.modePolicy.mode == WorkMode.LITE && state.workModeEntry.showSettingsRow &&
                    state.liteHiddenCard.showsRow) {
                    instrumentation.sendStatus(2, Bundle().apply {
                        putLong("coldSettingsReadyMillis", SystemClock.uptimeMillis() - started)
                    })
                    return
                }
                SystemClock.sleep(50)
            }
            fail("Visible settings did not complete its real runtime refresh")
        }
    }
}
