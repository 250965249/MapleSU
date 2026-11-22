package dev.maplesu.manager

import android.content.Context
import android.os.SystemClock
import android.view.accessibility.AccessibilityNodeInfo
import android.view.WindowManager
import android.accessibilityservice.AccessibilityService
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.ui.MainActivity
import com.maplesu.core.R
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Exercise visible upstream screens on Android; no root dependency is substituted. */
@RunWith(AndroidJUnit4::class)
class ManagerUiSmokeTest {
    @Test fun materialInstallNavigationAndRecreation() = launchAndRecreate("material")
    @Test fun miuixInstallNavigationAndRecreation() = launchAndRecreate("miuix")

    private fun launchAndRecreate(mode: String) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
        val oldMode = prefs.getString("ui_mode", null)
        val oldNeverShow = prefs.getBoolean("announcement_never_show", false)
        prefs.edit().putString("ui_mode", mode).putBoolean("announcement_never_show", true).commit()
        try {
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                scenario.onActivity { activity ->
                    activity.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                    assertEquals("dev.maplesu.manager", activity.packageName)
                    assertFalse(activity.isFinishing)
                }
                val installPrompt = context.getString(R.string.home_click_to_install)
                var install = awaitVisibleText(installPrompt)
                while (!install.isClickable) {
                    install = install.parent ?: throw AssertionError("Install prompt has no clickable parent")
                }
                assertTrue("Install prompt did not accept click", install.performAction(AccessibilityNodeInfo.ACTION_CLICK))
                val selectFile = context.getString(R.string.select_file)
                awaitVisibleText(selectFile)
                scenario.recreate()
                scenario.onActivity {
                    it.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                    assertFalse(it.isFinishing)
                }
                awaitVisibleText(selectFile)
                assertTrue(instrumentation.uiAutomation.performGlobalAction(AccessibilityService.GLOBAL_ACTION_BACK))
                awaitVisibleText(installPrompt)
            }
        } finally {
            prefs.edit().putString("ui_mode", oldMode).putBoolean("announcement_never_show", oldNeverShow).commit()
        }
    }

    private fun awaitVisibleText(text: String): AccessibilityNodeInfo {
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        val deadline = SystemClock.uptimeMillis() + 15_000
        var activePackage: String? = null
        while (SystemClock.uptimeMillis() < deadline) {
            val root = automation.rootInActiveWindow
            activePackage = root?.packageName?.toString()
            if (root != null && activePackage == "dev.maplesu.manager") {
                val nodes = ArrayDeque<AccessibilityNodeInfo>()
                nodes.add(root)
                while (nodes.isNotEmpty()) {
                    val node = nodes.removeFirst()
                    if (node.isVisibleToUser && (node.text?.contains(text) == true ||
                            node.contentDescription?.contains(text) == true)) return node
                    for (index in 0 until node.childCount) node.getChild(index)?.let(nodes::addLast)
                }
            }
            SystemClock.sleep(100)
        }
        throw AssertionError("Visible app text did not appear: $text (active package: $activePackage)")
    }
}
