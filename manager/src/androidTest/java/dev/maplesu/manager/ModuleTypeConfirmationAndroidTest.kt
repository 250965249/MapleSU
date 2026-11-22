package dev.maplesu.manager

import android.app.Activity
import android.app.Application
import android.net.Uri
import android.os.Bundle
import android.os.SystemClock
import android.view.WindowManager
import android.view.accessibility.AccessibilityNodeInfo
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.CompositionLocalProvider
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.navigation3.LocalNavigator
import com.maplesu.core.ui.navigation3.Route
import com.maplesu.core.ui.navigation3.rememberNavigator
import com.maplesu.core.ui.screen.flash.FlashIt
import com.maplesu.core.ui.screen.flash.FlashScreen
import com.maplesu.core.ui.theme.KernelSUTheme
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Real FlashScreen and upstream dialogs in both themes; no root backend is substituted. */
@RunWith(AndroidJUnit4::class)
class ModuleTypeConfirmationAndroidTest {
    @Test fun materialRecognizesConfirmsAndReportsTheRealBackendResult() = confirm(UiMode.Material)
    @Test fun miuixRecognizesConfirmsAndReportsTheRealBackendResult() = confirm(UiMode.Miuix)
    @Test fun materialRechecksAndConfirmsAfterActivityRecreation() = confirm(UiMode.Material, recreate = true)
    @Test fun miuixRechecksAndConfirmsAfterActivityRecreation() = confirm(UiMode.Miuix, recreate = true)

    private fun confirm(mode: UiMode, recreate: Boolean = false) {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val application = context.applicationContext as Application
        val input = File.createTempFile("confirm-source-", ".zip", context.cacheDir)
        val marker = File(context.cacheDir, "module-script-must-not-run-${System.nanoTime()}")
        // Replace only the test's composition root, including after a real Activity recreation.
        // FlashScreen, its saveable state, dialogs, inspector and backend remain production code.
        val callbacks = object : Application.ActivityLifecycleCallbacks {
            override fun onActivityPostCreated(activity: Activity, savedInstanceState: Bundle?) {
                if (activity.javaClass != ComponentActivity::class.java) return
                activity as ComponentActivity
                activity.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                activity.setContent {
                    val navigator = rememberNavigator(Route.Main)
                    CompositionLocalProvider(LocalUiMode provides mode, LocalNavigator provides navigator) {
                        KernelSUTheme(uiMode = mode) {
                            FlashScreen(FlashIt.FlashModules(listOf(Uri.fromFile(input)))) {}
                        }
                    }
                }
            }
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
            override fun onActivityStarted(activity: Activity) {}
            override fun onActivityResumed(activity: Activity) {}
            override fun onActivityPaused(activity: Activity) {}
            override fun onActivityStopped(activity: Activity) {}
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
            override fun onActivityDestroyed(activity: Activity) {}
        }
        try {
            ZipOutputStream(input.outputStream()).use { zip ->
                for ((name, bytes) in listOf("module.prop" to "id=maple_demo\nname=Maple Test\n",
                    "service.sh" to "touch '${marker.absolutePath}'")) {
                    zip.putNextEntry(ZipEntry(name)); zip.write(bytes.toByteArray()); zip.closeEntry()
                }
            }
            val original = input.readBytes()
            application.registerActivityLifecycleCallbacks(callbacks)
            ActivityScenario.launch(ComponentActivity::class.java).use { scenario ->
                awaitText(context.getString(R.string.module_type_ksu))
                awaitText("Maple Test")
                assertFalse(marker.exists())
                if (recreate) {
                    scenario.recreate()
                    awaitText(context.getString(R.string.module_type_ksu))
                    awaitText("Maple Test")
                    assertFalse(marker.exists())
                }
                val install = awaitText(context.getString(R.string.module_install), clickable = true)
                assertTrue(install.performAction(AccessibilityNodeInfo.ACTION_CLICK))
                awaitText(context.getString(R.string.root_install_required))
                assertFalse(marker.exists())
                assertArrayEquals(original, input.readBytes())
            }
        } finally {
            application.unregisterActivityLifecycleCallbacks(callbacks)
            input.delete(); marker.delete()
        }
    }

    private fun awaitText(text: String, clickable: Boolean = false): AccessibilityNodeInfo {
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        val deadline = SystemClock.uptimeMillis() + 15_000
        var matchingNodes = ""
        while (SystemClock.uptimeMillis() < deadline) {
            val nodes = ArrayDeque<AccessibilityNodeInfo>()
            automation.rootInActiveWindow?.let(nodes::addLast)
            while (nodes.isNotEmpty()) {
                val node = nodes.removeFirst()
                if (node.isVisibleToUser && node.text?.contains(text) == true) {
                    if (!clickable) return node
                    var candidate: AccessibilityNodeInfo? = node
                    val chain = mutableListOf<String>()
                    while (candidate != null) {
                        chain += "${candidate.className}(text=${candidate.text}, clickable=${candidate.isClickable}, children=${candidate.childCount})"
                        if (candidate.isClickable && containsOnlyLabel(candidate, text)) return candidate
                        candidate = candidate.parent
                    }
                    matchingNodes = chain.joinToString(" -> ")
                }
                for (i in 0 until node.childCount) node.getChild(i)?.let(nodes::addLast)
            }
            SystemClock.sleep(100)
        }
        throw AssertionError("Visible text did not appear: $text; matching nodes: $matchingNodes")
    }

    // Miuix exposes TextButton as a View; its dismissible dialog surface is clickable too.
    private fun containsOnlyLabel(root: AccessibilityNodeInfo, label: String): Boolean {
        val nodes = ArrayDeque<AccessibilityNodeInfo>()
        nodes.add(root)
        var found = false
        while (nodes.isNotEmpty()) {
            val node = nodes.removeFirst()
            val text = node.text?.toString().orEmpty()
            if (text.isNotBlank()) {
                if (text != label) return false
                found = true
            }
            for (i in 0 until node.childCount) node.getChild(i)?.let(nodes::addLast)
        }
        return found
    }
}
