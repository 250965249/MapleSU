package dev.maplesu.manager.installer

import android.content.Context
import android.os.SystemClock
import android.view.WindowManager
import android.view.accessibility.AccessibilityNodeInfo
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.Natives
import com.maplesu.core.R
import com.maplesu.core.ui.MainActivity
import com.maplesu.core.ui.util.rootAvailable
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** The real installation screen must discover an existing provider's application grant. */
@RunWith(AndroidJUnit4::class)
class InstallerUiAndroidTest {
    @Test fun materialShowsDirectInstallAfterAuthorizationAndResume() = verify("material")
    @Test fun miuixShowsDirectInstallAfterAuthorizationAndResume() = verify("miuix")

    @Test fun authorizedDirectSourceIsTheCurrentBootImage() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("existingRootInstaller") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        ActivityScenario.launch(MainActivity::class.java).use {
            val snapshot = InstallerServiceClient.analyzeCurrentBoot(context)
            val image = dev.maplesu.manager.ImageRepository(context).restore()!!
            assertEquals(snapshot.partitions.getValue("boot").sha256, image.report.sha256)
            assertEquals(snapshot.kernelRelease,
                org.json.JSONObject(image.roundTripJson!!).getString("kernelRelease"))
            assertFalse(org.json.JSONObject(image.roundTripJson!!).getBoolean("flashableCandidate"))
        }
    }

    private fun verify(mode: String) {
        assumeTrue(InstrumentationRegistry.getArguments().getString("existingRootInstaller") == "true")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        InstallerRootSession.open(context).close()
        val wasManager = Natives.isManager
        val managerRoot = rootAvailable()
        val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
        val oldMode = prefs.getString("ui_mode", null)
        val oldAnnouncement = prefs.getBoolean("announcement_never_show", false)
        prefs.edit().putString("ui_mode", mode).putBoolean("announcement_never_show", true).commit()
        try {
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                scenario.onActivity { it.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON) }
                click(awaitText(context.getString(R.string.home_click_to_install), clickable = true))
                awaitText(context.getString(R.string.select_file))
                val direct = context.getString(R.string.direct_install)
                awaitText(direct)
                scenario.moveToState(Lifecycle.State.STARTED)
                scenario.moveToState(Lifecycle.State.RESUMED)
                awaitText(direct)
                scenario.recreate()
                awaitText(direct)
                click(awaitText(direct, clickable = true))
                awaitText(context.getString(R.string.install_next), clickable = true)
                // Ordinary UI discovery never starts a production partition commit.
                assertEquals(wasManager, Natives.isManager)
                assertEquals(managerRoot, rootAvailable())
            }
        } finally {
            prefs.edit().putString("ui_mode", oldMode)
                .putBoolean("announcement_never_show", oldAnnouncement).commit()
        }
    }

    private fun click(node: AccessibilityNodeInfo) {
        var target = node
        while (!target.isClickable) target = target.parent ?: error("No clickable install action")
        assertTrue(target.performAction(AccessibilityNodeInfo.ACTION_CLICK))
    }

    private fun awaitText(text: String, clickable: Boolean = false): AccessibilityNodeInfo {
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        val deadline = SystemClock.uptimeMillis() + 10_000
        var visible = emptyList<String>()
        while (SystemClock.uptimeMillis() < deadline) {
            val nodes = ArrayDeque<AccessibilityNodeInfo>()
            val labels = mutableListOf<String>()
            automation.rootInActiveWindow?.takeIf { it.packageName == "dev.maplesu.manager" }
                ?.let(nodes::addLast)
            while (nodes.isNotEmpty()) {
                val node = nodes.removeFirst()
                if (node.isVisibleToUser && !node.text.isNullOrBlank()) labels.add(node.text.toString())
                if (node.isVisibleToUser && (node.text?.contains(text) == true ||
                        node.contentDescription?.contains(text) == true)) {
                    if (!clickable) return node
                    var target: AccessibilityNodeInfo? = node
                    while (target != null) {
                        if (target.isClickable && target.isEnabled) return target
                        target = target.parent
                    }
                }
                for (i in 0 until node.childCount) node.getChild(i)?.let(nodes::addLast)
            }
            visible = labels
            SystemClock.sleep(100)
        }
        throw AssertionError("Authorized install option did not appear: $text; visible=$visible")
    }
}
