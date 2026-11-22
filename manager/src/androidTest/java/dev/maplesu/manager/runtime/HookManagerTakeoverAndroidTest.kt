package dev.maplesu.manager.runtime

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.os.SystemClock
import android.graphics.Rect
import android.view.MotionEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.Natives
import com.maplesu.core.R
import com.maplesu.core.data.repository.SettingsRepository
import com.maplesu.core.data.repository.SettingsRepositoryImpl
import com.maplesu.core.ui.viewmodel.SuperUserViewModel
import androidx.lifecycle.viewModelScope
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import com.maplesu.core.data.repository.SuperUserRepositoryImpl
import com.maplesu.core.ui.MainActivity
import com.maplesu.core.ui.screen.settings.UltraEnvironmentPanel
import com.maplesu.core.ui.util.AppearancePreferences
import com.maplesu.core.ui.util.getSELinuxStatusRaw
import dev.maplesu.manager.jailbreak.JailbreakStatus
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/** Exercises the production page dependencies against an existing Hook; never attempts a new exploit. */
class HookManagerTakeoverAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    @Before fun readyHook() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyHookManagerTakeover") == "true")
        context.startActivity(Intent().setClassName(context, "com.maplesu.core.ui.MainActivity")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        val before = requireNotNull(JailbreakStatus.read(context))
        val result = requireNotNull(NativeSuDaemon.reproveHookOutcome(context))
        assertEquals(before.attemptId, result.attemptId)
        assertEquals(JailbreakStatus.STAGE_DAEMON_READY, result.stage)
        assertNull(result.failure)
        runBlocking { assertEquals(WorkMode.LITE, ModeRuntime.awaitActivated(15_000)) }
        assertTrue(HookRootExecutor.production(context).available())
    }

    @Test fun globalSwitchUsesTheActiveHookAuthority() {
        assertTrue("The production SU switch did not enable the Hook authority", Natives.setSuEnabled(true))
        assertTrue("The production SU switch did not read back its committed value", Natives.isSuEnabled())
    }

    @Test fun applicationListLoadsThroughHookWithoutSdkOrLibsu() = runBlocking {
        val (apps, users) = SuperUserRepositoryImpl().getAppList().getOrThrow()
        assertTrue("Hook superuser page returned no applications", apps.isNotEmpty())
        assertTrue(apps.any { it.packageName == context.packageName })
        assertTrue(users.isNotEmpty())
        val refreshed = SuperUserRepositoryImpl().refreshProfiles(apps).getOrThrow()
        assertEquals(apps.size, refreshed.size)
    }

    @Test fun settingsRecognizeTheLiveHookEnvironment() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val panel = UltraEnvironmentPanel(context, scope, UltraEnvironmentProbe.currentSnapshot())
            panel.loadInitialState()
            val deadline = SystemClock.elapsedRealtime() + 15_000
            while (panel.busy && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(50)
            assertFalse("Environment settings exceeded their read budget", panel.busy)
            assertEquals("Settings ignored the live Hook environment", UltraEnvironmentProbe.State.Running, panel.state)
            assertTrue("Settings selected the historical SDK environment", panel.hookEnvironment)
        } finally {
            scope.cancel()
        }
    }

    @Test fun grantIndependentPeerThroughTheProductionProfile() = updatePeer(true)
    @Test fun revokeIndependentPeerThroughTheProductionProfile() = updatePeer(false)

    @Test fun selinuxMatchesTheActualHookRoot() {
        val probe = HookRootExecutor.production(context)
            .run("/system/bin/id -u; /system/bin/getenforce")
        assertEquals(probe.detail, 0, probe.code)
        val lines = probe.output.trim().lines()
        assertEquals(2, lines.size)
        assertEquals("0", lines[0])
        assertTrue(lines[1] in setOf("Enforcing", "Permissive", "Disabled"))
        assertEquals("SELinux UI ignored the actual Hook root", lines[1], getSELinuxStatusRaw())
    }

    private fun updatePeer(grant: Boolean) {
        assumeTrue(InstrumentationRegistry.getArguments().getString("mutateHookPeerProfile") == "true")
        val peer = context.packageManager.getApplicationInfo("dev.maplesu.manager.test", 0)
        assertNotEquals(context.applicationInfo.uid, peer.uid)
        val profile = requireNotNull(Natives.getAppProfile(peer.packageName, peer.uid))
        assertTrue("The production profile write failed", Natives.setAppProfile(profile.copy(allowSu = grant)))
        assertEquals(grant, requireNotNull(Natives.getAppProfile(peer.packageName, peer.uid)).allowSu)
        assertTrue("Profile updates changed the global switch", Natives.isSuEnabled())
    }

    @Test fun lateSuReadDoesNotOverwriteEnable() {
        val reading = CountDownLatch(1)
        val release = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val settings = object : SettingsRepository by SettingsRepositoryImpl() {
            override fun isSuEnabled(): Boolean {
                reading.countDown()
                check(release.await(10, TimeUnit.SECONDS))
                finished.countDown()
                return false
            }
            override fun setSuEnabled(enabled: Boolean): Boolean = true
        }
        lateinit var model: SuperUserViewModel
        instrumentation.runOnMainSync {
            model = SuperUserViewModel(settingsRepo = settings)
            model.refreshSuState()
        }
        try {
            assertTrue(reading.await(5, TimeUnit.SECONDS))
            instrumentation.runOnMainSync { model.enableSu() }
            await("SU did not enable") { model.uiState.value.suEnabled == true }
            release.countDown()
            assertTrue(finished.await(5, TimeUnit.SECONDS))
            SystemClock.sleep(300)
            assertEquals("A stale read overwrote the committed enable", true, model.uiState.value.suEnabled)
        } finally {
            release.countDown()
            instrumentation.runOnMainSync { model.viewModelScope.cancel() }
        }
    }

    @Test fun materialPagesUseHook() = verifyPages("material")
    @Test fun miuixPagesUseHook() = verifyPages("miuix")

    private fun verifyPages(theme: String) {
        val appearance = AppearancePreferences.prefs(context)
        val oldTheme = appearance.getString("ui_mode", null)
        val settings = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
        val oldAnnouncement = settings.getBoolean("announcement_never_show", false)
        appearance.edit().putString("ui_mode", theme).commit()
        settings.edit().putBoolean("announcement_never_show", true).commit()
        try {
            assertTrue(Natives.setSuEnabled(false))
            assertFalse(Natives.isSuEnabled())
            val launch = Intent(context, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            ActivityScenario.launch<MainActivity>(launch).use {
                click(context.getString(R.string.superuser))
                val disabled = context.getString(R.string.maplesu_su_disabled_enable)
                await("Disabled SU banner was not rendered") { visibleTexts().any { it.contains(disabled) } }
                click(disabled)
                await("The page did not enable the real SU authority") { Natives.isSuEnabled() }
                await("Enabled page retained the disabled banner") { visibleTexts().none { it.contains(disabled) } }
                val installedLabels = runBlocking { SuperUserRepositoryImpl().getAppList().getOrThrow().first }
                    .filter { it.packageName != context.packageName && it.uid / 100000 == 0 &&
                        (it.packageInfo.applicationInfo?.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM == 0 }
                    .map { it.label }.toSet()
                assertTrue("No independent user applications were available", installedLabels.isNotEmpty())
                await("The visible superuser list stayed empty") { visibleTexts().any { it in installedLabels } }
                click(context.getString(R.string.settings))
                val title = context.getString(R.string.ui_d_env_title)
                reveal(title)
                val running = context.getString(R.string.ui_d_env_state_running)
                val hook = context.getString(R.string.ui_d_env_hook_summary, "").substringBefore('·').trim()
                await("Settings did not render an available Hook environment") {
                    val labels = visibleTexts()
                    labels.any { it.contains(title) } && labels.any { it.contains(hook) } &&
                        labels.any { it.contains(running) }
                }
                assertFalse(visibleTexts().any { it.contains(context.getString(R.string.ui_d_env_state_not_installed)) })
            }
        } finally {
            appearance.edit().apply {
                if (oldTheme == null) remove("ui_mode") else putString("ui_mode", oldTheme)
            }.commit()
            settings.edit().putBoolean("announcement_never_show", oldAnnouncement).commit()
            Natives.setSuEnabled(true)
        }
    }

    private fun await(message: String, predicate: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 20_000
        while (SystemClock.elapsedRealtime() < deadline) {
            if (predicate()) return
            SystemClock.sleep(100)
        }
        throw AssertionError("$message; visible=${visibleTexts()}")
    }

    private fun reveal(label: String) {
        repeat(5) {
            if (visibleTexts().any { it.contains(label) }) return
            fun scroll(node: AccessibilityNodeInfo): Boolean {
                if (node.isVisibleToUser && node.isScrollable &&
                    node.performAction(AccessibilityNodeInfo.ACTION_SCROLL_FORWARD)) return true
                for (index in 0 until node.childCount) {
                    if (node.getChild(index)?.let(::scroll) == true) return true
                }
                return false
            }
            instrumentation.uiAutomation.rootInActiveWindow?.let(::scroll)
            SystemClock.sleep(400)
        }
    }

    private fun click(label: String) = await("No clickable page element: $label") {
        val matches = mutableListOf<Rect>()
        fun find(node: AccessibilityNodeInfo) {
            if (node.isVisibleToUser &&
                (node.text?.toString() == label || node.contentDescription?.toString() == label)) {
                val bounds = Rect()
                node.getBoundsInScreen(bounds)
                if (!bounds.isEmpty) matches += bounds
            }
            for (index in 0 until node.childCount) node.getChild(index)?.let(::find)
        }
        instrumentation.uiAutomation.rootInActiveWindow?.let(::find)
        // The settings toolbar action and the bottom settings tab share a label.
        val bounds = matches.maxByOrNull { it.centerY() }
        if (bounds == null) false else {
            val at = SystemClock.uptimeMillis()
            val down = MotionEvent.obtain(at, at, MotionEvent.ACTION_DOWN,
                bounds.centerX().toFloat(), bounds.centerY().toFloat(), 0)
            val up = MotionEvent.obtain(at, at + 60, MotionEvent.ACTION_UP,
                bounds.centerX().toFloat(), bounds.centerY().toFloat(), 0)
            try {
                instrumentation.sendPointerSync(down)
                instrumentation.sendPointerSync(up)
            } finally { down.recycle(); up.recycle() }
            true
        }
    }

    private fun visibleTexts(): List<String> = buildList {
        fun read(node: AccessibilityNodeInfo) {
            if (node.isVisibleToUser) {
                node.text?.toString()?.let(::add)
                node.contentDescription?.toString()?.let(::add)
            }
            for (index in 0 until node.childCount) node.getChild(index)?.let(::read)
        }
        instrumentation.uiAutomation.rootInActiveWindow?.let(::read)
    }
}
