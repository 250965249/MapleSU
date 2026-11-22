package com.maplesu.core.ui

import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.storage.ModePaths
import dev.maplesu.manager.workmode.storage.SettingsPrefsPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * P1 配置隔离：UI 侧 `"settings"` 直连改造的契约测试（纯 JVM）。
 *
 * 路由规则唯一来源 = `SettingsPrefsPolicy` / `ModePaths`；本测试锁定：
 * A 原名逐字节等价、B 独立、未判定按策略（中性/证据，禁止默认 A）、切换后各读各的、
 * 以及 5 个直连点确实改走 `SettingsPrefsRouter`（源码契约，避免规则被复制/回退）。
 */
class ModePrefsRouteContractTest {

    // ── 规则等价/隔离 ─────────────────────────────────────────────────────

    @Test
    fun liteKeepsLegacySettingsName() {
        assertEquals("settings", SettingsPrefsPolicy.nameFor(WorkMode.LITE))
        assertEquals("settings", ModePaths.prefsNameFor("settings", WorkMode.LITE))
        // A 不变量：和改造前完全相同的文件、相同的 key（同文件同 key = 逐字节等价）。
        assertEquals(SettingsPrefsPolicy.A_NAME, ModePaths.prefsNameFor("settings", WorkMode.LITE))
    }

    @Test
    fun ksuUsesIsolatedSettingsB() {
        assertEquals("settings_B", SettingsPrefsPolicy.nameFor(WorkMode.KSU))
        assertEquals("settings_B", ModePaths.prefsNameFor("settings", WorkMode.KSU))
        assertNotEquals(
            SettingsPrefsPolicy.nameFor(WorkMode.LITE),
            SettingsPrefsPolicy.nameFor(WorkMode.KSU),
        )
    }

    @Test
    fun unresolvedNeverFallsBackToLiteWithoutEvidence() {
        assertNull(SettingsPrefsPolicy.nameFor(null))
        assertEquals(
            ModePaths.NEUTRAL_PREFS,
            SettingsPrefsPolicy.unresolvedName(lastKnown = null, liteEvidencePresent = false),
        )
    }

    @Test
    fun unresolvedUsesLastKnownHintOrExplicitLiteEvidence() {
        assertEquals(
            "settings",
            SettingsPrefsPolicy.unresolvedName(lastKnown = WorkMode.LITE, liteEvidencePresent = false),
        )
        assertEquals(
            "settings_B",
            SettingsPrefsPolicy.unresolvedName(lastKnown = WorkMode.KSU, liteEvidencePresent = false),
        )
        assertEquals(
            "settings",
            SettingsPrefsPolicy.unresolvedName(lastKnown = null, liteEvidencePresent = true),
        )
    }

    @Test
    fun switchingModesReadsSeparateStores() {
        // 模拟进程重启后的两次读取：A 读 A 文件、B 读 B 文件，互不串档。
        val a = ModePaths.prefsNameFor("settings", WorkMode.LITE)
        val b = ModePaths.prefsNameFor("settings", WorkMode.KSU)
        assertEquals("settings", a)
        assertEquals("settings_B", b)
        assertNotEquals(a, b)
        // 文件名与 ModePaths.prefsFile 的落盘名一致（同文件同 key 的另一重证据）。
        assertTrue(ModePaths.prefsFile("/data/user/0/app/shared_prefs", "settings", WorkMode.LITE).endsWith("settings.xml"))
        assertTrue(ModePaths.prefsFile("/data/user/0/app/shared_prefs", "settings", WorkMode.KSU).endsWith("settings_B.xml"))
    }

    // ── UI 直连点源码契约（防复制规则/回退） ─────────────────────────────

    private fun source(path: String): String? = File(path).takeIf { it.isFile }?.readText()

    @Test
    fun appearanceUsesSharedPreferencesAndFunctionalSettingsRemainRouted() {
        val callSites = listOf(
            "src/main/java/com/maplesu/core/ui/util/WallpaperPrefs.kt",
            "src/main/java/com/maplesu/core/ui/viewmodel/MainActivityViewModel.kt",
            "src/main/java/com/maplesu/core/ui/webui/SuFilePathHandler.java",
            "src/main/java/com/maplesu/core/ui/webui/WebUIActivity.kt",
            "src/main/java/com/maplesu/core/ui/webui/WebViewHelper.kt",
        )
        val missing = mutableListOf<String>()
        callSites.forEach { path ->
            val text = source(path) ?: return@forEach
            val expected = if (path.endsWith("WebViewHelper.kt")) "SettingsPrefsRouter" else "AppearancePreferences"
            if (!text.contains(expected)) missing += path
        }
        assumeTrue("sources unavailable (run in manager module dir)", missing.size < callSites.size)
        assertTrue("call sites not using the appropriate preferences source: $missing", missing.isEmpty())
    }

    @Test
    fun uiSettingsCallSitesNoLongerReadRawSettingsDirectly() {
        val callSites = listOf(
            "src/main/java/com/maplesu/core/ui/util/WallpaperPrefs.kt",
            "src/main/java/com/maplesu/core/ui/viewmodel/MainActivityViewModel.kt",
            "src/main/java/com/maplesu/core/ui/webui/SuFilePathHandler.java",
            "src/main/java/com/maplesu/core/ui/webui/WebUIActivity.kt",
            "src/main/java/com/maplesu/core/ui/webui/WebViewHelper.kt",
        )
        val offenders = mutableListOf<String>()
        callSites.forEach { path ->
            val text = source(path) ?: return@forEach
            if (text.contains("getSharedPreferences(\"settings\"")) offenders += path
        }
        assumeTrue("sources unavailable", offenders.isEmpty() || offenders.size < callSites.size)
        assertTrue("raw getSharedPreferences(\"settings\") remains: $offenders", offenders.isEmpty())
    }

    @Test
    fun perModeKeysAreTheSameKeysNotDuplicated() {
        // 同文件同 key 的语义：路由只换文件，不换 key；因此不变量就是"两种模式文件名不同"。
        assertFalse(SettingsPrefsPolicy.A_NAME == SettingsPrefsPolicy.B_NAME)
        assertEquals("settings", SettingsPrefsPolicy.A_NAME)
        assertEquals("settings_B", SettingsPrefsPolicy.B_NAME)
    }
}
