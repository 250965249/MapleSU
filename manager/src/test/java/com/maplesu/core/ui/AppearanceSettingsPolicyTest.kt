package com.maplesu.core.ui

import com.maplesu.core.ui.util.AppearancePrefsPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import kotlin.math.abs

/**
 * 外观设置（默认壁纸 / 界面扁平化 / 界面透明化）的纯 JVM 契约测试。
 *
 * 这里锁的是三件用户可见行为：
 * 1. 默认壁纸已删除：不再播种、没有内置默认图兜底，空壁纸 = 纯主题背景；
 * 2. 界面扁平化恒 false：旧键 `flat_home=true` 也不能让界面变扁平，设置页不再渲染该开关；
 * 3. 界面透明化恢复：默认关、选壁纸后自动开、已存值原样沿用、alpha 换算不变。
 */
class AppearanceSettingsPolicyTest {

    // ── 界面扁平化：恒 false ─────────────────────────────────────────────

    @Test
    fun flatUiStaysOffEvenWhenLegacyKeyWasTrue() {
        assertFalse(AppearancePrefsPolicy.effectiveFlatUi(stored = true))
    }

    @Test
    fun flatUiStaysOffWhenLegacyKeyWasFalse() {
        assertFalse(AppearancePrefsPolicy.effectiveFlatUi(stored = false))
    }

    // ── 界面透明化：默认关 / 已存值沿用 ──────────────────────────────────

    @Test
    fun translucentDefaultsOffWhenPreferenceIsMissing() {
        assertFalse(AppearancePrefsPolicy.effectiveTranslucent(stored = null))
        assertFalse(AppearancePrefsPolicy.DEFAULT_TRANSLUCENT)
    }

    @Test
    fun translucentKeepsExplicitlyStoredOff() {
        assertFalse(AppearancePrefsPolicy.effectiveTranslucent(stored = false))
    }

    @Test
    fun translucentKeepsExplicitlyStoredOn() {
        assertTrue(AppearancePrefsPolicy.effectiveTranslucent(stored = true))
    }

    @Test
    fun firstWallpaperPickTurnsTranslucentOnWhenNeverStored() {
        assertTrue(AppearancePrefsPolicy.autoEnableTranslucentOnWallpaperPick(hasStoredPreference = false))
    }

    @Test
    fun wallpaperPickNeverOverridesExplicitUserChoice() {
        assertFalse(AppearancePrefsPolicy.autoEnableTranslucentOnWallpaperPick(hasStoredPreference = true))
    }

    // ── alpha / 可见度换算：沿用原实现 ────────────────────────────────────

    @Test
    fun translucentAlphaDefaultsToOriginalMinimum() {
        assertEquals(0.02f, AppearancePrefsPolicy.DEFAULT_TRANSLUCENT_ALPHA, 0.0001f)
        assertEquals(0.02f, AppearancePrefsPolicy.MIN_TRANSLUCENT_ALPHA, 0.0001f)
        assertEquals(0.02f, AppearancePrefsPolicy.normalizeTranslucentAlpha(0.02f), 0.0001f)
    }

    @Test
    fun translucentAlphaClampsLegacyOutOfRangeValues() {
        assertEquals(0.02f, AppearancePrefsPolicy.normalizeTranslucentAlpha(0f), 0.0001f)
        assertEquals(0.02f, AppearancePrefsPolicy.normalizeTranslucentAlpha(-1f), 0.0001f)
        assertEquals(1f, AppearancePrefsPolicy.normalizeTranslucentAlpha(2f), 0.0001f)
    }

    @Test
    fun visibilityMapsMinimumAlphaToFullWallpaperVisibility() {
        assertEquals(1f, AppearancePrefsPolicy.visibilityForAlpha(0.02f), 0.0001f)
    }

    @Test
    fun visibilityMapsOpaqueAlphaToZero() {
        assertEquals(0f, AppearancePrefsPolicy.visibilityForAlpha(1f), 0.0001f)
    }

    @Test
    fun visibilityAndAlphaRoundTrip() {
        val alpha = AppearancePrefsPolicy.alphaForVisibility(0.63f)
        assertTrue(abs(AppearancePrefsPolicy.visibilityForAlpha(alpha) - 0.63f) < 0.0001f)
    }

    @Test
    fun alphaForVisibilityClampsSliderInput() {
        assertEquals(1f, AppearancePrefsPolicy.alphaForVisibility(-1f), 0.0001f)
        assertEquals(0.02f, AppearancePrefsPolicy.alphaForVisibility(2f), 0.0001f)
    }

    // ── 默认壁纸：空值不再被当成"要铺默认图" ─────────────────────────────

    @Test
    fun emptyWallpaperKindMeansNoWallpaper() {
        assertFalse(AppearancePrefsPolicy.hasWallpaper(""))
    }

    @Test
    fun noneWallpaperKindMeansNoWallpaper() {
        assertFalse(AppearancePrefsPolicy.hasWallpaper("none"))
    }

    @Test
    fun userConfiguredWallpaperKindIsDetected() {
        assertTrue(AppearancePrefsPolicy.hasWallpaper("image"))
        assertTrue(AppearancePrefsPolicy.hasWallpaper("video"))
    }

    // ── 源码契约：默认播种/兜底/扁平开关确实从 UI 与启动链消失 ──────────

    private fun source(path: String): String? = File(path).takeIf { it.isFile }?.readText()

    @Test
    fun startupNoLongerSeedsDefaultWallpaper() {
        val main = source(MAIN_ACTIVITY)
        assumeTrue("MainActivity source unavailable (run in manager module dir)", main != null)
        assertFalse(main!!.contains("seedDefaultIfNeeded"))
        assertFalse(main.contains("wallpaper_default_"))
    }

    @Test
    fun wallpaperStoreHasNoBuiltinDefaultOrFallback() {
        val store = source(WALLPAPER_STORE)
        assumeTrue("WallpaperStore source unavailable", store != null)
        assertFalse(store!!.contains("fun builtinArt"))
        assertFalse(store.contains("applyBuiltin"))
        assertFalse(store.contains("WallpaperSeedPolicy"))
        assertFalse(store.contains("Drawn.Builtin"))
        assertFalse(store.contains("wallpaper_default_"))
    }

    @Test
    fun settingsNoLongerRenderFlatSwitch() {
        for (path in listOf(SETTINGS_MIUIX, SETTINGS_MATERIAL)) {
            val text = source(path)
            assumeTrue("$path unavailable", text != null)
            assertFalse("$path still reads flatHome", text!!.contains("flatHome"))
            assertFalse("$path still writes flat_home", text.contains("\"flat_home\""))
            assertFalse("$path still renders 扁平化 switch", text.contains("title = \"界面扁平化\""))
        }
    }

    @Test
    fun settingsRenderTranslucentSwitchAndNoDefaultWallpaperEntry() {
        for (path in listOf(SETTINGS_MIUIX, SETTINGS_MATERIAL)) {
            val text = source(path)
            assumeTrue("$path unavailable", text != null)
            assertTrue("$path missing shared appearance settings", text!!.contains("AppearanceSettingsBody(uiState, actions)"))
            assertFalse("$path still offers 恢复默认背景", text.contains("恢复默认背景"))
        }
        val wallpaper = source(THEME_SETTINGS)
        assumeTrue("$THEME_SETTINGS unavailable", wallpaper != null)
        assertTrue(wallpaper!!.contains("ThemeSwitch(stringResource(R.string.ui_d_translucent),repo.uiTranslucent"))
        assertTrue(wallpaper.contains("ThemeSlider(stringResource(R.string.theme_interface_opacity)"))
        assertTrue(wallpaper.contains("operations.edit(mapOf(\"backgroundOpacity\" to it))"))
        assertFalse(wallpaper.contains("恢复默认背景"))
    }

    private companion object {
        const val MAIN_ACTIVITY = "src/main/java/com/maplesu/core/ui/MainActivity.kt"
        const val WALLPAPER_STORE = "src/main/java/com/maplesu/core/ui/util/WallpaperStore.kt"
        const val SETTINGS_MIUIX = "src/main/java/com/maplesu/core/ui/screen/settings/SettingsMiuix.kt"
        const val SETTINGS_MATERIAL = "src/main/java/com/maplesu/core/ui/screen/settings/SettingsMaterial.kt"
        const val THEME_SETTINGS = "src/main/java/com/maplesu/core/ui/screen/settings/ThemeSettingsScreens.kt"
    }
}
