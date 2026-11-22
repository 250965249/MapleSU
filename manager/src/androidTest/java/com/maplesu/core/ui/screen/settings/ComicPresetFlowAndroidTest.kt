package com.maplesu.core.ui.screen.settings

import android.content.SharedPreferences
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.height
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.test.platform.app.InstrumentationRegistry
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.maplesu.core.R
import com.maplesu.core.data.repository.SettingsRepositoryImpl
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.navigation3.LocalNavigator
import com.maplesu.core.ui.navigation3.Route
import com.maplesu.core.ui.navigation3.rememberNavigator
import com.maplesu.core.ui.theme.AppSettings
import com.maplesu.core.ui.theme.ColorMode
import com.maplesu.core.ui.theme.KernelSUTheme
import com.maplesu.core.ui.util.AppearancePreferences
import com.maplesu.core.ui.util.AppearancePrefsPolicy as Policy
import com.maplesu.core.ui.util.StatusDecoration
import org.junit.*
import org.junit.Assert.*
import java.io.File

class ComicPresetFlowAndroidTest {
    @get:Rule val compose = createComposeRule()
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var prefs: SharedPreferences
    private lateinit var original: Map<String, *>
    private var originalImage: ByteArray? = null
    private val repo = SettingsRepositoryImpl()

    @Before fun backup() {
        prefs = AppearancePreferences.prefs(context)
        original = prefs.all.toMap()
        originalImage = StatusDecoration.file(context).takeIf { it.isFile }?.readBytes()
        repo.uiMode = UiMode.Miuix.value
    }

    @After fun restore() {
        val image = StatusDecoration.file(context)
        originalImage?.let { image.writeBytes(it) } ?: image.delete()
        val editor = prefs.edit().clear()
        original.forEach { (key, value) -> when (value) {
            is Boolean -> editor.putBoolean(key, value)
            is Int -> editor.putInt(key, value)
            is Float -> editor.putFloat(key, value)
            is Long -> editor.putLong(key, value)
            is String -> editor.putString(key, value)
        } }
        assertTrue(editor.commit())
    }

    @Test fun plainPresetPersistsAcrossSkinChangesAndSizeIsIndependentOfArtwork() {
        repo.applyComicPreset(false)
        assertFalse(repo.homeLargeCard)
        assertFalse(repo.snowEnabled)
        assertFalse(repo.trollRainEnabled)
        assertFalse(repo.enableBlur)
        assertFalse(repo.enableFloatingBottomBar)
        assertFalse(repo.enableFloatingBottomBarBlur)
        repo.uiMode = UiMode.Material.value
        repo.uiMode = UiMode.Miuix.value
        assertFalse(repo.enableFloatingBottomBar)
        assertFalse(repo.enableBlur)
        repo.homeLargeCard = true
        assertEquals(Policy.DECORATION_CHECK, prefs.getString(Policy.DECORATION_SOURCE, null))
        assertFalse(repo.snowEnabled)
        val wallpaper = repo.wallpaperPath
        val translucent = repo.uiTranslucent
        repo.applyComicPreset(true)
        assertTrue(repo.homeLargeCard)
        assertTrue(repo.snowEnabled)
        assertFalse(repo.trollRainEnabled)
        assertTrue(repo.enableBlur)
        assertTrue(repo.enableFloatingBottomBar)
        assertTrue(repo.enableFloatingBottomBarBlur)
        assertEquals(Policy.DECORATION_COMIC, prefs.getString(Policy.DECORATION_SOURCE, null))
        assertEquals(wallpaper, repo.wallpaperPath)
        assertEquals(translucent, repo.uiTranslucent)
    }

    @Test fun trollRainDefaultsOffAndKeepsAnExplicitChoice() {
        prefs.edit().remove("troll_rain_enabled").commit()
        assertFalse(repo.trollRainEnabled)
        repo.trollRainEnabled = true
        assertTrue(repo.trollRainEnabled)
        repo.applyComicPreset(true)
        assertFalse(repo.trollRainEnabled)
    }

    @Test fun miuixImagesSelectArtworkAndWallpaperOwnsTransparency() = imagesPage(UiMode.Miuix)

    @Test fun materialImagesSelectArtworkAndWallpaperOwnsTransparency() = imagesPage(UiMode.Material)

    private fun imagesPage(skin: UiMode) {
        repo.uiMode = skin.value
        repo.applyComicPreset(true)
        repo.uiTranslucent = false
        val wallpaperPage = mutableStateOf(false)
        render(skin) {
            val navigator = rememberNavigator(Route.Main)
            CompositionLocalProvider(LocalNavigator provides navigator) {
                ThemeOperationsHost { if (wallpaperPage.value) WallpaperScreen() else AppearanceImagesScreen() }
            }
        }
        compose.waitUntil(5_000) {
            compose.onAllNodesWithText(context.getString(R.string.ui_d_decoration_comic)).fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithText(context.getString(R.string.ui_d_decoration_comic)).performClick()
        compose.waitUntil(5_000) {
            compose.onAllNodesWithText(context.getString(R.string.ui_d_decoration_check)).fetchSemanticsNodes().isNotEmpty()
        }
        compose.onAllNodesWithText(context.getString(R.string.ui_d_decoration_check)).onLast().performClick()
        compose.waitUntil(5_000) { prefs.getString(Policy.DECORATION_SOURCE, null) == Policy.DECORATION_CHECK }
        compose.onNodeWithText(context.getString(R.string.ui_d_decoration_check)).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.ui_d_translucent)).assertDoesNotExist()
        compose.runOnIdle { wallpaperPage.value=true }
        compose.onNode(hasScrollToNodeAction()).performScrollToNode(hasText(context.getString(R.string.ui_d_translucent)))
        compose.onNodeWithText(context.getString(R.string.ui_d_translucent)).performClick()
        compose.waitUntil(5_000) { repo.uiTranslucent }
        assertTrue(repo.homeLargeCard)
        val directory = File(context.getExternalFilesDir(null), "comic-preset-ui").apply { mkdirs() }
        File(directory, "images-${skin.name}.png").outputStream().use {
            assertTrue(compose.onRoot().captureToImage().asAndroidBitmap().compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it))
        }
    }

    @Test fun restorePresetRequiresConfirmationAndCanBeAppliedAgain() {
        repo.applyComicPreset(false)
        var applies = 0
        render { ThemeResetPreference { comic -> repo.applyComicPreset(comic); applies++ } }
        val title = context.getString(R.string.theme_reset)
        compose.onNodeWithText(title).performClick()
        compose.onNodeWithText(context.getString(R.string.theme_reset_question)).assertIsDisplayed()
        compose.runOnIdle { assertFalse(repo.homeLargeCard); assertEquals(0, applies) }
        compose.onNodeWithText(context.getString(R.string.theme_cancel)).performClick()
        compose.runOnIdle { assertFalse(repo.homeLargeCard); assertEquals(0, applies) }
        compose.onNodeWithText(title).performClick()
        compose.onNodeWithText(context.getString(R.string.theme_reset_comic)).performClick()
        compose.onNodeWithText(context.getString(R.string.theme_reset_confirm)).performClick()
        compose.runOnIdle { assertTrue(repo.homeLargeCard); assertEquals(1, applies) }
        compose.onNodeWithText(title).performClick()
        compose.onNodeWithText(context.getString(R.string.theme_reset_confirm)).performClick()
        compose.runOnIdle { assertEquals(2, applies) }
        assertFalse(repo.homeLargeCard)
    }

    @Test fun introPresetStartsEnabledAndCanBeDisabledBeforeContinuing() {
        val comic = mutableStateOf(true)
        var finishes = 0
        render {
            Box(Modifier.height(640.dp)) {
                AppearanceIntroScreen(UiMode.Miuix, {}, { finishes++ }, comic.value, { comic.value = it })
            }
        }
        compose.onNodeWithText(context.getString(R.string.ui_d_comic_intro)).performScrollTo().performClick()
        compose.runOnIdle { assertFalse(comic.value); assertEquals(0, finishes) }
        compose.onNodeWithText(context.getString(R.string.ui_d_comic_plain_style_summary)).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.appearance_intro_start)).performScrollTo().performClick()
        compose.runOnIdle { assertEquals(1, finishes) }
        val directory = File(context.getExternalFilesDir(null), "comic-preset-ui").apply { mkdirs() }
        File(directory, "intro-plain.png").outputStream().use {
            assertTrue(compose.onRoot().captureToImage().asAndroidBitmap().compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it))
        }
    }

    private fun render(skin: UiMode = UiMode.Miuix, content: @androidx.compose.runtime.Composable () -> Unit) {
        compose.setContent {
            CompositionLocalProvider(LocalUiMode provides skin,
                LocalNavigator provides rememberNavigator(Route.Main)) {
                KernelSUTheme(AppSettings(ColorMode.LIGHT, 0xff6750a4.toInt(), PaletteStyle.TonalSpot,
                    ColorSpec.SpecVersion.SPEC_2025), skin, content = content)
            }
        }
    }
}
