package com.maplesu.core.ui.navigation3

import android.content.SharedPreferences
import android.graphics.Bitmap
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.test.platform.app.InstrumentationRegistry
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.maplesu.core.data.repository.SettingsRepositoryImpl
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.screen.settings.AppearanceImagesScreen
import com.maplesu.core.ui.theme.AppSettings
import com.maplesu.core.ui.theme.ColorMode
import com.maplesu.core.ui.theme.KernelSUTheme
import com.maplesu.core.ui.util.AppearancePreferences
import com.maplesu.core.ui.util.WallpaperHost
import org.junit.*
import org.junit.Assert.*
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import top.yukonga.miuix.kmp.nav.transition.NavSwipeDirection
import top.yukonga.miuix.kmp.theme.MiuixTheme
import java.io.File
import kotlin.math.abs

/** Native rendering: a transparent destination must match the same page with no parent beneath it. */
@RunWith(Parameterized::class)
class TransparentNavigationTest(private val skin: UiMode) {
    @get:Rule val compose = createComposeRule()
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val repo = SettingsRepositoryImpl()
    private lateinit var prefs: SharedPreferences
    private lateinit var original: Map<String, *>
    private lateinit var wallpaper: File
    private lateinit var navigator: Navigator

    @Before fun prepare() {
        prefs = AppearancePreferences.prefs(context)
        original = prefs.all.toMap()
        wallpaper = File(context.cacheDir, "transparent-navigation-wallpaper.png")
        val bitmap = Bitmap.createBitmap(32, 32, Bitmap.Config.ARGB_8888)
        bitmap.eraseColor(android.graphics.Color.rgb(24, 110, 220))
        wallpaper.outputStream().use { assertTrue(bitmap.compress(Bitmap.CompressFormat.PNG, 100, it)) }
        bitmap.recycle()
        repo.wallpaperPath = wallpaper.absolutePath
        repo.wallpaperKind = "image"
        repo.wallpaperLandKind = "none"
        repo.wallpaperDim = 0f
        repo.wallpaperBlur = 0f
        repo.uiTranslucent = true
        repo.uiTranslucentAlpha = 0.2f
        repo.uiMode = skin.value
    }

    @After fun restore() {
        val editor = prefs.edit().clear()
        original.forEach { (key, value) -> when (value) {
            is Boolean -> editor.putBoolean(key, value)
            is Int -> editor.putInt(key, value)
            is Float -> editor.putFloat(key, value)
            is Long -> editor.putLong(key, value)
            is String -> editor.putString(key, value)
            is Set<*> -> editor.putStringSet(key, value.filterIsInstance<String>().toSet())
        } }
        assertTrue(editor.commit())
        wallpaper.delete()
    }

    @Test fun transparentPagesShowWallpaperWithoutParentsAndRetainBackState() {
        render()
        val reference = capture("reference")
        assertWallpaperVisible(reference)
        compose.runOnIdle { navigator.replaceAll(listOf(Route.Main)) }
        compose.onNodeWithTag("parentCount").performClick()
        compose.onNodeWithText("Parent 1").assertExists()
        compose.runOnIdle { navigator.push(Route.Appearance) }
        assertSamePixels(reference, capture("child"))
        compose.runOnIdle { navigator.push(Route.ColorPalette) }
        assertSamePixels(reference, capture("grandchild"))
        compose.runOnIdle { navigator.pop() }
        assertSamePixels(reference, capture("back-to-child"))

        // Change transparency while a child is open; neither theme change may expose its parent.
        compose.runOnIdle { repo.uiTranslucent = false }
        val opaque = capture("opaque")
        assertTrue("Disabling transparency hides wallpaper", blue(opaque) - red(opaque) < 60)
        compose.runOnIdle { repo.uiTranslucent = true }
        assertSamePixels(reference, capture("transparent-again"))

        compose.onNodeWithTag("navigation").performTouchInput {
            swipe(start = centerLeft + androidx.compose.ui.geometry.Offset(20f, 0f),
                end = centerRight - androidx.compose.ui.geometry.Offset(20f, 0f), durationMillis = 450)
        }
        compose.waitForIdle()
        compose.runOnIdle { assertEquals(Route.Main, navigator.current()) }
        compose.onNodeWithText("Parent 1").assertExists()
    }

    @Test fun actualImageSettingsRenderLikeAnIsolatedPageAfterTwoPushes() {
        render(actualSettings = true)
        compose.onNodeWithText(context.getString(com.maplesu.core.R.string.ui_d_translucent)).assertExists()
        val reference = capture("settings-isolated")
        compose.runOnIdle {
            navigator.replaceAll(listOf(Route.Main))
        }
        compose.waitForIdle()
        compose.runOnIdle { navigator.push(Route.Appearance) }
        compose.waitForIdle()
        compose.runOnIdle { navigator.push(Route.AppearanceImages) }
        compose.waitForIdle()
        assertSamePixels(reference, capture("settings-stacked"))
        compose.runOnIdle { navigator.pop() }
        compose.onNodeWithText("Theme page").assertExists()
    }

    private fun render(actualSettings: Boolean = false) {
        compose.setContent {
            navigator = rememberNavigator(if (actualSettings) Route.AppearanceImages else Route.Appearance)
            CompositionLocalProvider(LocalUiMode provides skin, LocalNavigator provides navigator) {
                KernelSUTheme(AppSettings(ColorMode.LIGHT, 0xff6750a4.toInt(),
                    PaletteStyle.TonalSpot, ColorSpec.SpecVersion.SPEC_2025), skin) {
                    Box(Modifier.fillMaxSize().testTag("navigation")) {
                        WallpaperHost {
                            // Same outer scaffold as MainActivity, without starting the root backend.
                            val navigation = @Composable {
                                AppNavDisplay(backStack = navigator.backStack, onBack = navigator::pop) {
                                    entry<Route.Main>(swipeDismiss = NavSwipeDirection.LeftToRight) {
                                        var count by rememberSaveable { mutableIntStateOf(0) }
                                        Box(Modifier.fillMaxSize().background(Color.Red)) {
                                            Text("Parent $count", Modifier.testTag("parentCount").clickable { count++ })
                                        }
                                    }
                                    entry<Route.Appearance>(swipeDismiss = NavSwipeDirection.LeftToRight) {
                                        Box(Modifier.fillMaxSize().background(background())) {
                                            if (actualSettings) Text("Theme page")
                                        }
                                    }
                                    entry<Route.ColorPalette>(swipeDismiss = NavSwipeDirection.LeftToRight) {
                                        Box(Modifier.fillMaxSize().background(background()))
                                    }
                                    entry<Route.AppearanceImages>(swipeDismiss = NavSwipeDirection.LeftToRight) {
                                        AppearanceImagesScreen()
                                    }
                                }
                            }
                            if (skin == UiMode.Material) {
                                androidx.compose.material3.Scaffold(containerColor = background()) { navigation() }
                            } else {
                                top.yukonga.miuix.kmp.basic.Scaffold { navigation() }
                            }
                        }
                    }
                }
            }
        }
        compose.waitForIdle()
        // Wallpaper decode is asynchronous, independent of the Compose clock.
        compose.waitUntil(5_000) {
            val bitmap = compose.onNodeWithTag("navigation").captureToImage().asAndroidBitmap()
            blue(bitmap) - red(bitmap) > 40
        }
    }

    @Composable private fun background(): Color = when (skin) {
        UiMode.Material -> MaterialTheme.colorScheme.background
        UiMode.Miuix -> MiuixTheme.colorScheme.background
    }

    private fun capture(name: String): Bitmap {
        compose.waitForIdle()
        val bitmap = compose.onNodeWithTag("navigation").captureToImage().asAndroidBitmap()
        val directory = File(context.getExternalFilesDir(null), "transparent-navigation").apply { mkdirs() }
        File(directory, "${skin.name}-$name.png").outputStream().use {
            assertTrue(bitmap.compress(Bitmap.CompressFormat.PNG, 100, it))
        }
        return bitmap
    }

    private fun assertSamePixels(expected: Bitmap, actual: Bitmap) {
        for (x in listOf(0.2f, 0.5f, 0.8f)) for (y in listOf(0.3f, 0.6f, 0.85f)) {
            val a = expected.getPixel((expected.width * x).toInt(), (expected.height * y).toInt())
            val b = actual.getPixel((actual.width * x).toInt(), (actual.height * y).toInt())
            for (shift in listOf(0, 8, 16)) assertTrue(
                "Parent page leaked at ($x, $y): expected ${a.toUInt().toString(16)}, actual ${b.toUInt().toString(16)}",
                abs(((a shr shift) and 255) - ((b shr shift) and 255)) <= 4)
        }
    }

    private fun red(bitmap: Bitmap) = android.graphics.Color.red(bitmap.getPixel(bitmap.width / 2, bitmap.height * 3 / 4))
    private fun blue(bitmap: Bitmap) = android.graphics.Color.blue(bitmap.getPixel(bitmap.width / 2, bitmap.height * 3 / 4))
    private fun assertWallpaperVisible(bitmap: Bitmap) {
        assertTrue("The blue wallpaper remains visible", blue(bitmap) - red(bitmap) > 60)
    }

    companion object {
        @JvmStatic @Parameterized.Parameters(name = "{0}")
        fun cases(): Collection<Array<Any>> = UiMode.entries.map { arrayOf<Any>(it) }
    }
}
