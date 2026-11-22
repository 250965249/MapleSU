package com.maplesu.core.ui.screen.home

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.getUnclippedBoundsInRoot
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.test.platform.app.InstrumentationRegistry
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.theme.AppSettings
import com.maplesu.core.ui.theme.ColorMode
import com.maplesu.core.ui.theme.KernelSUTheme
import com.maplesu.core.ui.theme.LocalColorMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import java.io.File
import android.graphics.Bitmap

/** Production component only; never starts an SDK or changes a device protection state. */
@RunWith(Parameterized::class)
class HomeSafeModeBannerNativeTest(private val skin: UiMode, private val dark: Boolean, private val scale: Float) {
    @get:Rule val compose = createComposeRule()

    @Test fun narrowBannerKeepsItsTitleAndRecoveryActionVisible() {
        var clicks = 0
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        compose.setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(LocalUiMode provides skin,
                LocalDensity provides Density(density.density, scale),
                LocalColorMode provides if (dark) ColorMode.DARK.value else ColorMode.LIGHT.value) {
                KernelSUTheme(AppSettings(if (dark) ColorMode.DARK else ColorMode.LIGHT,
                    0xff6750a4.toInt(), PaletteStyle.TonalSpot, ColorSpec.SpecVersion.SPEC_2025), skin) {
                    Box(Modifier.width(320.dp).testTag("banner")) {
                        HomeSafeModeBanner(onManageModules = { clicks++ })
                    }
                }
            }
        }
        compose.onNodeWithText(context.getString(R.string.home_safe_mode_banner_title)).assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.home_safe_mode_banner_summary)).assertIsDisplayed()
        val action = compose.onNodeWithText(context.getString(R.string.home_safe_mode_manage_modules))
        action.assertIsDisplayed().performClick()
        compose.runOnIdle { assertEquals(1, clicks) }
        val bounds = action.getUnclippedBoundsInRoot()
        assertTrue(bounds.bottom - bounds.top >= 48.dp)
        val directory = File(context.getExternalFilesDir(null), "ultra-safe-mode-ui").apply { mkdirs() }
        val bitmap = compose.onNodeWithTag("banner").captureToImage().asAndroidBitmap()
        File(directory, "${skin.name}-${dark}-${scale}.png").outputStream().use {
            assertTrue(bitmap.compress(Bitmap.CompressFormat.PNG, 100, it))
        }
    }

    companion object {
        @JvmStatic @Parameterized.Parameters(name = "{0}-dark{1}-font{2}")
        fun matrix(): Collection<Array<Any>> = UiMode.entries.flatMap { skin ->
            listOf(false, true).flatMap { dark -> listOf(1f, 1.8f).map { scale -> arrayOf<Any>(skin, dark, scale) } }
        }
    }
}
