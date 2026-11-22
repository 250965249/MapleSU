package dev.maplesu.manager.jailbreak

import android.content.res.Configuration
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.getUnclippedBoundsInRoot
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.text.TextLayoutResult
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
import java.util.Locale
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

@RunWith(Parameterized::class)
class JailbreakLogPanelNativeTest(private val skin: UiMode, private val dark: Boolean, private val scale: Float) {
    @get:Rule val compose = createComposeRule()

    @Test fun exportAndShareStaySingleLineAtNarrowWidthsAndLargeFonts() {
        val base = InstrumentationRegistry.getInstrumentation().targetContext
        val context = base.createConfigurationContext(Configuration(base.resources.configuration).apply {
            setLocale(Locale.SIMPLIFIED_CHINESE)
        })
        var exports = 0
        var shares = 0
        var copies = 0
        compose.setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(LocalContext provides context, LocalUiMode provides skin,
                LocalDensity provides Density(density.density, scale),
                LocalColorMode provides if (dark) ColorMode.DARK.value else ColorMode.LIGHT.value) {
                KernelSUTheme(AppSettings(if (dark) ColorMode.DARK else ColorMode.LIGHT,
                    0xff6750a4.toInt(), PaletteStyle.TonalSpot, ColorSpec.SpecVersion.SPEC_2025), skin) {
                    Box(Modifier.width(320.dp)) {
                        JailbreakLogPanel(JailbreakSelectionState(running = true),
                            JailbreakLogReader.Snapshot(lines = listOf(
                                JailbreakLogReader.Line("dirtyfrag-native.log", "[*] detailed output", JailbreakLogReader.Tone.STEP))),
                            busy = false, onCopy = { copies++ }, onExport = { exports++ },
                            onShare = { shares++ }, onDismiss = {}, onCancel = {})
                    }
                }
            }
        }
        listOf(R.string.maplesu_jailbreak_export_logs, R.string.maplesu_jailbreak_share_logs).forEach { id ->
            val label = context.getString(id)
            compose.onNodeWithText(label).assertIsDisplayed().performClick()
            val layouts = mutableListOf<TextLayoutResult>()
            compose.onNodeWithText(label, useUnmergedTree = true)
                .performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(layouts) }
            assertEquals(1, layouts.single().lineCount)
            assertFalse(layouts.single().hasVisualOverflow)
            val bounds = compose.onNodeWithText(label).getUnclippedBoundsInRoot()
            assertTrue(bounds.bottom - bounds.top >= 48.dp)
        }
        compose.onNodeWithContentDescription(context.getString(R.string.maplesu_jailbreak_copy_logs)).performClick()
        compose.runOnIdle {
            assertEquals(1, exports)
            assertEquals(1, shares)
            assertEquals(1, copies)
        }
    }

    companion object {
        @JvmStatic @Parameterized.Parameters(name = "{0}-dark{1}-font{2}")
        fun matrix(): Collection<Array<Any>> = UiMode.entries.flatMap { skin ->
            listOf(false, true).flatMap { dark -> listOf(1f, 1.8f).map { scale -> arrayOf<Any>(skin, dark, scale) } }
        }
    }
}
