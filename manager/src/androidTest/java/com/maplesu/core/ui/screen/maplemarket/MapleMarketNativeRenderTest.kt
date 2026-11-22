package com.maplesu.core.ui.screen.maplemarket

import android.content.res.Configuration
import android.graphics.Bitmap
import android.view.KeyEvent
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.core.graphics.ColorUtils
import androidx.test.platform.app.InstrumentationRegistry
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.theme.*
import dev.maplesu.manager.market.MarketModule
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import top.yukonga.miuix.kmp.theme.MiuixTheme
import java.io.File

/** PresentationTestRunner only: production composables with inert actions and no backend. */
@OptIn(ExperimentalTestApi::class)
@RunWith(Parameterized::class)
class MapleMarketNativeRenderTest(private val skin: UiMode, private val dark: Boolean, private val fontScale: Float) {
    @get:Rule val compose = createComposeRule()
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val selected = mutableStateOf<MarketModule?>(null)
    private var surfaceArgb = 0
    private var textArgb = 0
    private var selectedLocal = 0
    private var selectedMarket = 0
    private val viewportTag = "maple-market-viewport"

    @Test fun listAndDetailRemainReadableAtNarrowWidth() {
        render()
        compose.onNodeWithText(module.name).assertIsDisplayed().performClick()
        compose.onNodeWithText(context.getString(R.string.maple_market_update)).performScrollTo().assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.maple_market_open_project)).performScrollTo().assertIsDisplayed()
        assertTrue("theme text contrast", ColorUtils.calculateContrast(textArgb, surfaceArgb) >= 4.5)
        assertEquals("light/dark palette", dark, ColorUtils.calculateLuminance(surfaceArgb) < .3)
        capture("detail")
        compose.onNodeWithText(context.getString(R.string.maple_market_changelog)).performScrollTo().performClick()
        compose.onNodeWithText("Release 2.1.0\nImproved compatibility and layout.").assertExists()
    }

    @Test fun searchMatchesAuthorAndClearsEmptyResults() {
        render()
        compose.onNodeWithText(module.name).assertIsDisplayed()
        capture("list")
        compose.onNode(hasSetTextAction()).performTextInput("fixture author")
        compose.onNodeWithText(module.name).assertIsDisplayed()
        compose.onNode(hasSetTextAction()).performTextClearance()
        compose.onNode(hasSetTextAction()).performTextInput("missing result")
        compose.onNodeWithText(context.getString(R.string.maple_market_no_results)).assertIsDisplayed()
        compose.onNodeWithText(module.name).assertDoesNotExist()
    }

    @Test fun ultraInstallMenuClosesOnBackAndSelection() {
        render(menu = true)
        val open = "fixture-install"
        val close = context.getString(R.string.maple_market_close_menu)
        val market = context.getString(R.string.maple_market_from_repository)
        val local = context.getString(R.string.maple_market_local_file)
        compose.onNodeWithContentDescription(open).performClick()
        compose.onNodeWithText(market).assertIsDisplayed()
        compose.onNodeWithText(local).assertIsDisplayed()
        capture("fab-expanded")
        instrumentation.sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
        compose.waitForIdle()
        compose.onNodeWithText(market).assertDoesNotExist()
        compose.onNodeWithContentDescription(open).performClick()
        compose.onNodeWithText(local).performClick()
        compose.onNodeWithText(local).assertDoesNotExist()
        assertEquals(1, selectedLocal)
        compose.onNodeWithContentDescription(open).performClick()
        compose.onNodeWithText(market).performClick()
        compose.onNodeWithContentDescription(close).assertDoesNotExist()
        assertEquals(1, selectedMarket)
    }

    private fun render(menu: Boolean = false) {
        compose.setContent {
            val density = LocalDensity.current
            val config = Configuration(LocalConfiguration.current).apply {
                screenWidthDp = 320
                smallestScreenWidthDp = 320
                this.fontScale = this@MapleMarketNativeRenderTest.fontScale
            }
            CompositionLocalProvider(
                LocalUiMode provides skin,
                LocalColorMode provides if (dark) ColorMode.DARK.value else ColorMode.LIGHT.value,
                LocalEnableBlur provides false,
                LocalConfiguration provides config,
                LocalDensity provides Density(density.density, fontScale),
            ) {
                KernelSUTheme(AppSettings(if (dark) ColorMode.DARK else ColorMode.LIGHT,
                    0xff6750a4.toInt(), PaletteStyle.TonalSpot, ColorSpec.SpecVersion.SPEC_2025), skin) {
                    val surface = if (skin == UiMode.Miuix) MiuixTheme.colorScheme.surface else MaterialTheme.colorScheme.surface
                    val text = if (skin == UiMode.Miuix) MiuixTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurface
                    SideEffect {
                        surfaceArgb = surface.toArgb()
                        textArgb = text.toArgb()
                    }
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
                        Box(Modifier.width(320.dp).fillMaxHeight().testTag(viewportTag)) {
                            MarketPage(selected.value?.name ?: context.getString(R.string.maple_market_title),
                                onBack = { selected.value = null }, onRefresh = {}, onSource = {}) { padding ->
                                Box(Modifier.fillMaxSize().padding(padding)) {
                                    val current = selected.value
                                    if (current == null) {
                                        var query by remember { mutableStateOf("") }
                                        MarketModuleList(MapleMarketUiState(modules = listOf(module), installedVersions = mapOf(module.id to "2.0.0")),
                                            query, { query = it }, {}, { selected.value = it }, {})
                                    } else MarketDetail(current, "Release 2.1.0\nImproved compatibility and layout.", "2.0.0", null, null, null, {}, {}, {})
                                    if (menu) Box(Modifier.align(Alignment.BottomEnd).padding(16.dp)) {
                                        MapleMarketInstallMenu(true, { selectedMarket++ }, { selectedLocal++ }) { rotation, expanded, click ->
                                            val label = if (expanded) context.getString(R.string.maple_market_close_menu) else "fixture-install"
                                            when (skin) {
                                                UiMode.Miuix -> top.yukonga.miuix.kmp.basic.FloatingActionButton(onClick = click) {
                                                    top.yukonga.miuix.kmp.basic.Icon(Icons.Rounded.Add, label, modifier = Modifier.rotate(rotation))
                                                }
                                                UiMode.Material -> androidx.compose.material3.FloatingActionButton(onClick = click) {
                                                    androidx.compose.material3.Icon(Icons.Rounded.Add, label, modifier = Modifier.rotate(rotation))
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        compose.waitForIdle()
    }

    private fun capture(scene: String) {
        val directory = File(context.getExternalFilesDir(null), "maple-market-native-render/${skin.name.lowercase()}_${if (dark) "dark" else "light"}_${fontScale}x").apply { mkdirs() }
        val bitmap = compose.onNodeWithTag(viewportTag).captureToImage().asAndroidBitmap()
        File(directory, "$scene.png").outputStream().use { assertTrue(bitmap.compress(Bitmap.CompressFormat.PNG, 100, it)) }
        File(directory, "$scene.json").writeText(JSONObject().put("skin", skin.name).put("dark", dark).put("fontScale", fontScale)
            .put("surfaceArgb", surfaceArgb).put("textArgb", textArgb).toString(2))
    }

    private val module = MarketModule(
        id = "native-render-fixture", name = "MapleSU Extended Native Module Fixture", englishName = "Native fixture",
        version = "2.1.0", description = "A module fixture with long metadata to verify narrow layouts and theme colors.",
        author = "Fixture author · MapleSU contributors", type = "MAPLESU", updatedAt = "2026-11-01",
        sourceUrl = "https://fixture.invalid/project", downloadAlert = "", compatibilityModes = listOf("MapleSU_Ultra"),
        sha256 = "a".repeat(64), size = 1024 * 1024, downloadUrls = listOf("https://fixture.invalid/module.zip"), changelogUrl = "", installable = true,
    )

    companion object {
        @JvmStatic @Parameterized.Parameters(name = "{0}-{1}-320dp-font{2}")
        fun matrix(): Collection<Array<Any>> = UiMode.entries.flatMap { skin ->
            listOf(false, true).flatMap { dark -> listOf(1f, 1.8f).map { scale -> arrayOf<Any>(skin, dark, scale) } }
        }
    }
}
