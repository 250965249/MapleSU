package com.maplesu.core.theme

import android.graphics.Bitmap
import android.net.Uri
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toPixelMap
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.unit.dp
import androidx.test.platform.app.InstrumentationRegistry
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.maplesu.core.ui.LocalMainPagerState
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.bottombar.*
import com.maplesu.core.ui.navigation3.LocalNavigator
import com.maplesu.core.ui.navigation3.Route
import com.maplesu.core.ui.navigation3.rememberNavigator
import com.maplesu.core.ui.theme.*
import com.maplesu.core.ui.util.NavIcons
import com.maplesu.core.ui.util.WallpaperHost
import com.maplesu.core.ui.util.rememberBlurBackdrop
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TestName
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.blur.rememberLayerBackdrop
import java.io.File

/** Production navigation and wallpaper host, without the root-dependent main-page bootstrap. */
@RunWith(Parameterized::class)
class ThemeNavigationDeviceTest(private val skin: UiMode, private val dark: Boolean) {
    @get:Rule val compose = createComposeRule()
    @get:Rule val testName = TestName()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val repository get() = ThemeRepository(context)
    private val form = mutableStateOf("docked")
    private lateinit var pager: MainPagerState
    private var style: ThemeWallpaperStyle? = null
    private val forms get() = if (skin == UiMode.Miuix)
        listOf("docked", "docked-blur", "floating", "floating-blur", "flat", "rail")
        else listOf("docked", "rail")

    @Before fun reset() {
        val arguments = InstrumentationRegistry.getArguments()
        arguments.getString("themeUiFocus")?.let { assumeTrue(testName.methodName.substringBefore('[') in it.split(',')) }
        arguments.getString("themeUiMode")?.let { assumeTrue(it == "${skin.name}-${if (dark) "dark" else "light"}") }
        assertTrue(context.packageName.endsWith(".themetest"))
        runBlocking { repository.reset() }
        com.maplesu.core.ui.util.AppearancePreferences.prefs(context).edit()
            .putBoolean("nav_icon_circle", false).putBoolean("nav_rail_expanded", false)
            .putFloat("wallpaper_dim", 0f).putFloat("wallpaper_blur", 0f).commit()
    }

    @Test fun iconsRefreshWhenOnlyNavigationAssetsChange() {
        val plain = fixture("plain", icons = false, background = false)
        val red = fixture("red", background = false)
        val blue = fixture("blue", color = android.graphics.Color.BLUE, background = false)
        apply(plain)
        render()
        apply(red)
        waitForIcon(Color.Red)
        capture("asset-only-red")
        apply(blue)
        waitForIcon(Color.Blue)
        capture("asset-only-blue")
        apply(plain)
        compose.waitForIdle()
        assertNull(NavIcons.currentFile(context, "home"))
        compose.waitUntil(10_000) { !iconHasColor(Color.Blue) }
        capture("asset-only-default")
    }

    @Test fun transparentAssetsAndWallpaperWorkAcrossNativeNavigationForms() {
        apply(fixture("transparent"))
        render()
        compose.waitUntil(10_000) { style != null }
        for (current in forms) {
            compose.runOnIdle { form.value = current }
            waitForIcon(Color.Red)
            val pixels = NavIcons.load(context, "home")!!.toPixelMap()
            assertEquals(0f, pixels[0, 0].alpha)
            assertEquals(1f, pixels[pixels.width / 2, pixels.height / 2].alpha)
            for (index in BottomBarDestination.entries.indices) {
                val label = context.getString(BottomBarDestination.entries[index].label)
                compose.onAllNodesWithContentDescription(label).onFirst()
                    .assertIsDisplayed().performClick()
                try {
                    compose.waitUntil(5_000) { pager.pagerState.currentPage == index && !pager.isNavigating }
                } catch (error: Throwable) {
                    capture("$current-click-$index-failure")
                    throw AssertionError("$current index=$index current=${pager.pagerState.currentPage} " +
                        "selected=${pager.selectedPage} navigating=${pager.isNavigating}", error)
                }
                assertEquals(index, pager.selectedPage)
            }
            for (opacity in listOf(0.0, 0.5, 1.0)) {
                runBlocking { repository.edit(mapOf("backgroundOpacity" to opacity)) }
                compose.waitUntil(10_000) { style?.opacity == opacity.toFloat() }
                capture("$current-opacity-$opacity")
                if (current != "flat" && opacity != .5) assertWallpaperMaterial(opacity)
            }
            runBlocking { repository.edit(mapOf("backgroundOpacity" to 0.0)) }
        }
        apply(fixture("missing", icons = false))
        compose.waitForIdle()
        assertTrue(NavIcons.keys.none { NavIcons.has(context, it) })
        compose.runOnIdle { form.value = "docked" }
        capture("wallpaper-default-icons")
        runBlocking { repository.reset() }
        compose.waitUntil(10_000) { style == null }
        capture("restored")
    }

    @Test fun originalFinaPackagesCoverBottomBarsAndSideRails() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("themeRealAppearance") == "true")
        val inputs = File(context.getExternalFilesDir(null), "real-theme-inputs")
        val packages = listOf("store-live", "store-card-live").map { File(inputs, "$it.fpt") }
        packages.forEach { assertTrue(it.isFile) }
        apply(packages.first())
        render()
        for (input in packages) {
            apply(input)
            compose.waitUntil(10_000) { style != null }
            for (current in forms.filter { it in listOf("docked", "floating", "floating-blur", "rail") }) {
                compose.runOnIdle { form.value = current }
                try {
                    val label = context.getString(BottomBarDestination.Home.label)
                    compose.onAllNodes(hasContentDescription(label) or hasText(label),
                        useUnmergedTree = true).onFirst().assertIsDisplayed()
                } catch (error: Throwable) {
                    capture("${input.nameWithoutExtension}-$current-failure")
                    throw AssertionError(compose.onRoot(useUnmergedTree = true).printToString(), error)
                }
                capture("${input.nameWithoutExtension}-$current")
            }
        }
    }

    private fun apply(input: File) = runBlocking { repository.apply(repository.prepare(Uri.fromFile(input))) }

    private fun fixture(name: String, color: Int = android.graphics.Color.RED,
        icons: Boolean = true, background: Boolean = true): File {
        val directory = File(context.cacheDir, "navigation-$name").apply { mkdirs() }
        val image = File(directory, "background.png")
        val bitmap = Bitmap.createBitmap(64, 64, Bitmap.Config.ARGB_8888)
        bitmap.eraseColor(0xff66bbaa.toInt())
        image.outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
        bitmap.eraseColor(android.graphics.Color.TRANSPARENT)
        for (y in 20 until 44) for (x in 20 until 44) bitmap.setPixel(x, y, color)
        val icon = File(directory, "nav_icon.png")
        icon.outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
        bitmap.recycle()
        val resources = mutableMapOf<String, File>()
        if (background) resources[image.name] = image
        if (icons) resources[icon.name] = icon
        val nav = JSONObject()
        // Keep one destination absent to exercise its native fallback alongside custom images.
        if (icons) ThemeDocument.destinations.keys.filter { it != "AModule" }.forEach { nav.put(it, icon.name) }
        val document = JSONObject().put("meta_name", name).put("isBackgroundEnabled", background)
            .put("backgroundOpacity", 0.0).put("navIconCustomEnabled", icons).put("navIcons", nav)
            .put("isDualBackgroundDimEnabled", true).put("backgroundDayDim", 0.0).put("backgroundNightDim", 0.0)
        return File(directory, "$name.fpt").also { out ->
            out.outputStream().use { FptContainer.write(document, resources, it) }
        }
    }

    private fun waitForIcon(color: Color) {
        try { compose.waitUntil(10_000) { iconHasColor(color) } }
        catch (error: Throwable) { capture("icon-refresh-failure"); throw error }
    }

    private fun assertWallpaperMaterial(opacity: Double) {
        val home = compose.onAllNodesWithContentDescription(context.getString(BottomBarDestination.Home.label),
            useUnmergedTree = true).onFirst().fetchSemanticsNode().boundsInRoot
        val superuser = compose.onAllNodesWithContentDescription(context.getString(BottomBarDestination.SuperUser.label),
            useUnmergedTree = true).onFirst().fetchSemanticsNode().boundsInRoot
        val point = androidx.compose.ui.geometry.Offset((home.center.x + superuser.center.x) / 2,
            (home.center.y + superuser.center.y) / 2)
        val pixels = compose.onRoot().captureToImage().toPixelMap()
        val color = pixels[point.x.toInt().coerceIn(0, pixels.width - 1), point.y.toInt().coerceIn(0, pixels.height - 1)]
        if (opacity == 0.0) assertTrue("${form.value} must show the green wallpaper: $color", color.green > color.red + .08f)
        else assertTrue("${form.value} must follow opaque chrome: $color", kotlin.math.abs(color.green - color.red) < .06f)
    }

    private fun iconHasColor(color: Color): Boolean {
        val nodes = compose.onAllNodesWithContentDescription(context.getString(BottomBarDestination.Home.label),
            useUnmergedTree = true)
        if (nodes.fetchSemanticsNodes().isEmpty()) return false
        val pixels = nodes.onFirst().captureToImage().toPixelMap()
        val center = pixels[pixels.width / 2, pixels.height / 2]
        return if (color == Color.Red) center.red > center.blue + .4f
            else center.blue > center.red + .4f
    }

    private fun render() {
        val orientation = InstrumentationRegistry.getArguments().getString("themeUiOrientation")
        compose.runOnUiThread {
            androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry.getInstance()
                .getActivitiesInStage(androidx.test.runner.lifecycle.Stage.RESUMED).forEach {
                    it.requestedOrientation = if (orientation == "landscape")
                        android.content.pm.ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE
                    else android.content.pm.ActivityInfo.SCREEN_ORIENTATION_PORTRAIT
                }
        }
        compose.setContent {
            val state = rememberMainPagerState(rememberPagerState(pageCount = { 4 }),
                animatePageChanges = form.value != "rail")
            pager = state
            CompositionLocalProvider(LocalUiMode provides skin,
                LocalColorMode provides if (dark) ColorMode.DARK.value else ColorMode.LIGHT.value,
                LocalMainPagerState provides state, LocalNavigator provides rememberNavigator(Route.Main),
                LocalThemeWallpaperPage provides state.selectedPage,
                LocalEnableFloatingBottomBar provides form.value.startsWith("floating").or(form.value == "flat"),
                LocalEnableFloatingBottomBarBlur provides (form.value == "floating-blur"),
                LocalFlatUi provides (form.value == "flat")) {
                KernelSUTheme(AppSettings(if (dark) ColorMode.DARK else ColorMode.LIGHT,
                    0xff6750a4.toInt(), PaletteStyle.TonalSpot, ColorSpec.SpecVersion.SPEC_2025), skin) {
                    val wallpaper = LocalThemeWallpaperStyle.current
                    SideEffect { style = wallpaper }
                    WallpaperHost(state.selectedPage) { NavigationContent() }
                }
            }
        }
        compose.waitForIdle()
    }

    @Composable private fun NavigationContent() {
        val blurBackdrop = rememberBlurBackdrop(form.value == "docked-blur")
        val surfaceColor = when (skin) {
            UiMode.Miuix -> top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme.surface
            UiMode.Material -> androidx.compose.material3.MaterialTheme.colorScheme.surface
        }
        val backdrop = rememberLayerBackdrop { drawRect(surfaceColor); drawContent() }
        val content: @Composable () -> Unit = {
            HorizontalPager(state = pager.pagerState, modifier = Modifier.fillMaxSize()
                .layerBackdrop(backdrop).then(if (blurBackdrop == null) Modifier else Modifier.layerBackdrop(blurBackdrop))) {
                Box(Modifier.fillMaxSize())
            }
        }
        val bar: @Composable () -> Unit = {
            Box(Modifier.fillMaxWidth().testTag("theme-navigation")) {
                BottomBar(blurBackdrop, backdrop, NavigationBadgeState(), Modifier.align(Alignment.BottomCenter))
            }
        }
        val rail = form.value == "rail"
        if (rail) {
            Row(Modifier.fillMaxSize()) {
                SideRail(NavigationBadgeState(), Modifier.testTag("theme-navigation"))
                Box(Modifier.weight(1f)) { content() }
            }
        } else when (skin) {
            UiMode.Miuix -> top.yukonga.miuix.kmp.basic.Scaffold(bottomBar = bar) {
                content()
            }
            UiMode.Material -> androidx.compose.material3.Scaffold(bottomBar = bar,
                containerColor = androidx.compose.material3.MaterialTheme.colorScheme.background) {
                content()
            }
        }
    }

    private fun capture(name: String) {
        compose.waitForIdle()
        android.os.SystemClock.sleep(100)
        val run = InstrumentationRegistry.getArguments().getString("themeEvidenceRun") ?: "navigation"
        val directory = File(context.getExternalFilesDir(null), "theme-ui-evidence/$run").apply { mkdirs() }
        val bitmap = instrumentation.uiAutomation.takeScreenshot()
        File(directory, "${skin.name}-${if (dark) "dark" else "light"}-$name.png").outputStream().use {
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, it)
        }
        bitmap.recycle()
    }

    companion object {
        @JvmStatic @Parameterized.Parameters(name = "{0}-dark={1}") fun modes() = listOf(
            arrayOf<Any>(UiMode.Miuix, false), arrayOf<Any>(UiMode.Miuix, true),
            arrayOf<Any>(UiMode.Material, false), arrayOf<Any>(UiMode.Material, true))
    }
}
