package com.maplesu.core.ui.screen.module

import android.content.ContextWrapper
import android.content.res.Configuration
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Shader
import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.ActivityResultRegistryOwner
import androidx.activity.result.contract.ActivityResultContract
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.getUnclippedBoundsInRoot
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasContentDescription
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.click
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.DpRect
import androidx.compose.ui.unit.dp
import androidx.core.app.ActivityOptionsCompat
import androidx.core.graphics.ColorUtils
import androidx.test.platform.app.InstrumentationRegistry
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.maplesu.core.R
import com.maplesu.core.data.model.Module
import com.maplesu.core.data.model.ModuleUpdateInfo
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.theme.AppSettings
import com.maplesu.core.ui.theme.ColorMode
import com.maplesu.core.ui.theme.KernelSUTheme
import com.maplesu.core.ui.theme.LocalColorMode
import com.maplesu.core.ui.theme.LocalEnableBlur
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import top.yukonga.miuix.kmp.theme.MiuixTheme
import java.io.File

/**
 * Real Android composition, text measurement, pointer input and screenshots of production pagers.
 * Run only on the isolated UI preview application/runner: never launches MainActivity or a backend.
 * These checks complement, rather than stand in for, human review of the emitted PNGs.
 */
@OptIn(ExperimentalTestApi::class)
@RunWith(Parameterized::class)
class ModuleNativeRenderTest(
    private val skin: UiMode,
    private val dark: Boolean,
    private val fontScale: Float,
) {
    @get:Rule val compose = createComposeRule()

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val caseName get() = "${skin.name.lowercase()}_${if (dark) "dark" else "light"}_320dp_${fontScale}x"
    private lateinit var listState: LazyListState
    private lateinit var scope: CoroutineScope
    private var pixelDensity = 1f
    private var surfaceArgb = 0
    private var textArgb = 0
    private val calls = mutableMapOf<String, Int>()
    private val state = mutableStateOf(ModuleUiState())
    private val viewportTag = "module-native-viewport"

    @Test fun longMetadataAndWrappingActionsUseRealMeasuredBounds() {
        val module = fixture(nativeModule = false)
        render(module)
        val title = compose.onNodeWithText(module.name, useUnmergedTree = true)
        val version = compose.onNodeWithText(versionLine(module), useUnmergedTree = true)
        val author = compose.onNodeWithText(authorLine(module), useUnmergedTree = true)
        assertEquals(2, title.textLayout().layoutInput.maxLines)
        assertTrue(title.textLayout().lineCount <= 2)
        assertEquals(1, version.textLayout().lineCount)
        assertEquals(1, author.textLayout().lineCount)
        assertTrue("long author should visibly ellipsize", author.textLayout().isLineEllipsized(0))
        val titleBounds = title.getUnclippedBoundsInRoot()
        val toggleBounds = toggle().getUnclippedBoundsInRoot()
        assertTrue("320dp / large fonts must move the toggle below the title", toggleBounds.top >= titleBounds.bottom)
        assertTrue("native title color contrast", ColorUtils.calculateContrast(textArgb, surfaceArgb) >= 4.5)
        assertEquals("native light/dark palette", dark, ColorUtils.calculateLuminance(surfaceArgb) < 0.3)
        capture("header")

        val labels = listOf(R.string.action, R.string.module_open_webui, R.string.module_update,
            R.string.module_card_artwork, R.string.uninstall).map { text(it) }
        val documentBounds = linkedMapOf<String, DpRect>()
        labels.forEach { label ->
            val target = button(label).performScrollTo().assertIsDisplayed()
            val bounds = target.getUnclippedBoundsInRoot()
            val viewport = compose.onNodeWithTag(viewportTag).getUnclippedBoundsInRoot()
            assertTrue("$label left edge", bounds.left >= viewport.left - 1.dp)
            assertTrue("$label right edge", bounds.right <= viewport.right + 1.dp)
            assertTrue("$label touch width", bounds.right - bounds.left >= 48.dp)
            assertTrue("$label touch height", bounds.bottom - bounds.top >= 48.dp)
            val offset = compose.runOnIdle { listState.firstVisibleItemScrollOffset / pixelDensity }.dp
            documentBounds[label] = DpRect(bounds.left, bounds.top + offset, bounds.right, bounds.bottom + offset)
        }
        val entries = documentBounds.entries.toList()
        entries.forEachIndexed { index, a ->
            entries.drop(index + 1).forEach { b ->
                assertFalse("${a.key} overlaps ${b.key}", a.value.overlaps(b.value))
            }
        }
        assertTrue("footer must wrap instead of squeezing five actions into one row",
            documentBounds.values.map { it.top.value.toInt() }.distinct().size >= 2)
        scrollToEnd()
        val uninstall = button(text(R.string.uninstall)).getUnclippedBoundsInRoot()
        val authorRight = author.getUnclippedBoundsInRoot().right
        assertEquals("uninstall aligns with the content right edge", authorRight.value, uninstall.right.value, 1f)
        val card = compose.onNode(hasText(module.name) and hasClickAction()).getUnclippedBoundsInRoot()
        val bottomInset = if (skin == UiMode.Miuix) 16f else 12f
        assertEquals("uninstall is at the card bottom", bottomInset,
            (card.bottom - uninstall.bottom).value, 1f)
        assertFalse("uninstall has icon semantics and no visible text",
            button(text(R.string.uninstall)).fetchSemanticsNode().config.contains(SemanticsProperties.Text))
        val fab = compose.onNode(hasContentDescription(text(R.string.module_install)) and hasClickAction())
            .getUnclippedBoundsInRoot()
        assertFalse("install FAB covers the last module action", uninstall.overlaps(fab))
        capture("footer", documentBounds)
    }

    @Test fun protectedUltraKeepsUninstallAndHidesModuleExecution() {
        render(fixture(nativeModule = true), safeMode = true)
        compose.onNodeWithText(text(R.string.home_safe_mode_banner_title)).performScrollTo().assertIsDisplayed()
        capture("safe-mode-banner")
        for (id in listOf(R.string.action, R.string.module_open_webui, R.string.module_update)) {
            compose.onAllNodes(hasText(text(id)) and hasClickAction()).assertCountEquals(0)
        }
        compose.onAllNodes(hasContentDescription(text(R.string.module_install)) and hasClickAction()).assertCountEquals(0)
        toggle().performScrollTo().assertIsNotEnabled()
        button(text(R.string.uninstall)).performScrollTo().assertIsEnabled().performTouchInput { click() }
        compose.runOnIdle { assertEquals(1, calls["uninstall"] ?: 0) }
        capture("safe-mode-uninstall")
    }

    @Test fun pendingFeedbackPreventsDuplicateMutationsButKeepsBrowsingAvailable() {
        val module = fixture(nativeModule = false)
        render(module)
        toggle().performScrollTo().assertIsEnabled().performTouchInput { click() }
        compose.waitForIdle()
        compose.runOnIdle { assertEquals(1, calls["toggle"] ?: 0) }
        toggle().assertIsNotEnabled().performTouchInput { click() }
        compose.onNodeWithText(text(R.string.module_card_processing)).performScrollTo().assertIsDisplayed()
        listOf(R.string.action, R.string.module_update, R.string.uninstall).forEach { id ->
            val target = button(text(id), requireClickAction = false).performScrollTo().assertIsNotEnabled()
            val fab = compose.onNode(hasContentDescription(text(R.string.module_install)) and hasClickAction())
            val before = target.getUnclippedBoundsInRoot()
            val fabBefore = fab.getUnclippedBoundsInRoot()
            if (id == R.string.uninstall) {
                capture("pending-uninstall-before-touch-scroll", linkedMapOf("target" to before, "install-fab" to fabBefore))
            }
            // performScrollTo considers the scrolling viewport, not a sibling floating button.
            if (before.overlaps(fabBefore)) scrollToEnd()
            target.assertIsDisplayed().assertIsNotEnabled()
            val bounds = target.getUnclippedBoundsInRoot()
            val visible = target.fetchSemanticsNode().boundsInRoot
            val fabBounds = fab.getUnclippedBoundsInRoot()
            assertTrue("${text(id)} touch width", bounds.right - bounds.left >= 48.dp)
            assertTrue("${text(id)} touch height", bounds.bottom - bounds.top >= 48.dp)
            assertEquals("${text(id)} fully visible width", (bounds.right - bounds.left).value,
                visible.width / pixelDensity, 1f / pixelDensity)
            assertEquals("${text(id)} fully visible height", (bounds.bottom - bounds.top).value,
                visible.height / pixelDensity, 1f / pixelDensity)
            assertFalse("install FAB covers pending ${text(id)}", bounds.overlaps(fabBounds))
            if (id == R.string.uninstall) {
                capture("pending-uninstall-touch-target", linkedMapOf("target" to bounds, "install-fab" to fabBounds))
            }
            target.performTouchInput { click() }
        }
        button(text(R.string.module_open_webui)).performScrollTo().assertIsEnabled().performTouchInput { click() }
        button(text(R.string.module_card_artwork)).assertIsEnabled()
        compose.runOnIdle {
            assertEquals(1, calls["toggle"] ?: 0)
            assertEquals(0, calls["action"] ?: 0)
            assertEquals(0, calls["update"] ?: 0)
            assertEquals(0, calls["uninstall"] ?: 0)
            assertEquals(1, calls["webui"] ?: 0)
            assertTrue("pending does not invent a successful enabled state", state.value.moduleList.single().enabled)
        }
        compose.onAllNodesWithText(authorLine(module), useUnmergedTree = true).assertCountEquals(1)
        listOf("Module details", "Hide details", "模块详情", "收起详情").forEach {
            compose.onAllNodesWithText(it, substring = true).assertCountEquals(0)
        }
        capture("pending")
    }

    @Test fun mapleSuCardArtworkAndCompatibilityUseTheSelectedNativeSkin() {
        val module = fixture(nativeModule = true)
        render(module, artwork = true)
        compose.onNodeWithText("MapleSU").assertIsDisplayed()
        compose.onAllNodesWithText(text(R.string.module_card_running)).assertCountEquals(0)
        compose.onAllNodesWithText(text(R.string.module_runtime_running)).assertCountEquals(0)
        val unsupported = text(R.string.module_card_unsupported_summary,
            listOf(R.string.module_capability_toggle, R.string.module_capability_stop,
                R.string.module_capability_in_place_update).map { text(it) }
                .joinToString(text(R.string.module_capability_separator)))
        // Some translations share the legacy prefix; inspect leaves and allow only the compact hint.
        compose.onAllNodes(
            hasText(text(R.string.module_runtime_unsupported, ""), substring = true) and !hasText(unsupported),
            useUnmergedTree = true,
        ).assertCountEquals(0)
        compose.onAllNodesWithText(unsupported, useUnmergedTree = true).assertCountEquals(1)
        capture("maplesu-artwork")
        val hint = compose.onNodeWithText(unsupported, useUnmergedTree = true)
            .performScrollTo().assertIsDisplayed().textLayout()
        assertEquals("compatibility hint stays on one line", 1, hint.layoutInput.maxLines)
        assertEquals("compatibility hint uses small type", 11f, hint.layoutInput.style.fontSize.value, 0.1f)
        capture("maplesu-compatibility")
    }

    private fun render(module: Module, artwork: Boolean = false, safeMode: Boolean = false) {
        val fixtureDir = File(context.cacheDir, "module-native-render/$caseName/${if (artwork) "art" else "plain"}")
        assertTrue(fixtureDir.isDirectory || fixtureDir.mkdirs())
        val fixtureContext = object : ContextWrapper(context) {
            override fun getFilesDir(): File = fixtureDir
        }
        // Register production launchers without allowing this rendering fixture to start activities.
        val fixtureActivityResultOwner = object : ActivityResultRegistryOwner {
            override val activityResultRegistry: ActivityResultRegistry = object : ActivityResultRegistry() {
                override fun <I, O> onLaunch(
                    requestCode: Int,
                    contract: ActivityResultContract<I, O>,
                    input: I,
                    options: ActivityOptionsCompat?,
                ) {
                    error("Module rendering fixture must not launch an external activity")
                }
            }
        }
        if (artwork) writeArtwork(fixtureDir, module.id)
        state.value = ModuleUiState(hasLoaded = true, modules = listOf(module), moduleList = listOf(module),
            isSafeMode = safeMode, isUltra = safeMode,
            updateInfo = if (module.canToggle) mapOf(module.id to ModuleUpdateInfo(
                "https://fixture.invalid/module.zip", "2.0", "UI fixture only", 2)) else emptyMap())
        compose.setContent {
            val originalDensity = LocalDensity.current
            val configuration = Configuration(LocalConfiguration.current).apply {
                screenWidthDp = 320
                smallestScreenWidthDp = 320
                this.fontScale = this@ModuleNativeRenderTest.fontScale
            }
            CompositionLocalProvider(
                LocalContext provides fixtureContext,
                LocalActivityResultRegistryOwner provides fixtureActivityResultOwner,
                LocalConfiguration provides configuration,
                LocalDensity provides Density(originalDensity.density, fontScale),
                LocalUiMode provides skin,
                LocalColorMode provides if (dark) ColorMode.DARK.value else ColorMode.LIGHT.value,
                LocalEnableBlur provides false,
            ) {
                KernelSUTheme(AppSettings(if (dark) ColorMode.DARK else ColorMode.LIGHT,
                    0xff6750a4.toInt(), PaletteStyle.TonalSpot, ColorSpec.SpecVersion.SPEC_2025), skin) {
                    val nativeSurface = if (skin == UiMode.Miuix) MiuixTheme.colorScheme.surfaceContainer
                        else MaterialTheme.colorScheme.surfaceBright
                    val nativeText = if (skin == UiMode.Miuix) MiuixTheme.colorScheme.onSurface
                        else MaterialTheme.colorScheme.onSurface
                    val currentList = rememberLazyListState()
                    val currentScope = rememberCoroutineScope()
                    SideEffect {
                        listState = currentList
                        scope = currentScope
                        pixelDensity = originalDensity.density
                        surfaceArgb = nativeSurface.toArgb()
                        textArgb = nativeText.toArgb()
                    }
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
                        Box(Modifier.width(320.dp).fillMaxHeight().testTag(viewportTag)) {
                            when (skin) {
                                UiMode.Miuix -> ModulePagerMiuix(state.value, null, emptyFlow(), actions(),
                                    bottomInnerPadding = 24.dp, listState = currentList)
                                UiMode.Material -> ModulePagerMaterial(state.value, null, emptyFlow(), actions(),
                                    bottomInnerPadding = 24.dp, listState = currentList)
                            }
                        }
                    }
                }
            }
        }
        compose.waitForIdle()
        val bounds = compose.onNodeWithTag(viewportTag).getUnclippedBoundsInRoot()
        val width = bounds.right - bounds.left
        assertEquals("render device must have at least 320dp usable width", 320f, width.value, 1f)
    }

    private fun actions() = ModuleActions(
        onRefresh = {}, onSearchStatusChange = {}, onSearchTextChange = {}, onClearSearch = {},
        onRequestUpdateConfirmation = { _, _ -> record("update") },
        onRequestUninstallConfirmation = { record("uninstall") }, onDismissConfirmRequest = {},
        onConfirmUpdate = {}, onOpenRepo = {}, onToggleSortActionFirst = {}, onToggleSortEnabledFirst = {},
        onOpenWebUi = { record("webui") },
        onToggleModule = { module ->
            record("toggle")
            state.value = state.value.copy(pendingModuleIds = setOf(module.id))
        },
        onUninstallModule = { record("uninstall") }, onUndoUninstallModule = { record("undo") },
        onOpenFlash = {}, onExecuteModuleAction = { record("action") },
    )

    private fun record(name: String) { calls[name] = (calls[name] ?: 0) + 1 }
    private fun text(id: Int, vararg args: Any): String = context.getString(id, *args)
    private fun versionLine(module: Module) = "${text(R.string.module_version)}: ${module.version}"
    private fun authorLine(module: Module) = "${text(R.string.module_author)}: ${module.author}"
    private fun button(label: String, requireClickAction: Boolean = true): SemanticsNodeInteraction {
        val matcher = (hasText(label) or hasContentDescription(label)) and
            SemanticsMatcher.expectValue(SemanticsProperties.Role, Role.Button)
        return compose.onNode(if (requireClickAction) matcher and hasClickAction() else matcher)
    }
    private fun toggle() = compose.onNode(SemanticsMatcher.expectValue(SemanticsProperties.Role, Role.Switch))

    private fun DpRect.overlaps(other: DpRect): Boolean =
        left < other.right && other.left < right && top < other.bottom && other.top < bottom

    private fun SemanticsNodeInteraction.textLayout(): TextLayoutResult {
        val results = mutableListOf<TextLayoutResult>()
        performSemanticsAction(SemanticsActions.GetTextLayoutResult) { action -> action(results) }
        assertEquals("one real TextLayoutResult", 1, results.size)
        return results.single()
    }

    private fun scrollToEnd() {
        compose.runOnIdle { scope.launch { listState.scrollToItem(0, 100_000) } }
        compose.waitForIdle()
    }

    private fun capture(scene: String, bounds: Map<String, DpRect> = emptyMap()) {
        val directory = File(context.getExternalFilesDir(null), "module-native-render/$caseName")
        assertTrue(directory.isDirectory || directory.mkdirs())
        val bitmap = compose.onNodeWithTag(viewportTag).captureToImage().asAndroidBitmap()
        File(directory, "$scene.png").outputStream().use { output ->
            assertTrue(bitmap.compress(Bitmap.CompressFormat.PNG, 100, output))
        }
        val geometry = JSONArray()
        bounds.forEach { (label, rect) -> geometry.put(JSONObject().put("label", label)
            .put("leftDp", rect.left.value).put("topDp", rect.top.value)
            .put("rightDp", rect.right.value).put("bottomDp", rect.bottom.value)) }
        File(directory, "$scene.json").writeText(JSONObject().put("skin", skin.name).put("dark", dark)
            .put("widthDp", 320).put("fontScale", fontScale).put("scene", scene)
            .put("surfaceArgb", surfaceArgb).put("textArgb", textArgb).put("bounds", geometry).toString(2))
    }

    private fun writeArtwork(directory: File, moduleId: String) {
        val art = File(directory, "module_cards").apply { mkdirs() }
        val bitmap = Bitmap.createBitmap(512, 256, Bitmap.Config.ARGB_8888)
        Canvas(bitmap).drawPaint(Paint().apply { shader = LinearGradient(0f, 0f, 512f, 256f,
            intArrayOf(0xff33264d.toInt(), 0xff9672bd.toInt(), 0xff496875.toInt()), null, Shader.TileMode.CLAMP) })
        val id = moduleId.replace(Regex("[^A-Za-z0-9._-]"), "_").take(80)
        File(art, "$id.jpg").outputStream().use { bitmap.compress(Bitmap.CompressFormat.JPEG, 92, it) }
        bitmap.recycle()
    }

    private fun fixture(nativeModule: Boolean) = Module(
        id = if (nativeModule) "maplesu:ui_native_render_fixture" else "ui_native_render_fixture",
        name = "TEESimulator-RS_MapleSU_Extended_Native_Rendering_Fixture_Module_Title",
        author = "JingMatrix · MapleSU Community · Native Rendering Test Authors Collaboration Team",
        version = "v2026.10.31-preview-native-layout-fixture-long-version",
        versionCode = 1, description = "A real module card with a concise description.",
        enabled = true, update = false, remove = false, updateJson = "",
        hasWebUi = true, hasActionScript = !nativeModule, metamodule = false,
        actionIconPath = null, webUiIconPath = null, runtimeStatus = "running", canToggle = !nativeModule,
        unsupported = if (nativeModule) listOf("toggle", "stop", "in-place-update") else emptyList(),
    )

    companion object {
        @JvmStatic @Parameterized.Parameters(name = "{0}-{1}-320dp-font{2}")
        fun matrix(): Collection<Array<Any>> = UiMode.entries.flatMap { skin ->
            listOf(false, true).flatMap { dark -> listOf(1f, 1.8f).map { scale -> arrayOf<Any>(skin, dark, scale) } }
        }
    }
}
