package dev.maplesu.manager.jailbreak

import android.content.res.Configuration
import android.graphics.Bitmap
import android.view.KeyEvent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.swipeDown
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.test.getUnclippedBoundsInRoot
import androidx.compose.ui.text.TextLayoutResult
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
import com.maplesu.core.ui.theme.LocalEnableBlur
import dev.maplesu.ghostlock.extract.OtaCopy
import dev.maplesu.ghostlock.extract.OtaFailure
import dev.maplesu.ghostlock.extract.OtaParseState
import java.io.File
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

/** Production dialog and native controls only: callbacks never touch a provider or device state. */
@RunWith(Parameterized::class)
class JailbreakSelectionNativeRenderTest(private val skin: UiMode, private val dark: Boolean) {
    @get:Rule val compose = createComposeRule()
    private val context by lazy {
        val base = InstrumentationRegistry.getInstrumentation().targetContext
        base.createConfigurationContext(Configuration(base.resources.configuration).apply {
            setLocale(Locale.SIMPLIFIED_CHINESE)
        })
    }
    private val state = mutableStateOf(JailbreakSelectionState(ghostlockDecided = true, checksReady = true))
    private val visible = mutableStateOf(true)
    private var starts = 0
    private var dismissals = 0
    private var localPicks = 0

    @Test fun dirtyfragUsesNativeSkinAndOnlyShowsTheRequestedModeNames() {
        render()
        choice(text(R.string.maplesu_jailbreak_dirtyfrag)).assertIsDisplayed().assertIsSelected()
        compose.onAllNodesWithText(OtaCopy.PICK_LOCAL).assertCountEquals(0)
        compose.onAllNodesWithText(OtaCopy.FIELD_HINT).assertCountEquals(0)
        listOf(R.string.maplesu_jailbreak_target_ultra, R.string.maplesu_jailbreak_target_normal).forEach { id ->
            choice(text(id)).performScrollTo().assertIsDisplayed()
            val layouts = mutableListOf<TextLayoutResult>()
            val label = compose.onNodeWithText(text(id), useUnmergedTree = true)
            label.performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(layouts) }
            val layout = layouts.single()
            assertTrue("Chinese mode name uses a readable size", layout.layoutInput.style.fontSize.value >= 16f)
            assertTrue("Chinese mode name stays compact", layout.lineCount <= 3)
            repeat(layout.lineCount) { line ->
                assertFalse("Chinese mode name is never ellipsized", layout.isLineEllipsized(line))
            }
            assertFalse("Chinese mode name fits its measured width", layout.hasVisualOverflow)
            val labelBounds = label.getUnclippedBoundsInRoot()
            val rowBounds = choice(text(id)).getUnclippedBoundsInRoot()
            assertTrue("Chinese mode name stays inside its row", labelBounds.left >= rowBounds.left &&
                labelBounds.right <= rowBounds.right && labelBounds.top >= rowBounds.top &&
                labelBounds.bottom <= rowBounds.bottom)
        }
        choice(text(R.string.maplesu_jailbreak_target_normal)).assertIsSelected()
        compose.onNodeWithText(text(R.string.maplesu_jailbreak_start)).assertIsDisplayed().assertIsEnabled()
        capture("dirtyfrag")
    }

    @Test fun ghostlockShowsImagesOnlyWhileSelectedAndKeepsUrlAndParseState() {
        render()
        choice(text(R.string.maplesu_jailbreak_ghostlock)).performScrollTo().performClick()
        compose.onNode(hasSetTextAction()).performScrollTo().performTextInput("https://fixture.invalid/update.zip")
        compose.onNodeWithText(OtaCopy.ACTION).performScrollTo().performClick()
        compose.onNodeWithText(OtaCopy.lineFor(state.value.otaState)!!).performScrollTo().assertIsDisplayed()
        compose.onNodeWithText(OtaCopy.PICK_LOCAL).performScrollTo().performClick()
        assertEquals(1, localPicks)
        compose.onNodeWithText(text(R.string.maplesu_jailbreak_start)).assertIsNotEnabled()
        capture("ghostlock-configuration")
        choice(text(R.string.maplesu_jailbreak_dirtyfrag)).performScrollTo().performClick()
        compose.onAllNodesWithText(OtaCopy.PICK_LOCAL).assertCountEquals(0)
        compose.onAllNodesWithText(OtaCopy.FIELD_HINT).assertCountEquals(0)
        compose.onNodeWithText(text(R.string.maplesu_jailbreak_start)).assertIsEnabled()
        choice(text(R.string.maplesu_jailbreak_ghostlock)).performScrollTo().performClick()
        compose.onNode(hasSetTextAction()).performScrollTo()
            .assertTextContains("https://fixture.invalid/update.zip")
        compose.onNodeWithText(OtaCopy.lineFor(state.value.otaState)!!).performScrollTo().assertIsDisplayed()
        assertEquals(0, starts)
    }

    @Test fun readyProfileHidesSetupAndSelectionMapsToTheOriginalBackends() {
        render()
        choice(text(R.string.maplesu_jailbreak_target_ultra)).performScrollTo().performClick()
        compose.runOnIdle { assertEquals(JailbreakRequest.BACKEND_HOOK, state.value.rootTarget) }
        choice(text(R.string.maplesu_jailbreak_target_normal)).performScrollTo().performClick()
        compose.runOnIdle { assertEquals(JailbreakRequest.BACKEND_KSU, state.value.rootTarget) }
        compose.runOnIdle { state.value = state.value.copy(method = JailbreakMethod.GHOSTLOCK, ghostlockReady = true) }
        compose.onAllNodesWithText(OtaCopy.PICK_LOCAL).assertCountEquals(0)
        compose.onNodeWithText(text(R.string.maplesu_jailbreak_start)).assertIsEnabled().performClick()
        assertEquals(1, starts)
        compose.runOnIdle { state.value = state.value.copy(otaState = OtaParseState.Parsing) }
        compose.onNodeWithText(OtaCopy.PARSING).assertIsNotEnabled()
        compose.onNodeWithText(text(R.string.maplesu_jailbreak_close)).assertIsEnabled()
        capture("ghostlock-ready")
    }

    @Test fun systemBackDismissesTheNativeWindowWithoutStartingAnything() {
        render()
        InstrumentationRegistry.getInstrumentation().sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
        compose.waitUntil(5_000) { dismissals == 1 }
        assertEquals(0, starts)
        compose.onAllNodesWithText(text(R.string.maplesu_jailbreak_start)).assertCountEquals(0)
    }

    @Test fun failureOpensLogSheetOnceAndCanReopenItForEveryModeAndProvider() {
        render()
        var run = 0L
        for (method in JailbreakMethod.entries) for (backend in listOf(
            JailbreakRequest.BACKEND_KSU, JailbreakRequest.BACKEND_HOOK)) {
            compose.runOnIdle { state.value = state.value.copy(runId = ++run, method = method,
                rootTarget = backend, outcome = JailbreakController.Outcome(
                    JailbreakStatus.STAGE_FAILED, "fixture", "HOOK_BACKEND_NOT_READY:su_gate_not_armed")) }
            compose.onNodeWithText(text(R.string.maplesu_jailbreak_logs_title)).assertIsDisplayed()
            compose.onNodeWithText(text(R.string.maplesu_jailbreak_export_logs)).assertIsDisplayed().assertIsEnabled()
            compose.onNodeWithText(text(R.string.maplesu_jailbreak_share_logs)).assertIsDisplayed().assertIsEnabled()
            compose.onNodeWithText(text(R.string.maplesu_jailbreak_logs_close)).performClick()
            // Recomposition from status polling must not reopen a dismissed sheet.
            compose.runOnIdle { state.value = state.value.copy(observedStage = "fixture-$run") }
            compose.onAllNodesWithText(text(R.string.maplesu_jailbreak_logs_title)).assertCountEquals(0)
            compose.onNodeWithText(text(R.string.maplesu_jailbreak_open_logs)).performScrollTo().performClick()
            compose.onNodeWithText(text(R.string.maplesu_jailbreak_logs_title)).assertIsDisplayed()
            compose.onNodeWithText(text(R.string.maplesu_jailbreak_logs_close)).performClick()
        }
        assertEquals(0, starts)
    }

    @Test fun runningAttemptsShowLiveNativeAndWorkerLogsForEveryProviderAndTarget() {
        render()
        var run = 0L
        for (method in JailbreakMethod.entries) for (backend in listOf(
            JailbreakRequest.BACKEND_KSU, JailbreakRequest.BACKEND_HOOK)) {
            val id = "render-live-${java.util.UUID.randomUUID()}"
            val directory = JailbreakDiagnostics.attemptDirectory(context.filesDir, id)
            try {
                val native = File(directory, "${method.wireName}-native.log")
                native.writeText("[*] native started $id\n")
                compose.runOnIdle { state.value = state.value.copy(runId = ++run, method = method,
                    rootTarget = backend, running = true, outcome = null, logAttemptId = id) }
                compose.waitUntil(5_000) { compose.onAllNodesWithText("[*] native started $id")
                    .fetchSemanticsNodes().isNotEmpty() }
                native.appendText("[+] native progress $id\n")
                val worker = File(directory, "worker/root-worker.log")
                worker.parentFile!!.mkdirs()
                worker.writeText("[+] worker connected $id\n")
                compose.waitUntil(5_000) { compose.onAllNodesWithText("[+] worker connected $id")
                    .fetchSemanticsNodes().isNotEmpty() }
                compose.onNodeWithContentDescription(text(R.string.maplesu_jailbreak_copy_logs)).assertIsEnabled()
                capture("live-${method.wireName}-$backend")
                compose.onNodeWithText(text(R.string.maplesu_jailbreak_logs_close)).performClick()
                compose.runOnIdle { assertTrue(state.value.running) }
                compose.onNodeWithText(text(R.string.maplesu_jailbreak_open_logs)).performScrollTo().performClick()
                compose.onNodeWithText(text(R.string.maplesu_jailbreak_logs_title)).assertIsDisplayed()
                compose.onNodeWithText(text(R.string.maplesu_jailbreak_logs_close)).performClick()
                compose.runOnIdle { state.value = state.value.copy(running = false) }
            } finally { directory.deleteRecursively() }
        }
        assertEquals(0, starts)
    }

    @Test fun readingOlderOutputPausesFollowingUntilBackToLatestIsPressed() {
        val id = "render-scroll-${java.util.UUID.randomUUID()}"
        val directory = JailbreakDiagnostics.attemptDirectory(context.filesDir, id)
        val native = File(directory, "dirtyfrag-native.log")
        native.writeText((1..120).joinToString("\n") { "[*] fixture line $it" } + "\n")
        state.value = state.value.copy(runId = 1, running = true, logAttemptId = id)
        try {
            render()
            compose.waitUntil(5_000) { compose.onAllNodesWithText("[*] fixture line 120")
                .fetchSemanticsNodes().isNotEmpty() }
            compose.onNodeWithTag("jailbreak-log-console").performTouchInput { swipeDown() }
            compose.onNodeWithText(text(R.string.maplesu_jailbreak_logs_latest)).assertIsDisplayed()
            native.appendText("[+] newest fixture output\n")
            compose.onNodeWithText(text(R.string.maplesu_jailbreak_logs_latest)).performClick()
            compose.waitUntil(5_000) { compose.onAllNodesWithText("[+] newest fixture output")
                .fetchSemanticsNodes().isNotEmpty() }
        } finally { directory.deleteRecursively() }
    }

    private fun render() {
        compose.setContent {
            CompositionLocalProvider(
                LocalContext provides context,
                LocalConfiguration provides context.resources.configuration,
                LocalUiMode provides skin,
                LocalColorMode provides if (dark) ColorMode.DARK.value else ColorMode.LIGHT.value,
                LocalEnableBlur provides false,
            ) {
                KernelSUTheme(AppSettings(if (dark) ColorMode.DARK else ColorMode.LIGHT,
                    0xff6750a4.toInt(), PaletteStyle.TonalSpot, ColorSpec.SpecVersion.SPEC_2025), skin) {
                    Box(Modifier.fillMaxSize()) {
                        if (visible.value) JailbreakSelectionDialogContent(
                            ui = state.value,
                            onDismiss = { dismissals++; visible.value = false },
                            onConfirm = { starts++ },
                            onMethodSelected = { state.value = state.value.copy(method = it) },
                            onTargetSelected = { state.value = state.value.copy(rootTarget = it) },
                            onSoftRebootChanged = { state.value = state.value.copy(softReboot = it) },
                            onOtaUrlChanged = { state.value = state.value.copy(otaUrl = it) },
                            onParse = { state.value = state.value.copy(otaState = OtaParseState.Failed(OtaFailure.INVALID_URL)) },
                            onLocalBoot = { localPicks++ },
                            onOverwrite = { state.value = state.value.copy(awaitingOverwrite = false) },
                            onCancelOverwrite = { state.value = state.value.copy(awaitingOverwrite = false) },
                        )
                    }
                }
            }
        }
        compose.waitForIdle()
    }

    private fun choice(label: String) = compose.onNode(hasText(label) and hasClickAction())
    private fun text(id: Int) = context.getString(id)
    private fun capture(scene: String) {
        val directory = File(context.getExternalFilesDir(null),
            "jailbreak-native-render/${skin.name.lowercase()}_${if (dark) "dark" else "light"}")
        assertTrue(directory.isDirectory || directory.mkdirs())
        val screenshot = InstrumentationRegistry.getInstrumentation().uiAutomation.takeScreenshot()
        File(directory, "$scene.png").outputStream().use { output ->
            assertTrue(screenshot.compress(Bitmap.CompressFormat.PNG, 100, output))
        }
        screenshot.recycle()
    }

    companion object {
        @JvmStatic @Parameterized.Parameters(name = "{0}_{1}")
        fun skins(): List<Array<Any>> = UiMode.entries.flatMap { skin ->
            listOf(false, true).map { dark -> arrayOf(skin, dark) }
        }
    }
}
