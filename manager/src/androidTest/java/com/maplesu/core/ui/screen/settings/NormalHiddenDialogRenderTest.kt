package com.maplesu.core.ui.screen.settings

import android.graphics.Bitmap
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextReplacement
import androidx.test.platform.app.InstrumentationRegistry
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.maplesu.core.R
import dev.maplesu.manager.liteweb.RecoveryWebUiState
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.theme.AppSettings
import com.maplesu.core.ui.theme.ColorMode
import com.maplesu.core.ui.theme.KernelSUTheme
import com.maplesu.core.ui.theme.LocalColorMode
import com.maplesu.core.ui.theme.LocalEnableBlur
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import java.io.File

/** Native dialog fixtures only: no ViewModel, controller, daemon, root or package removal. */
@RunWith(Parameterized::class)
class NormalHiddenDialogRenderTest(private val mode: UiMode, private val dark: Boolean) {
    @get:Rule val compose = createComposeRule()
    private val ui = mutableStateOf(NormalHiddenUi(visible = true, preparing = true))
    private var activates = 0
    private var retries = 0
    private var dismisses = 0

    @Test fun preparingIsImmediateAndCancelNeverActivates() {
        render()
        compose.onNodeWithText(text(R.string.normal_hidden_preparing)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.normal_hidden_prepare)).assertIsNotEnabled()
        compose.onNodeWithText(text(R.string.normal_hidden_copy)).assertDoesNotExist()
        capture("preparing")
        compose.onNodeWithText(text(R.string.lite_hidden_confirm_cancel)).performClick()
        compose.runOnIdle { assertEquals(0, activates); assertEquals(1, dismisses) }
    }

    @Test fun preparedLinkRequiresAccessThenOneSavedConfirmationActivates() {
        ui.value = NormalHiddenUi(visible = true, linkAvailable = true, webUiState = RecoveryWebUiState.RUNNING)
        render()
        compose.onNodeWithTag("normalHiddenPort").assertDoesNotExist()
        compose.onNodeWithText(text(R.string.normal_hidden_prepare)).assertDoesNotExist()
        compose.onNodeWithText(text(R.string.normal_hidden_webui_stop)).assertDoesNotExist()
        compose.onNodeWithText(text(R.string.normal_hidden_saved_confirm)).assertIsNotEnabled()
        compose.onNodeWithText(text(R.string.normal_hidden_copy)).performClick()
        compose.onNodeWithText(text(R.string.normal_hidden_saved_confirm)).assertIsEnabled()
        capture("save-link")
        compose.onNodeWithText(text(R.string.normal_hidden_saved_confirm)).performClick()
        compose.runOnIdle { assertEquals(true, ui.value.linkSaved); assertEquals(1, activates) }
    }

    @Test fun portSetupPrecedesPreparingAndSavingTheLink() {
        ui.value = NormalHiddenUi(visible = true)
        render()
        val setupTitle = compose.onNodeWithText(text(R.string.normal_hidden_setup_title)).fetchSemanticsNode().id
        compose.onNodeWithTag("normalHiddenPort").performTextReplacement("18437")
        compose.onNodeWithText(text(R.string.normal_hidden_saved_confirm)).assertDoesNotExist()
        compose.onNodeWithText(text(R.string.normal_hidden_copy)).assertDoesNotExist()
        compose.runOnIdle { assertEquals("18437", ui.value.portText); assertEquals(0, activates) }
        capture("setup")
        compose.onNodeWithText(text(R.string.normal_hidden_prepare)).assertIsEnabled().performClick()
        compose.onNodeWithText(text(R.string.normal_hidden_preparing)).assertIsDisplayed()
        compose.runOnIdle { assertEquals(1, retries) }
        compose.runOnIdle { ui.value = ui.value.copy(preparing = false, linkAvailable = true,
            webUiState = RecoveryWebUiState.RUNNING) }
        compose.onNodeWithTag("normalHiddenPort").assertDoesNotExist()
        compose.onNodeWithText(text(R.string.normal_hidden_setup_title)).assertDoesNotExist()
        val linkTitle = compose.onNodeWithText(text(R.string.normal_hidden_link_title)).fetchSemanticsNode().id
        assertNotEquals("The next stage creates a new dialog", setupTitle, linkTitle)
        compose.onNodeWithText(text(R.string.normal_hidden_copy)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.ui_polish_link_open)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.normal_hidden_saved_confirm)).assertIsNotEnabled()
        compose.runOnIdle { assertEquals(0, activates) }
    }

    @Test fun openingWebUiAllowsConfirmationOnlyAfterReturningToTheDialog() {
        ui.value = NormalHiddenUi(visible = true, linkAvailable = true, webUiState = RecoveryWebUiState.RUNNING)
        render()
        compose.onNodeWithText(text(R.string.ui_polish_link_open)).performClick()
        compose.runOnIdle { assertEquals(0, activates); assertEquals(false, ui.value.linkSaved) }
        compose.onNodeWithText(text(R.string.normal_hidden_saved_confirm)).assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals(true, ui.value.linkSaved); assertEquals(1, activates) }
    }

    @Test fun cancellingTheLinkDialogDoesNotActivateHiding() {
        ui.value = NormalHiddenUi(visible = true, linkAvailable = true, webUiState = RecoveryWebUiState.RUNNING)
        render()
        compose.onNodeWithText(text(R.string.normal_hidden_copy)).performClick()
        compose.onNodeWithText(text(R.string.lite_hidden_confirm_cancel)).performClick()
        compose.onNodeWithText(text(R.string.normal_hidden_link_title)).assertDoesNotExist()
        compose.runOnIdle { assertEquals(0, activates); assertEquals(1, dismisses) }
    }

    @Test fun failureStaysVisibleAndRetryShowsBusyWithoutActivation() {
        ui.value = NormalHiddenUi(visible = true, failure = NormalHiddenFailure.ACTIVATE)
        render()
        compose.onNodeWithText(text(R.string.normal_hidden_activate_failed)).assertIsDisplayed()
        capture("failed")
        compose.onNodeWithText(text(R.string.normal_hidden_retry)).performClick()
        compose.onNodeWithText(text(R.string.normal_hidden_preparing)).assertIsDisplayed()
        compose.runOnIdle { assertEquals(1, retries); assertEquals(0, activates) }
    }

    @Test fun activationDisablesConfirmationAndCancelWithoutFakingCompletion() {
        ui.value = NormalHiddenUi(visible = true, activating = true,
            linkAvailable = true, linkAccessed = true, linkSaved = true)
        render()
        compose.onNodeWithText(text(R.string.normal_hidden_activating)).assertIsNotEnabled()
        compose.onNodeWithText(text(R.string.lite_hidden_confirm_cancel)).assertIsNotEnabled()
        compose.onNodeWithText(text(R.string.normal_hidden_done_title)).assertDoesNotExist()
        capture("activating")
        compose.runOnIdle { assertEquals(0, activates); assertEquals(0, dismisses) }
    }

    private fun render() {
        compose.setContent {
            CompositionLocalProvider(LocalUiMode provides mode,
                LocalColorMode provides if (dark) ColorMode.DARK.value else ColorMode.LIGHT.value,
                LocalEnableBlur provides false) {
                KernelSUTheme(AppSettings(if (dark) ColorMode.DARK else ColorMode.LIGHT,
                    0xff6750a4.toInt(), PaletteStyle.TonalSpot, ColorSpec.SpecVersion.SPEC_2025), mode) {
                    NormalHiddenDialog(ui.value,
                        onDismiss = { dismisses++; ui.value = NormalHiddenUi() },
                        onPrepare = { retries++; ui.value = NormalHiddenUi(visible = true, preparing = true) },
                        onCopyLink = { ui.value = ui.value.copy(linkAccessed = true) },
                        onOpenLink = { ui.value = ui.value.copy(linkAccessed = true) },
                        onSaveLink = { ui.value = ui.value.copy(linkSaved = true) },
                        onConfirm = { activates++; ui.value = ui.value.copy(activating = true) },
                        onPortChange = { ui.value = ui.value.withPort(it) })
                }
            }
        }
    }

    private fun text(id: Int) = InstrumentationRegistry.getInstrumentation().targetContext.getString(id)

    private fun capture(state: String) {
        compose.waitForIdle()
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val directory = File(instrumentation.targetContext.getExternalFilesDir(null), "normal-hidden-ui")
        directory.mkdirs()
        val screenshot = instrumentation.uiAutomation.takeScreenshot()
        File(directory, "${mode.name.lowercase()}_${if (dark) "dark" else "light"}_$state.png")
            .outputStream().use { screenshot.compress(Bitmap.CompressFormat.PNG, 100, it) }
        screenshot.recycle()
    }

    companion object {
        @JvmStatic @Parameterized.Parameters(name = "{0}-dark{1}")
        fun parameters(): List<Array<Any>> = UiMode.entries.flatMap { mode ->
            listOf(false, true).map { dark -> arrayOf<Any>(mode, dark) }
        }
    }
}
