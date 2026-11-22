package dev.maplesu.manager.workmode.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
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
import dev.maplesu.manager.liteweb.RecoveryWebUiState
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

/** Native skin rendering; callbacks are fixtures and never stop a real service. */
@RunWith(Parameterized::class)
class WebUiControlRenderTest(private val mode: UiMode, private val dark: Boolean) {
    @get:Rule val compose = createComposeRule()
    private val ui = mutableStateOf(LiteHiddenPageUi(webUiState = RecoveryWebUiState.RUNNING, checkingWebUi = false))
    private var stops = 0
    private var refreshes = 0

    @Test fun stopRequiresConfirmationAndCancelKeepsTheListener() {
        render()
        compose.onNodeWithText(text(R.string.webui_control_stop)).assertIsDisplayed().performClick()
        compose.onNodeWithText(text(R.string.webui_control_confirm_title)).assertIsDisplayed()
        compose.runOnIdle { assertEquals(0, stops) }
        compose.onNodeWithText(text(R.string.lite_hidden_confirm_cancel)).performClick()
        compose.onNodeWithText(text(R.string.webui_control_confirm_title)).assertDoesNotExist()
        compose.runOnIdle { assertEquals(0, stops) }
    }

    @Test fun pendingStopIsImmediateAndDuplicateConfirmationIsDisabled() {
        ui.value = ui.value.copy(confirmStopWebUi = true)
        render()
        compose.onNodeWithText(text(R.string.webui_control_stop)).performClick()
        compose.onNodeWithText(text(R.string.webui_control_stopping)).assertIsDisplayed().assertIsNotEnabled()
        compose.onNodeWithText(text(R.string.lite_hidden_confirm_cancel)).assertIsNotEnabled()
        compose.runOnIdle { assertEquals(1, stops) }
    }

    @Test fun stoppedAndUnknownStatesDoNotOfferAFalseStopAction() {
        ui.value = ui.value.copy(webUiState = RecoveryWebUiState.STOPPED)
        render()
        compose.onNodeWithText(text(R.string.webui_control_stopped)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.webui_control_stop)).assertDoesNotExist()
        compose.onNodeWithText(text(R.string.webui_control_restart_hint)).assertIsDisplayed()
        compose.runOnIdle { ui.value = ui.value.copy(webUiState = RecoveryWebUiState.UNKNOWN) }
        compose.onNodeWithText(text(R.string.webui_control_retry)).performClick()
        compose.runOnIdle { assertEquals(1, refreshes); assertEquals(0, stops) }
    }

    private fun render() {
        compose.setContent {
            CompositionLocalProvider(
                LocalUiMode provides mode,
                LocalColorMode provides if (dark) ColorMode.DARK.value else ColorMode.LIGHT.value,
                LocalEnableBlur provides false,
            ) {
                KernelSUTheme(AppSettings(
                    if (dark) ColorMode.DARK else ColorMode.LIGHT,
                    0xff6750a4.toInt(), PaletteStyle.TonalSpot, ColorSpec.SpecVersion.SPEC_2025,
                ), mode) {
                    Column {
                        if (!ui.value.confirmStopWebUi) WebUiServiceActions(ui.value,
                            onStop = { ui.value = ui.value.copy(confirmStopWebUi = true) },
                            onRefresh = { refreshes += 1 })
                        WebUiStopDialog(ui.value,
                            onDismiss = { ui.value = ui.value.copy(confirmStopWebUi = false) },
                            onConfirm = { stops += 1; ui.value = ui.value.copy(stoppingWebUi = true) })
                    }
                }
            }
        }
    }

    private fun text(id: Int) = InstrumentationRegistry.getInstrumentation().targetContext.getString(id)

    companion object {
        @JvmStatic @Parameterized.Parameters(name = "{0}-dark{1}")
        fun parameters(): List<Array<Any>> = UiMode.entries.flatMap { mode ->
            listOf(false, true).map { dark -> arrayOf<Any>(mode, dark) }
        }
    }
}
