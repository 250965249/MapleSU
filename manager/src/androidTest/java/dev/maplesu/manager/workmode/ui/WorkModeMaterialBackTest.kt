package dev.maplesu.manager.workmode.ui

import android.view.KeyEvent
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasContentDescription
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.click
import androidx.compose.ui.unit.dp
import androidx.test.platform.app.InstrumentationRegistry
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.navigation3.Route
import com.maplesu.core.ui.theme.AppSettings
import com.maplesu.core.ui.theme.ColorMode
import com.maplesu.core.ui.theme.KernelSUTheme
import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import top.yukonga.miuix.kmp.nav.core.NavDisplay
import top.yukonga.miuix.kmp.nav.core.rememberNavBackStack

/** Real dialog-window Back delivery under the production NavDisplay; callbacks are fixtures only. */
@RunWith(Parameterized::class)
class WorkModeMaterialBackTest(private val dark: Boolean) {
    @get:Rule val compose = createComposeRule()

    private val show = mutableStateOf(true)
    private val intro = mutableStateOf<WorkMode?>(null)
    private val selected = mutableStateOf(WorkMode.LITE)
    private val dismissible = mutableStateOf(true)
    private var confirms = 0
    private var dismisses = 0
    private var introDismisses = 0
    private var parentBacks = 0
    private var settingsClicks = 0

    @Test fun backClosesIntroductionThenSheetBeforeTheBottomBarReceivesTouches() {
        render()
        compose.onNodeWithText(text(WorkModeStrings.modeNameRes(WorkMode.KSU))).performClick()
        openUltraIntroduction()
        pressSystemBack()
        compose.runOnIdle {
            assertNull(intro.value)
            assertTrue(show.value)
            assertEquals(WorkMode.KSU, selected.value)
            assertEquals(1, introDismisses)
            assertNoUnintendedAction()
        }
        pressSystemBack()
        compose.runOnIdle {
            assertFalse("second Back must dismiss the sheet", show.value)
            assertEquals(1, dismisses)
            assertNoUnintendedAction()
        }
        compose.onNodeWithText(SHEET_TITLE).assertDoesNotExist()
        compose.onNodeWithTag(SETTINGS_TAG).assertIsDisplayed().performTouchInput { click() }
        compose.runOnIdle {
            assertEquals(1, settingsClicks)
            assertEquals(0, confirms)
            assertEquals(0, parentBacks)
        }
    }

    @Test fun pendingStillClosesOnlyTheIntroductionAndConsumesSheetBack() {
        dismissible.value = false
        render()
        openUltraIntroduction()
        pressSystemBack()
        compose.runOnIdle {
            assertNull(intro.value)
            assertEquals(1, introDismisses)
            assertTrue(show.value)
            assertNoUnintendedAction()
        }
        repeat(2) { pressSystemBack() }
        compose.onNodeWithText(SHEET_TITLE).assertIsDisplayed()
        compose.runOnIdle {
            assertTrue(show.value)
            assertEquals(0, dismisses)
            assertNoUnintendedAction()
        }
    }

    private fun render() {
        compose.setContent {
            CompositionLocalProvider(LocalUiMode provides UiMode.Material) {
                KernelSUTheme(AppSettings(
                    if (dark) ColorMode.DARK else ColorMode.LIGHT,
                    0xff6750a4.toInt(), PaletteStyle.TonalSpot, ColorSpec.SpecVersion.SPEC_2025,
                ), UiMode.Material) {
                    // This installs the same entry-scoped dispatcher inherited by the real home sheet.
                    val backStack = rememberNavBackStack<Route>(Route.Main)
                    NavDisplay(backStack = backStack, onBack = { parentBacks += 1 }) {
                        entry<Route.Main> {
                            BackHandler { parentBacks += 1 }
                            Box(Modifier.fillMaxSize()) {
                                Button(
                                    onClick = { settingsClicks += 1 },
                                    modifier = Modifier.align(Alignment.BottomCenter)
                                        .fillMaxWidth().height(64.dp).testTag(SETTINGS_TAG),
                                ) { Text("Fixture settings") }
                            }
                            WorkModeSheetMaterial(
                                show = show.value,
                                ui = WorkModeSheetUi(
                                    title = SHEET_TITLE,
                                    current = WorkMode.LITE,
                                    selected = selected.value,
                                    options = WorkMode.entries.map { WorkModeSheetOption(it) },
                                    confirmText = "Fixture switch",
                                    confirmStyle = when {
                                        !dismissible.value -> WorkModeSheetButtonStyle.LOADING
                                        selected.value == WorkMode.LITE -> WorkModeSheetButtonStyle.DISABLED
                                        else -> WorkModeSheetButtonStyle.PRIMARY
                                    },
                                    note = null, hint = null, dismissible = dismissible.value,
                                ),
                                onSelect = { selected.value = it },
                                onOpenIntro = { intro.value = it },
                                onConfirm = { confirms += 1 },
                                onDismiss = { dismisses += 1; show.value = false },
                            )
                            WorkModeIntroDialogMaterial(intro.value) {
                                introDismisses += 1
                                intro.value = null
                            }
                        }
                    }
                }
            }
        }
        compose.waitForIdle()
        compose.onNodeWithText(SHEET_TITLE).assertIsDisplayed()
    }

    private fun openUltraIntroduction() {
        compose.onNode(
            hasContentDescription(text(R.string.work_mode_intro_action)) and
                hasAnyAncestor(hasText(text(WorkModeStrings.modeNameRes(WorkMode.LITE)))),
        ).performClick()
        compose.waitForIdle()
        compose.runOnIdle { assertEquals(WorkMode.LITE, intro.value) }
    }

    private fun pressSystemBack() {
        // KEYCODE_BACK goes to the focused dialog window, not directly to an Activity dispatcher.
        InstrumentationRegistry.getInstrumentation().sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
        compose.waitForIdle()
    }

    private fun assertNoUnintendedAction() {
        assertEquals(0, confirms)
        assertEquals(0, parentBacks)
        assertEquals(0, settingsClicks)
    }

    private fun text(id: Int) = InstrumentationRegistry.getInstrumentation().targetContext.getString(id)

    companion object {
        private const val SHEET_TITLE = "Fixture target mode"
        private const val SETTINGS_TAG = "fixture-bottom-settings"

        @JvmStatic @Parameterized.Parameters(name = "Material-dark{0}")
        fun appearance(): Collection<Array<Any>> = listOf(arrayOf<Any>(false), arrayOf<Any>(true))
    }
}
