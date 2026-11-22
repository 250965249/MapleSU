package dev.maplesu.manager.workmode.ui

import android.net.Uri
import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.ActivityResultRegistryOwner
import androidx.activity.result.contract.ActivityResultContract
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.core.app.ActivityOptionsCompat
import androidx.test.platform.app.InstrumentationRegistry
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.theme.AppSettings
import com.maplesu.core.ui.theme.ColorMode
import com.maplesu.core.ui.theme.KernelSUTheme
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.service.SwitchOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

/** Exercise the real follow-up dialog without a mode switch, partition write or document provider. */
@RunWith(Parameterized::class)
class WorkModeImageDialogTest(private val uiMode: UiMode) {
    @get:Rule val compose = createComposeRule()

    private var nextDocument: Uri? = null
    private val busy = mutableStateOf(false)
    private val confirmations = mutableListOf<Pair<Uri?, Uri?>>()
    private var dismisses = 0
    private val registry = object : ActivityResultRegistry() {
        override fun <I, O> onLaunch(
            requestCode: Int, contract: ActivityResultContract<I, O>, input: I, options: ActivityOptionsCompat?,
        ) { dispatchResult(requestCode, nextDocument) }
    }
    private val registryOwner = object : ActivityResultRegistryOwner {
        override val activityResultRegistry = registry
    }

    @Test fun normalRequiresBootAndConfirmsOnlyThatDocument() {
        render(WorkMode.KSU, restoreInitBoot = false)
        compose.onNodeWithText(text(R.string.work_mode_images_restore_init_boot)).assertDoesNotExist()
        compose.onNodeWithText(text(R.string.confirm)).assertIsNotEnabled()
        choose(R.string.work_mode_images_boot, BOOT)
        compose.onNodeWithText(text(R.string.confirm)).assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals(listOf(BOOT to null), confirmations) }
    }

    @Test fun ultraRequiresInitBootAndLetsBootRemainEmpty() {
        render(WorkMode.LITE, restoreInitBoot = true)
        compose.onNodeWithText(text(R.string.confirm)).assertIsNotEnabled()
        choose(R.string.work_mode_images_restore_init_boot, INIT_BOOT)
        compose.onNodeWithText(text(R.string.confirm)).assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals(listOf(null to INIT_BOOT), confirmations) }
    }

    @Test fun ultraCanSelectBootThenReturnToTheCurrentPartition() {
        render(WorkMode.LITE, restoreInitBoot = true)
        choose(R.string.work_mode_images_restore_init_boot, INIT_BOOT)
        choose(R.string.work_mode_images_boot_optional, BOOT)
        compose.onNodeWithText(text(R.string.confirm)).performClick()
        compose.onNodeWithText(text(R.string.work_mode_images_use_current)).performClick()
        compose.onNodeWithText(text(R.string.work_mode_images_boot_optional)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.confirm)).performClick()
        compose.runOnIdle { assertEquals(listOf(BOOT to INIT_BOOT, null to INIT_BOOT), confirmations) }
    }

    @Test fun cancellingThePickerKeepsThePreviousSelection() {
        render(WorkMode.KSU, restoreInitBoot = false)
        choose(R.string.work_mode_images_boot, BOOT)
        nextDocument = null
        compose.onNodeWithText("boot.img").performClick()
        compose.onNodeWithText(text(R.string.confirm)).performClick()
        compose.runOnIdle { assertEquals(listOf(BOOT to null), confirmations) }
    }

    @Test fun cancelDoesNotStartTheSwitch() {
        render(WorkMode.KSU, restoreInitBoot = false)
        compose.onNodeWithText(text(R.string.download_cancel)).performClick()
        compose.runOnIdle {
            assertEquals(1, dismisses)
            assertTrue(confirmations.isEmpty())
        }
    }

    @Test fun readingOrSwitchingDisablesEveryAction() {
        render(WorkMode.LITE, restoreInitBoot = true)
        choose(R.string.work_mode_images_restore_init_boot, INIT_BOOT)
        compose.runOnIdle { busy.value = true }
        for (label in listOf(text(R.string.confirm), text(R.string.download_cancel),
            text(R.string.work_mode_images_boot_optional), "init_boot.img")) {
            compose.onNodeWithText(label).assertIsNotEnabled()
        }
        compose.runOnIdle { assertTrue(confirmations.isEmpty()) }
    }

    @Test fun deviceWithoutInitBootCanUseCurrentBootWithoutSelectingDocuments() {
        render(WorkMode.LITE, restoreInitBoot = false)
        compose.onNodeWithText(text(R.string.work_mode_images_restore_init_boot)).assertDoesNotExist()
        compose.onNodeWithText(text(R.string.confirm)).assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals(listOf(null to null), confirmations) }
    }

    private fun render(target: WorkMode, restoreInitBoot: Boolean) {
        compose.setContent {
            CompositionLocalProvider(LocalUiMode provides uiMode,
                LocalActivityResultRegistryOwner provides registryOwner) {
                KernelSUTheme(AppSettings(ColorMode.LIGHT, 0xff6750a4.toInt(), PaletteStyle.TonalSpot,
                    ColorSpec.SpecVersion.SPEC_2025), uiMode) {
                    WorkModeImageDialog(SwitchOutcome.ImagesRequired(target, restoreInitBoot), busy.value, null,
                        onConfirm = { boot, initBoot -> confirmations += boot to initBoot },
                        onDismiss = { dismisses++ })
                }
            }
        }
        compose.onNodeWithText(text(R.string.work_mode_images_title)).assertIsDisplayed()
    }

    private fun choose(label: Int, document: Uri) {
        nextDocument = document
        compose.onNodeWithText(text(label)).performClick()
        compose.onNodeWithText(document.lastPathSegment!!).assertIsDisplayed()
    }

    private fun text(id: Int) = InstrumentationRegistry.getInstrumentation().targetContext.getString(id)

    companion object {
        private val BOOT = Uri.parse("content://switch-fixture/boot.img")
        private val INIT_BOOT = Uri.parse("content://switch-fixture/init_boot.img")

        @JvmStatic @Parameterized.Parameters(name = "{0}")
        fun appearance(): Collection<Array<Any>> = UiMode.entries.map { arrayOf<Any>(it) }
    }
}
