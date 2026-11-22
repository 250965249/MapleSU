package com.maplesu.core.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Wiring checks supplement the preference policy; gesture rendering still needs device validation. */
class PredictiveBackWiringContractTest {
    private fun source(path: String) = File("src/main/$path").readText()

    @Test fun manifestEnablesApplicationBackCallbacksWithoutAnActivityOverride() {
        val manifest = source("AndroidManifest.xml")
        assertTrue(manifest.substringAfter("<application").substringBefore(">").contains("android:enableOnBackInvokedCallback=\"true\""))
        assertFalse(manifest.substringAfter("<activity").contains("android:enableOnBackInvokedCallback"))
    }

    @Test fun predictivePolicyIsAppliedBeforeRuntimeStartup() {
        val application = source("java/com/maplesu/core/KernelSUApplication.kt")
        val onCreate = application.substringAfter("override fun onCreate()")
        assertTrue(onCreate.indexOf("setEnableOnBackInvokedCallback(applicationInfo, SettingsRepositoryImpl().enablePredictiveBack)") in
            0 until onCreate.indexOf("RootExec.install("))
    }

    @Test fun liveChangesRefreshExistingNavigationInputsAndRestoreTheirState() {
        val activity = source("java/com/maplesu/core/ui/MainActivity.kt")
        assertTrue(activity.contains("LaunchedEffect(uiState.enablePredictiveBack)"))
        assertTrue(activity.contains("val wasEnabled = dispatcher.isEnabled"))
        assertTrue(activity.contains("dispatcher.isEnabled = false"))
        assertTrue(Regex("finally \\{\\s+dispatcher.isEnabled = wasEnabled").containsMatchIn(activity))
        assertFalse(Regex("\\.setOnBackInvokedDispatcher\\s*\\(").containsMatchIn(activity))
    }

    @Test fun predictivePreferenceChangesKeepTheCurrentUiProcess() {
        val screen = source("java/com/maplesu/core/ui/screen/colorpalette/ColorPaletteScreen.kt")
        assertTrue(screen.contains("onSetEnablePredictiveBack = viewModel::setEnablePredictiveBack"))
        assertFalse(screen.contains("restartUiFresh"))
        assertFalse(screen.contains("recreate()"))
        val viewModel = source("java/com/maplesu/core/ui/viewmodel/MainActivityViewModel.kt")
        assertTrue(viewModel.contains("enablePredictiveBack = settingRepo.enablePredictiveBack"))
        assertTrue(viewModel.contains("\"enable_predictive_back\""))
    }

    @Test fun selectingMiuixInitializesMissingEffectsInTheSamePreferenceTransaction() {
        val repository = source("java/com/maplesu/core/data/repository/SettingsRepositoryImpl.kt")
        val selection = repository.substringAfter("override var uiMode:").substringBefore("override var checkUpdate:")
        assertTrue(selection.contains("putString(\"ui_mode\", value)"))
        assertTrue(selection.contains("UiMode.fromValue(value) == UiMode.Miuix"))
        assertTrue(selection.contains("if (!shared.contains(key)) putBoolean(key, true)"))
        assertFalse(selection.contains("remove("))
    }
}
