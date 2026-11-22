package dev.maplesu.manager.modules

import java.io.File
import org.junit.Assert.*
import org.junit.Test

/** Complements task behavior tests with the Android entry points that can resubmit work. */
class ModuleOperationWiringTest {
    private fun source(path: String): String = listOf(File("src/main/$path"), File("manager/src/main/$path"))
        .first { it.isFile }.readText()

    @Test fun installationAndUserScriptEntrypointsRunThroughTheForegroundOwner() {
        val flash = source("java/com/maplesu/core/ui/screen/flash/FlashUtils.kt")
            .substringAfter("is FlashIt.FlashModules -> {").substringBefore("FlashIt.FlashRestore ->")
        assertTrue(flash.contains("ModuleOperationService.run(ksuApp)"))
        assertTrue(flash.indexOf("ModuleOperationService.run") < flash.indexOf("flashModulesSequentially("))
        val action = source("java/com/maplesu/core/ui/screen/executemoduleaction/ExecuteModuleActionViewModel.kt")
        assertTrue(action.contains("ModuleOperationService.run(ksuApp)"))
        assertTrue(action.contains("ModuleActionStart.RESTORED_RUNNING"))
    }

    @Test fun restoringBeforeTheFirstLogLineDoesNotResubmitAnInstall() {
        val effect = source("java/com/maplesu/core/ui/screen/flash/FlashUtils.kt").substringAfter("fun FlashEffect(")
        assertTrue(effect.contains("moduleOperationStarted by rememberSaveable(flashIt)"))
        val restored = effect.indexOf("if (flashIt is FlashIt.FlashModules && moduleOperationStarted)")
        val invoke = effect.indexOf("flashIt(flashIt, onStdout")
        assertTrue(restored >= 0 && invoke > restored)
        val guard = effect.substring(restored, invoke)
        assertTrue(guard.contains("R.string.module_operation_interrupted"))
        assertTrue(guard.contains("onFlashingStatusChange(FlashingStatus.PENDING)"))
        assertTrue(guard.contains("return@LaunchedEffect"))
    }

    @Test fun theServiceStopsAtCompletionAndHasNoRestartOrExportedEntrypoint() {
        val service = source("java/dev/maplesu/manager/modules/ModuleOperationService.kt")
        assertTrue(service.contains("task.start(scope)"))
        assertTrue(service.contains("job.invokeOnCompletion"))
        assertTrue(service.contains("stopSelfResult(latestStartId)"))
        assertTrue(service.contains("scope.cancel()"))
        assertTrue(service.contains("return START_NOT_STICKY"))
        assertFalse(service.contains("START_REDELIVER_INTENT"))
        val declaration = source("AndroidManifest.xml").substringAfter("android:name=\"dev.maplesu.manager.modules.ModuleOperationService\"")
            .substringBefore("</service>")
        assertTrue(declaration.contains("android:exported=\"false\""))
        assertTrue(declaration.contains("android:foregroundServiceType=\"specialUse\""))
    }
}
