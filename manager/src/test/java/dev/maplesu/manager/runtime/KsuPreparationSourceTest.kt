package dev.maplesu.manager.runtime

import java.io.File
import org.junit.Assert.*
import org.junit.Test

/** Source contracts only; PackageManager and Binder behavior still need a device. */
class KsuPreparationSourceTest {
    private val manager = sequenceOf(File("."), File("manager"), File("../manager"))
        .first { File(it, "src/main/java").isDirectory }

    private fun prepare(): String = File(manager,
        "src/main/java/dev/maplesu/manager/runtime/NativeSuDaemon.kt").readText()
        .substringAfter("fun prepareKsu(").substringBefore("fun management(")

    @Test fun normalEnablesItsPrivateDirectoryBeforeTheProviderCall() {
        val body = prepare()
        val enabled = body.indexOf("setComponentEnabledSetting(")
        assertTrue("stock boot can leave the private preparation provider disabled", enabled >= 0)
        assertTrue(enabled < body.indexOf("ProviderCall.call(context.contentResolver,"))
        assertTrue(body.contains("ModeComponentIds.COMPONENT_NATIVE_SU_DIRECTORY_PROVIDER"))
        assertTrue(body.contains("PackageManager.DONT_KILL_APP"))
        assertFalse(body.contains("enableHookComponents("))
        assertFalse(body.contains("COMPONENT_NATIVE_SU_BROKER_SERVICE"))
    }

    @Test fun normalKeepsTheProviderFailureAndRequiresAReply() {
        val body = prepare()
        assertFalse("prepare exceptions must reach the controller's diagnostic outcome",
            body.contains(".getOrNull()"))
        assertTrue(body.contains("SU_KSU_PREPARE_EMPTY_REPLY"))
    }

    @Test fun hookRecoveryOnlyUsesARecordForThisBackendAndKernelBoot() {
        val body = File(manager,
            "src/main/java/dev/maplesu/manager/jailbreak/JailbreakController.kt").readText()
            .substringAfter("val persisted = JailbreakStatus.read(context)")
            .substringBefore("val reproved = NativeSuDaemon.reproveHookOutcome(context)")
        assertTrue(body.contains("persisted.rootBackend == JailbreakRequest.BACKEND_HOOK"))
        assertTrue(body.contains("persisted.bootId == request.bootId"))
    }
}
