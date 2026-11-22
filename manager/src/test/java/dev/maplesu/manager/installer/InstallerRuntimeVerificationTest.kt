package dev.maplesu.manager.installer

import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootExecResult
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class InstallerRuntimeVerificationTest {
    private val boot = "13e48963-f544-4475-a9bb-b56efc91942f"
    private fun result(backend: RootBackend, code: Int = 0, id: String = "0", bootId: String = boot) =
        RootExecResult(backend, code, "$id\n$bootId\n")

    @Test fun ultraAcceptsItsRealUltraBackend() {
        assertTrue(installerRuntimeIdentityVerified(InstallTargetMode.ULTRA, boot, result(RootBackend.ULTRA_ENV)))
    }

    @Test fun normalAcceptsItsKsuBackend() {
        assertTrue(installerRuntimeIdentityVerified(InstallTargetMode.NORMAL, boot, result(RootBackend.KSU)))
    }

    @Test fun anotherRootProviderDoesNotVerifyTheInstalledTarget() {
        assertFalse(installerRuntimeIdentityVerified(InstallTargetMode.ULTRA, boot, result(RootBackend.KSU)))
        assertFalse(installerRuntimeIdentityVerified(InstallTargetMode.NORMAL, boot, result(RootBackend.ULTRA_ENV)))
        assertFalse(installerRuntimeIdentityVerified(InstallTargetMode.ULTRA, boot, result(RootBackend.HOOK)))
    }

    @Test fun unknownTargetOrBootDoesNotBecomeVerified() {
        assertFalse(installerRuntimeIdentityVerified(null, boot, result(RootBackend.ULTRA_ENV)))
        assertFalse(installerRuntimeIdentityVerified(InstallTargetMode.ULTRA, "", result(RootBackend.ULTRA_ENV, bootId = "")))
    }

    @Test fun failedCommandNonRootOrWrongBootDoesNotBecomeVerified() {
        assertFalse(installerRuntimeIdentityVerified(InstallTargetMode.ULTRA, boot, result(RootBackend.ULTRA_ENV, code = 1)))
        assertFalse(installerRuntimeIdentityVerified(InstallTargetMode.ULTRA, boot, result(RootBackend.ULTRA_ENV, id = "2000")))
        assertFalse(installerRuntimeIdentityVerified(InstallTargetMode.ULTRA, boot, result(RootBackend.ULTRA_ENV, bootId = "previous-boot")))
        assertFalse(installerRuntimeIdentityVerified(InstallTargetMode.ULTRA, boot, result(RootBackend.NONE)))
    }

    @Test fun aNeutralReceiptSurvivesAnUnrelatedCurrentModeRecord() {
        assertEquals(InstallTargetMode.ULTRA, installTargetFromRecords("task", listOf(
            "task" to "ultra", "other-task" to "normal")))
        assertNull(installTargetFromRecords("task", listOf("other-task" to "ultra")))
    }

    @Test fun conflictingOrCorruptTargetReceiptsDoNotGuessUltra() {
        assertNull(installTargetFromRecords("task", listOf("task" to "ultra", "task" to "normal")))
        assertNull(installTargetFromRecords("task", listOf("task" to "broken", "task" to "ultra")))
    }

    @Test fun productionVerificationUsesTheRecordedTargetAndRootExec() {
        val source = File("src/main/java/dev/maplesu/manager/installer/InstallerServiceClient.kt").readText()
        val verify = source.substringAfter("fun verifyInstallation(").substringBefore("fun restoreInstallation(")
        assertFalse(verify.contains("MapleSuRuntime.openShell"))
        assertTrue(verify.contains("rootTarget = recordedTarget"))
        assertTrue(verify.contains("RootExec.execute(context,"))
        assertTrue(verify.contains("installerRuntimeIdentityVerified("))
    }
}
