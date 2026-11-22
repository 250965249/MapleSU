package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.*
import org.junit.Test

class UltraEnvironmentInstallRecheckTest {
    @Test fun channelLossAfterTheInitialProbeMustNotSubmitAnInstallation() {
        for (error in listOf("ERR_MODULE_NO_BOOT", "ERR_MODULE_ROOT_KEY", "ERR_MODULE_TEST_CHANNEL",
                             "MAPLESU_SDK_BUSY", "MAPLESU_BRIDGE_CHILD_EXIT")) {
            var submits = 0
            val port = object : UltraEnvironmentInstaller.InstallPort {
                override fun environmentState() = NativeReceipt.parse(
                    """{"backend":"maplesu_ultra","ok":false,"sdkError":"$error","sdkErrorCode":-1001}""")!!
                override fun submitInstall(): NativeReceipt {
                    submits++
                    return NativeReceipt.parse("""{"backend":"maplesu_ultra","ok":true,"sdkError":"OK","sdkErrorCode":0}""")!!
                }
            }
            val result = UltraEnvironmentInstaller.install(port, UltraEnvironmentInstaller.Intent.ReuseRunning,
                UltraEnvironmentInstaller.Attachments(
                    whitelist = { error("failed observation must not authorize") },
                    backup = { error("failed observation must not deploy") },
                ))
            assertFalse("failed recheck must preserve $error", result.ok)
            assertEquals(error, result.sdkError)
            assertEquals(0, submits)
        }
    }

    @Test fun unreadableOrUnknownRecheckNeverTurnsIntoAnInstall() {
        for (state in listOf(null, "Unknown", "NoKey", "Fault")) {
            var submits = 0
            val port = object : UltraEnvironmentInstaller.InstallPort {
                override fun environmentState(): NativeReceipt {
                    if (state == null) error("transport lost")
                    return NativeReceipt.parse("""{"backend":"maplesu_ultra","ok":true,"sdkError":"OK","sdkErrorCode":0,"data":{"state":"$state"}}""")!!
                }
                override fun submitInstall(): NativeReceipt {
                    submits++
                    return NativeReceipt.parse("""{"backend":"maplesu_ultra","ok":true,"sdkError":"OK","sdkErrorCode":0}""")!!
                }
            }
            val result = UltraEnvironmentInstaller.install(port, UltraEnvironmentInstaller.Intent.ReuseRunning,
                UltraEnvironmentInstaller.Attachments(
                    whitelist = { error("unreadable state must not authorize") }, backup = { null }))
            assertFalse(result.ok)
            assertEquals(0, submits)
        }
    }
}
