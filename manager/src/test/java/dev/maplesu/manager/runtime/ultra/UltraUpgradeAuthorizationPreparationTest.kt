package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.*
import org.junit.Test

class UltraUpgradeAuthorizationPreparationTest {
    private fun receipt() = NativeReceipt.parse("""{"schemaVersion":1,"backend":"maplesu_ultra","bridgeVersion":1,"operation":"install_maplesu_environment","sdkError":"OK","sdkErrorCode":0,"ok":true,"data":{"state":"Running"}}""")!!

    private fun attachments(events: MutableList<String>, failure: String? = null) = UltraEnvironmentInstaller.Attachments(
        whitelist = { UltraSelfWhitelist.Result(true, false, true, false, true) },
        backup = { events += "backup"; "OK" },
        prepareUpgrade = { events += "prepare"; failure?.let { UltraEnvironmentInstaller.Outcome(false, "UPGRADE_PREPARATION_FAILED", reason = it) } },
    )

    private fun port(events: MutableList<String>) = object : UltraEnvironmentInstaller.InstallPort {
        override fun environmentState() = receipt()
        override fun submitInstall(): NativeReceipt { events += "submit"; return receipt() }
    }

    @Test fun currentSdkRestorerIsPreparedBeforeTheUpgradeCanReboot() {
        val events = mutableListOf<String>()
        val outcome = UltraEnvironmentInstaller.install(port(events),
            UltraEnvironmentInstaller.Intent.UpgradeToBundledBuild, attachments(events))
        assertTrue(outcome.ok)
        assertEquals(listOf("prepare", "submit", "backup"), events)
    }

    @Test fun failedPreparationDoesNotSubmitOrLoseTheExistingEnvironment() {
        val events = mutableListOf<String>()
        val outcome = UltraEnvironmentInstaller.install(port(events),
            UltraEnvironmentInstaller.Intent.UpgradeToBundledBuild, attachments(events, "IDENTITY_NOT_READY"))
        assertFalse(outcome.ok)
        assertEquals(listOf("prepare"), events)
        assertEquals("UPGRADE_PREPARATION_FAILED", outcome.sdkError)
    }

    @Test fun normalReopeningDoesNotRedeployTheBootRestorer() {
        val events = mutableListOf<String>()
        val outcome = UltraEnvironmentInstaller.install(port(events),
            UltraEnvironmentInstaller.Intent.ReuseRunning, attachments(events))
        assertTrue(outcome.ok)
        assertEquals(listOf("backup"), events)
    }
}
