package dev.maplesu.manager.recovery

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** FullHideTransaction：固定步骤名/顺序、失败回滚、boot persistence 未证明即拒绝卸载。 */
class FullHideTransactionTest {
    private class Harness(
        var prepareResult: RecoveryPrepareResult = RecoveryPrepareResult.Ok(sampleManifest()),
        var daemonResult: DaemonVerification = DaemonVerification(true, true, 18427),
        var backupShaOk: Boolean = true,
        var hiddenWriteOk: Boolean = true,
        var uninstallCode: Int = 0,
    ) {
        var prepareCalls = 0
        var daemonCalls = 0
        var uninstallCalls = 0
        var stopDaemonCalls = 0
        var clearBackupCalls = 0
        val hiddenWrites = mutableListOf<Boolean>()

        fun transaction(persistence: BootPersistenceEvidence = BootPersistenceEvidence.UNPROVEN) =
            FullHideTransaction(
                prepare = {
                    prepareCalls++
                    prepareResult
                },
                startDaemon = {
                    daemonCalls++
                    daemonResult
                },
                verifyBackupSha = { backupShaOk },
                writeHidden = { enabled ->
                    hiddenWrites += enabled
                    hiddenWriteOk
                },
                uninstall = {
                    uninstallCalls++
                    RecoveryCommandResult(uninstallCode, if (uninstallCode == 0) "Success" else "Failure")
                },
                stopDaemon = { stopDaemonCalls++ },
                clearBackup = { clearBackupCalls++ },
                bootPersistence = persistence,
            )
    }

    private fun proven() = BootPersistenceEvidence(true, "device-probe:reboot-ping", "verified")

    @Test
    fun stepNamesAreFixedAndOrdered() {
        val harness = Harness()
        val result = harness.transaction(proven()).activate()
        assertTrue(result.ok)
        assertEquals(
            listOf(
                "backup", "webui_start", "webui_ping", "backup_sha",
                "boot_persistence", "hide_state", "uninstall_apk",
            ),
            result.steps.map { it.step },
        )
        assertTrue(result.steps.all { it.ok })
        assertEquals(1, harness.uninstallCalls)
    }

    @Test
    fun unprovenBootPersistenceFailsBeforeHideAndUninstall() {
        val harness = Harness()
        val result = harness.transaction().activate()
        assertFalse(result.ok)
        assertEquals(ActivationCodes.BOOT_PERSISTENCE_UNPROVEN, result.code)
        val bootStep = result.steps.first { it.step == "boot_persistence" }
        assertFalse(bootStep.ok)
        assertEquals(BootPersistenceEvidence.UNPROVEN_CODE, bootStep.reason)
        assertEquals(0, harness.uninstallCalls)
        assertTrue(harness.hiddenWrites.none { it })
        // 回滚步骤存在，且 daemon/备份被清理。
        assertTrue(result.steps.any { it.step == "rollback_webui_stop" })
        assertEquals(1, harness.stopDaemonCalls)
        assertEquals(1, harness.clearBackupCalls)
    }

    @Test
    fun backupFailureReturnsBackupStepOnly() {
        val harness = Harness(
            prepareResult = RecoveryPrepareResult.Failed(RecoveryCodes.SHA_READBACK_FAILED, "manager.apk"),
        )
        val result = harness.transaction(proven()).activate()
        assertFalse(result.ok)
        assertEquals(RecoveryCodes.SHA_READBACK_FAILED, result.code)
        assertEquals(listOf("backup"), result.steps.map { it.step })
        assertEquals(0, harness.daemonCalls)
    }

    @Test
    fun daemonStartFailureRollsBackWithoutUninstall() {
        val harness = Harness(daemonResult = DaemonVerification(false, false, null, "START_FAILED"))
        val result = harness.transaction(proven()).activate()
        assertFalse(result.ok)
        assertEquals(ActivationCodes.DAEMON_UNVERIFIED, result.code)
        assertFalse(result.steps.first { it.step == "webui_start" }.ok)
        assertEquals(0, harness.uninstallCalls)
        assertEquals(1, harness.stopDaemonCalls)
    }

    @Test
    fun daemonPingFailureRollsBackWithoutUninstall() {
        val harness = Harness(daemonResult = DaemonVerification(true, false, 18427, "PING_FAILED"))
        val result = harness.transaction(proven()).activate()
        assertFalse(result.ok)
        assertFalse(result.steps.first { it.step == "webui_ping" }.ok)
        assertEquals(0, harness.uninstallCalls)
        assertEquals(1, harness.clearBackupCalls)
    }

    @Test
    fun backupShaMismatchRollsBackWithoutUninstall() {
        val harness = Harness(backupShaOk = false)
        val result = harness.transaction(proven()).activate()
        assertFalse(result.ok)
        assertEquals(ActivationCodes.BACKUP_SHA_MISMATCH, result.code)
        assertEquals(0, harness.uninstallCalls)
        assertTrue(harness.hiddenWrites.none { it })
    }

    @Test
    fun hideOnFailureRollsBackWithoutUninstall() {
        val harness = Harness(hiddenWriteOk = false)
        val result = harness.transaction(proven()).activate()
        assertFalse(result.ok)
        assertEquals(ActivationCodes.HIDDEN_ON_FAILED, result.code)
        assertEquals(0, harness.uninstallCalls)
    }

    @Test
    fun uninstallFailureRollsBackHiddenState() {
        val harness = Harness(uninstallCode = 1)
        val result = harness.transaction(proven()).activate()
        assertFalse(result.ok)
        assertEquals(ActivationCodes.UNINSTALL_FAILED, result.code)
        assertFalse(result.steps.first { it.step == "uninstall_apk" }.ok)
        assertTrue(harness.hiddenWrites.containsAll(listOf(true, false)))
        assertEquals(1, harness.stopDaemonCalls)
        assertEquals(1, harness.clearBackupCalls)
    }

    private companion object {
        fun sampleManifest(): RecoveryManifest = RecoveryManifest(
            packageName = "dev.maplesu.manager",
            versionCode = 1,
            createdAt = 0,
            apkSha256 = "a".repeat(64),
            apkSize = 10,
            items = emptyList(),
        )
    }
}
