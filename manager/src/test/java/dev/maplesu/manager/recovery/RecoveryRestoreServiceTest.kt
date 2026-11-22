package dev.maplesu.manager.recovery

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/** restore full：备份校验 → APK sha → pm install → pm path → hidden OFF；失败 fail-closed。 */
class RecoveryRestoreServiceTest {
    private class FakeRunner : RecoveryCommandRunner {
        val scripts = mutableListOf<String>()
        var handler: (String) -> RecoveryCommandResult = { RecoveryCommandResult(0, "") }

        override fun run(script: String): RecoveryCommandResult {
            scripts += script
            return handler(script)
        }
    }

    private lateinit var dir: File
    private lateinit var bundle: RecoveryBundle
    private lateinit var manifest: RecoveryManifest
    private val runner = FakeRunner()
    private var cleanupCalls = 0
    private var cleanupResult = RecoveryCleanupResult(true, steps = listOf("restore_host_so:ok", "revoke_su_auth:ok"))
    private var finalizeResult = RecoveryCleanupResult(true)
    private var handoverPrepared = false
    private var expectedUid: Int? = 10489
    private var handoverResult = RecoveryCleanupResult(true, steps = listOf("await_manager_confirmation:pending"))

    private fun setUpBundle(awaitConfirmation: Boolean = false): RecoveryRestoreService {
        dir = Files.createTempDirectory("maplesu-restore-").toFile()
        bundle = RecoveryBundle(LocalRecoveryFs(), dir.absolutePath, { 1_000L }, { true })
        // Source APK 必须在备份目录之外：prepare 会先删除备份目录（原子重建）。
        val apk = Files.createTempDirectory("maplesu-restore-src-").toFile()
            .resolve("source.apk").apply { writeBytes(ByteArray(1024) { it.toByte() }) }
        val result = bundle.prepare("dev.maplesu.manager", 1, apk.absolutePath, emptyList(), null)
        manifest = (result as RecoveryPrepareResult.Ok).manifest
        return RecoveryRestoreService(
            bundle = bundle,
            runner = runner,
            packageName = "dev.maplesu.manager",
            apkPath = File(dir, "manager.apk").absolutePath,
            hiddenStatePath = File(dir, "lite_hidden").absolutePath,
            cleanup = { cleanupCalls++; cleanupResult },
            retainedUid = { expectedUid },
            finalizeRestoration = { finalizeResult },
            prepareHandover = if (awaitConfirmation) ({
                handoverPrepared = handoverResult.ok
                handoverResult
            }) else null,
        )
    }

    private fun successHandler(script: String): RecoveryCommandResult = when {
        script.startsWith("sha256sum") -> RecoveryCommandResult(0, manifest.apkSha256 + "  " + dir)
        script.contains("pm install -r ") -> RecoveryCommandResult(0, "Success\n")
        script.startsWith("pm path") -> RecoveryCommandResult(0, "package:/data/app/dev.maplesu.manager/base.apk\n")
        script.contains("MAPLESU_RESTORE_LAUNCHER_OK") -> RecoveryCommandResult(0, "MAPLESU_RESTORE_LAUNCHER_OK\n")
        script.contains("MAPLESU_RESTORE_DATA_OK") -> RecoveryCommandResult(0, "MAPLESU_RESTORE_DATA_OK\n")
        script.contains("MAPLESU_RESTORE_HIDDEN_OFF_OK") -> RecoveryCommandResult(0, "MAPLESU_RESTORE_HIDDEN_OFF_OK\n")
        script.contains("LITE_OK") -> RecoveryCommandResult(0, "LITE_OK\n")
        else -> RecoveryCommandResult(0, "")
    }

    @Test
    fun successRunsAllStepsInOrder() {
        val service = setUpBundle()
        runner.handler = ::successHandler
        val report = service.restoreFull()
        assertTrue(report.ok)
        assertEquals(emptyList<String>(), report.steps.filter { it.endsWith("failed") })
        // verify / apk_sha / apk_stage / pm_install / pm_path / hidden_off
        assertEquals(10, report.steps.size)
        assertTrue(runner.scripts[0].startsWith("sha256sum"))
        // /data/adb 是 adb_data_file，system_server 读不到 → 必须先搬 /data/local/tmp 再装。
        assertTrue(runner.scripts[1].startsWith("cp -f"))
        assertTrue(runner.scripts[1].contains("/data/local/tmp/"))
        assertTrue(runner.scripts[2].contains("pm install -r '/data/local/tmp/"))
        assertTrue(runner.scripts[3].startsWith("rm -f '/data/local/tmp/"))
        assertTrue(runner.scripts[4].startsWith("pm path"))
        assertTrue(runner.scripts[5].contains("LauncherAlias"))
        assertTrue(runner.scripts[6].contains("10489"))
        assertTrue(runner.scripts[7].contains("lite_hidden"))
        assertEquals(1, cleanupCalls)
    }

    @Test
    fun installationReceiptMustWaitForManagerConfirmationBeforeFinalization() {
        val service = setUpBundle(awaitConfirmation = true)
        runner.handler = ::successHandler
        finalizeResult = RecoveryCleanupResult(false, "FINALIZED_BEFORE_MANAGER_CONFIRMATION")
        val report = service.restoreFull()
        assertTrue("installation should leave a retryable handover, not finalize it: $report", report.ok)
        assertTrue(report.steps.contains("await_manager_confirmation:pending"))
        assertTrue(report.awaitingConfirmation)
        assertEquals("host bootstrap must survive an interrupted manager handover", 0, cleanupCalls)
        assertTrue(runner.scripts.single { it.startsWith("am start") }.contains("--ez maplesu_restore true"))
    }

    @Test
    fun blockedActivityLaunchLeavesWebRecoveryPending() {
        val service = setUpBundle(awaitConfirmation = true)
        runner.handler = { script ->
            if (script.startsWith("am start")) RecoveryCommandResult(1, "background launch blocked")
            else successHandler(script)
        }
        val report = service.restoreFull()
        assertTrue(report.ok)
        assertTrue(report.awaitingConfirmation)
        assertTrue(report.steps.contains("launch_manager:pending"))
        assertEquals(0, cleanupCalls)
    }

    @Test
    fun durableHandoverExistsBeforeHiddenOffSoRebootCanResumeRecovery() {
        val service = setUpBundle(awaitConfirmation = true)
        runner.handler = { script ->
            if (script.contains("MAPLESU_RESTORE_HIDDEN_OFF_OK")) {
                assertTrue("hidden OFF without a pending ticket disables UltraRecoveryBoot", handoverPrepared)
            }
            successHandler(script)
        }
        assertTrue(service.restoreFull().ok)
    }

    @Test
    fun handoverWriteFailureNeverClearsHiddenStateOrLaunchesManager() {
        val service = setUpBundle(awaitConfirmation = true)
        handoverResult = RecoveryCleanupResult(false, "RECOVERY_HANDOVER_WRITE_FAILED")
        runner.handler = ::successHandler
        val report = service.restoreFull()
        assertFalse(report.ok)
        assertEquals("RECOVERY_HANDOVER_WRITE_FAILED", report.code)
        assertFalse("failed ticket write must preserve boot recovery", runner.scripts.any {
            it.contains("MAPLESU_RESTORE_HIDDEN_OFF_OK") || it.startsWith("am start")
        })
    }

    @Test
    fun hiddenWriteFailureRetainsThePendingHandoverForRetry() {
        val service = setUpBundle(awaitConfirmation = true)
        runner.handler = { script ->
            if (script.contains("MAPLESU_RESTORE_HIDDEN_OFF_OK")) RecoveryCommandResult(1, "write failure")
            else successHandler(script)
        }
        assertEquals(RestoreCodes.HIDDEN_OFF_FAILED, service.restoreFull().code)
        assertTrue(handoverPrepared)
        assertFalse(runner.scripts.any { it.startsWith("am start") })
        runner.handler = ::successHandler
        assertTrue(service.restoreFull().awaitingConfirmation)
    }

    @Test
    fun tamperedBackupStopsBeforeAnyCommand() {
        val service = setUpBundle()
        File(dir, "manager.apk").writeBytes(byteArrayOf(1, 2, 3))
        val report = service.restoreFull()
        assertFalse(report.ok)
        assertEquals(RestoreCodes.VERIFY_FAILED, report.code)
        assertTrue(runner.scripts.isEmpty())
    }

    @Test
    fun apkShaMismatchBlocksInstall() {
        val service = setUpBundle()
        runner.handler = { script ->
            if (script.startsWith("sha256sum")) RecoveryCommandResult(0, "deadbeef  /x")
            else successHandler(script)
        }
        val report = service.restoreFull()
        assertFalse(report.ok)
        assertEquals(RestoreCodes.APK_SHA_MISMATCH, report.code)
        assertEquals(1, runner.scripts.size)
    }

    @Test
    fun installFailureBlocksPathProbeAndHiddenOff() {
        val service = setUpBundle()
        runner.handler = { script ->
            if (script.contains("pm install -r ")) RecoveryCommandResult(1, "Failure [INSTALL_FAILED]")
            else successHandler(script)
        }
        val report = service.restoreFull()
        assertFalse(report.ok)
        assertEquals(RestoreCodes.APK_INSTALL_FAILED, report.code)
        assertFalse(runner.scripts.any { it.startsWith("pm path") })
        assertFalse(runner.scripts.any { it.contains("lite_hidden") })
    }

    @Test
    fun pathProbeFailureBlocksHiddenOff() {
        val service = setUpBundle()
        runner.handler = { script ->
            if (script.startsWith("pm path")) RecoveryCommandResult(0, "not installed\n")
            else successHandler(script)
        }
        val report = service.restoreFull()
        assertFalse(report.ok)
        assertEquals(RestoreCodes.APK_INSTALL_VERIFY_FAILED, report.code)
        assertFalse(runner.scripts.any { it.contains("lite_hidden") })
    }

    @Test
    fun hiddenOffFailureIsReportedNotSwallowed() {
        val service = setUpBundle()
        runner.handler = { script ->
            // 只让 hidden 状态写入失败；staging/清理也带 LITE_OK，不能误伤。
            if (script.contains("lite_hidden")) RecoveryCommandResult(1, "")
            else successHandler(script)
        }
        val report = service.restoreFull()
        assertFalse(report.ok)
        assertEquals(RestoreCodes.HIDDEN_OFF_FAILED, report.code)
        assertTrue(report.steps.last().startsWith("hidden_off:failed"))
    }

    @Test
    fun unconditionalSuccessMarkerDoesNotProveHiddenStateWasCleared() {
        val service = setUpBundle()
        runner.handler = { script ->
            if (script.contains("lite_hidden")) RecoveryCommandResult(0, "LITE_OK\n")
            else successHandler(script)
        }
        val report = service.restoreFull()
        assertFalse("a shell transport exit code and unconditional echo are not a hidden-state readback", report.ok)
        assertEquals(RestoreCodes.HIDDEN_OFF_FAILED, report.code)
    }

    @Test
    fun cleanupFailurePreservesHiddenStateAndRetryService() {
        val service = setUpBundle()
        cleanupResult = RecoveryCleanupResult(false, "SU_AUTH_REVOKE_FAILED", listOf("restore_host_so:ok", "revoke_su_auth:failed"))
        runner.handler = ::successHandler
        val report = service.restoreFull()
        assertFalse(report.ok)
        assertEquals("SU_AUTH_REVOKE_FAILED", report.code)
        assertTrue(report.steps.contains("restore_host_so:ok"))
        assertFalse(runner.scripts.any { it.contains("lite_hidden") })
    }

    @Test
    fun launcherFailureStopsBeforeTouchingHostOrHiddenState() {
        val service = setUpBundle()
        runner.handler = { script ->
            if (script.contains("LauncherAlias")) RecoveryCommandResult(0, "Success") else successHandler(script)
        }
        val report = service.restoreFull()
        assertFalse(report.ok)
        assertEquals(RestoreCodes.LAUNCHER_FAILED, report.code)
        assertEquals(0, cleanupCalls)
    }

    @Test
    fun retainedDataUidMismatchStopsBeforeHostCleanup() {
        val service = setUpBundle()
        runner.handler = { script ->
            if (script.contains("MAPLESU_RESTORE_DATA_OK")) RecoveryCommandResult(0, "") else successHandler(script)
        }
        val report = service.restoreFull()
        assertFalse(report.ok)
        assertEquals(RestoreCodes.DATA_VERIFY_FAILED, report.code)
        assertEquals(0, cleanupCalls)
    }

    @Test
    fun dataFailureReportsTheSpecificReasonAndRetainsRecovery() {
        val service = setUpBundle(awaitConfirmation = true)
        runner.handler = { script ->
            if (script.contains("MAPLESU_RESTORE_DATA_OK"))
                RecoveryCommandResult(1, "MAPLESU_RESTORE_DATA_FAILED=DATA_PACKAGE_UID_MISMATCH\n")
            else successHandler(script)
        }
        val report = service.restoreFull()
        assertEquals("DATA_PACKAGE_UID_MISMATCH", report.detail)
        assertTrue(report.steps.contains("data:failed(DATA_PACKAGE_UID_MISMATCH)"))
        assertFalse(handoverPrepared)
        assertFalse(runner.scripts.any { it.contains("MAPLESU_RESTORE_HIDDEN_OFF_OK") })
    }

    @Test
    fun invalidRemovalReceiptHasAnExplicitFailedDataStep() {
        val service = setUpBundle(awaitConfirmation = true)
        expectedUid = -1
        runner.handler = ::successHandler
        val report = service.restoreFull()
        assertFalse(report.ok)
        assertEquals("DATA_RECEIPT_INVALID", report.detail)
        assertTrue(report.steps.contains("data:failed(DATA_RECEIPT_INVALID)"))
        assertFalse(handoverPrepared)
    }

    @Test
    fun transientDataPreparationCanSettleWithoutAnotherApkInstall() {
        val service = setUpBundle(awaitConfirmation = true)
        var probes = 0
        runner.handler = { script ->
            if (script.contains("MAPLESU_RESTORE_DATA_OK") && ++probes == 1)
                RecoveryCommandResult(1, "MAPLESU_RESTORE_DATA_FAILED=DATA_DIRECTORY_MISSING\n")
            else successHandler(script)
        }
        assertTrue(service.restoreFull().awaitingConfirmation)
        assertEquals(2, probes)
        assertEquals(1, runner.scripts.count { it.contains("pm install -r ") })
    }

    @Test
    fun actualDataShellAcceptsReassignedUidAndRejectsUnrelatedDataOwner() {
        val service = setUpBundle(awaitConfirmation = true)
        val bash = if (System.getProperty("os.name").startsWith("Windows"))
            File("C:/Program Files/Git/bin/bash.exe") else File("/bin/bash")
        org.junit.Assume.assumeTrue("shell fixture requires bash", bash.isFile)
        val data = File(dir, "data").apply { mkdir() }.absolutePath.replace('\\', '/')
        var owner = 10489
        var dataOutput = ""
        var queryExit = 0
        var packages = "package:dev.maplesu.manager.test uid:10500\\r\\npackage:dev.maplesu.manager uid:10489  \\r\\n"
        runner.handler = { script ->
            if (script.contains("MAPLESU_RESTORE_DATA_OK")) {
                val shell = "stat() { printf '%s\\n' '$owner'; }; " +
                    "pm() { printf '$packages'; return $queryExit; }; restorecon() { return 0; }; " +
                    script.replace("/data/user/0/dev.maplesu.manager", data)
                val fixture = File(dir, "verify-data.sh").apply { writeText(shell) }
                val process = ProcessBuilder(bash.path, "--noprofile", "--norc", fixture.absolutePath.replace('\\', '/'))
                    .redirectErrorStream(true).start()
                val output = process.inputStream.bufferedReader().readText()
                dataOutput = output
                RecoveryCommandResult(process.waitFor(), output)
            } else successHandler(script)
        }
        val restored = service.restoreFull()
        assertTrue("valid retained data must tolerate shell line endings: $restored; $dataOutput", restored.ok)
        owner = 10490
        packages = "package:dev.maplesu.manager uid:10490\\r\\n"
        val migrated = service.restoreFull()
        assertTrue("a reassigned UID with matching installed package and data owner must reach manager handover: $migrated", migrated.ok)
        assertTrue(migrated.awaitingConfirmation)
        assertTrue(migrated.steps.contains("data_uid:ok"))
        assertEquals(0, cleanupCalls)
        packages = "package:dev.maplesu.manager uid:10489\\n"
        val changed = service.restoreFull()
        assertFalse(changed.ok)
        assertEquals("DATA_PACKAGE_UID_MISMATCH", changed.detail)
        owner = 10489
        queryExit = 1
        assertEquals("DATA_PACKAGE_QUERY_FAILED", service.restoreFull().detail)
        queryExit = 0
        packages = "package:devXmaplesuXmanager uid:10489\\n"
        assertEquals("DATA_PACKAGE_QUERY_FAILED", service.restoreFull().detail)
    }

    @Test
    fun failedUidMigrationRetainsBackupsAndNeverClearsHiddenOrPreparesHandover() {
        for (reason in listOf("DATA_DIRECTORY_UNSAFE", "DATA_BACKUP_FAILED",
                "DATA_MIGRATION_FAILED", "DATA_LABEL_RESTORE_FAILED")) {
            val service = setUpBundle(awaitConfirmation = true)
            handoverPrepared = false
            runner.scripts.clear()
            runner.handler = { script ->
                if (script.contains("MAPLESU_RESTORE_DATA_OK")) RecoveryCommandResult(1,
                    "MAPLESU_RESTORE_DATA_BACKUP_OK\nMAPLESU_RESTORE_DATA_FAILED=$reason\n")
                else successHandler(script)
            }
            val report = service.restoreFull()
            assertFalse(reason, report.ok)
            assertEquals(reason, report.detail)
            assertEquals(1, report.steps.count { it == "data_backup:ok" })
            assertEquals(1, runner.scripts.count { it.contains("MAPLESU_RESTORE_DATA_OK") })
            assertFalse(handoverPrepared)
            assertFalse(runner.scripts.any { it.contains("MAPLESU_RESTORE_HIDDEN_OFF_OK") || it.startsWith("am start") })
        }
    }

    @Test
    fun successfulUidMigrationReachesPendingHandoverWithoutDeletingRecoveryIdentity() {
        val service = setUpBundle(awaitConfirmation = true)
        runner.handler = { script ->
            if (script.contains("MAPLESU_RESTORE_DATA_OK")) RecoveryCommandResult(0,
                "MAPLESU_RESTORE_DATA_BACKUP_OK\nMAPLESU_RESTORE_UID_CHANGED\nMAPLESU_RESTORE_DATA_OK\n")
            else successHandler(script)
        }
        val report = service.restoreFull()
        assertTrue(report.ok)
        assertTrue(report.awaitingConfirmation)
        assertTrue(report.steps.containsAll(listOf("data_backup:ok", "data_uid:ok", "data:ok")))
        assertTrue(handoverPrepared)
        assertEquals(0, cleanupCalls)
        assertFalse(runner.scripts.any { it.contains("identity.json") || it.contains("manager-uninstall.receipt") })
    }

    @Test
    fun archiveFailureIsRetryableAndNeverReportsFullRestoration() {
        val service = setUpBundle()
        runner.handler = ::successHandler
        finalizeResult = RecoveryCleanupResult(false, "RESTORED_BACKUP_ARCHIVE_FAILED", listOf("archive_host_backup:failed"))
        val failed = service.restoreFull()
        assertFalse(failed.ok)
        assertEquals("RESTORED_BACKUP_ARCHIVE_FAILED", failed.code)
        assertTrue(failed.steps.contains("archive_host_backup:failed"))
        finalizeResult = RecoveryCleanupResult(true, steps = listOf("archive_host_backup:ok"))
        val retry = service.restoreFull()
        assertTrue(retry.ok)
        assertTrue(retry.steps.contains("archive_host_backup:ok"))
    }

    @Test
    fun diagnosticReceiptRecordsFailureStepWithoutShellOutputOrConfirmationSecrets() {
        val report = RecoveryRestoreReport(false, "SU_AUTH_REVOKE_FAILED",
            listOf("restore_host_so:ok", "revoke_su_auth:failed(secret-token)", "pending:nonce-value"),
            detail = "secret-key", awaitingConfirmation = true)
        assertEquals("MAPLESU_RESTORE phase=confirm ok=false awaiting=true code=SU_AUTH_REVOKE_FAILED " +
            "steps=restore_host_so:ok,revoke_su_auth:failed", report.diagnosticLine(confirmation = true))
    }
}
