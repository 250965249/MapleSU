package dev.maplesu.manager.liteweb

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 一键隐藏（activate）/一键恢复（restore）/端口配置/设置/诊断 的 JVM 用例。 */
class LiteWebActivateTest {
    private val fixtures = LiteWebTestFixtures
    private val backend = FakeBackend()
    private val handler = fixtures.handler(backend)

    private fun get(path: String) = handler.handle(fixtures.request(target = fixtures.target(path)))

    private fun post(path: String, body: String) = handler.handle(
        fixtures.request(method = "POST", target = fixtures.target(path), body = body.toByteArray()),
    )

    private fun activate(port: String? = "18437", confirm: String = "true"): LiteWebHttpResponse {
        val portField = if (port == null) "" else ",\"port\":$port"
        return post("/api/activate", "{\"confirm\":$confirm$portField}")
    }

    // ------------------------------------------------------------------ activate

    @Test
    fun activateSuccessRunsTransactionInOrderWithRequestedPort() {
        val response = activate()
        assertEquals(response.text(), 200, response.status)
        assertEquals(18437, backend.activatePort.portValue)
        assertEquals(listOf(true), backend.activatePort.hiddenWrites)
        assertEquals(
            listOf("prepareBackup", "applyPort:18437", "startDaemon", "pingDaemon:18437", "writeHidden:true"),
            backend.activatePort.calls.filter { !it.startsWith("recorded") },
        )
        val body = response.text()
        assertTrue(body, body.contains("\"ok\":true"))
        assertTrue(body, body.contains("\"webuiPort\":18437"))
        assertTrue(body, body.contains("\"recoveryUrlTokenPresent\":true"))
        assertTrue(body, body.contains("\"prepareBackup\""))
        assertTrue(body, body.contains("\"verifyRecovery\""))
    }

    @Test
    fun activateKeepsCurrentPortWhenOmitted() {
        backend.activatePort.portValue = 18427
        val response = post("/api/activate", "{\"confirm\":true}")
        assertEquals(200, response.status)
        assertEquals(listOf<Int?>(null), backend.activatePort.appliedPorts)
    }

    @Test
    fun activateRequiresConfirmTrue() {
        assertEquals(400, post("/api/activate", "{}").status)
        assertEquals(400, post("/api/activate", "{\"confirm\":false}").status)
        assertTrue(backend.activatePort.calls.isEmpty())
    }

    @Test
    fun activateRejectsInvalidPort() {
        assertEquals(400, post("/api/activate", "{\"confirm\":true,\"port\":\"abc\"}").status)
        val response = activate(port = "80")
        assertEquals(409, response.status)
        assertTrue(response.text(), response.text().contains(LiteWebPortPolicy.CODE_RANGE))
        assertTrue(backend.activatePort.calls.isEmpty())
    }

    @Test
    fun activateRejectsWhenBootPersistenceUnprovenWithoutUninstall() {
        backend.activatePort.recoveryStatus = backend.activatePort.recoveryStatus.copy(
            bootPersistence = LiteWebBootPersistence.UNPROVEN,
        )
        val response = activate()
        assertEquals(409, response.status)
        assertTrue(response.text(), response.text().contains("BOOT_PERSISTENCE_UNPROVEN"))
        assertTrue(backend.activatePort.calls.isEmpty())
        assertTrue(backend.activatePort.hiddenWrites.isEmpty())
    }

    @Test
    fun activateRejectsMissingBackup() {
        backend.activatePort.recoveryStatus = backend.activatePort.recoveryStatus.copy(apkBackupPresent = false)
        val response = activate()
        assertEquals(409, response.status)
        assertTrue(response.text().contains("APK_BACKUP_MISSING"))
        assertTrue(backend.activatePort.calls.isEmpty())
    }

    @Test
    fun activateRejectsInvalidBackupSha() {
        backend.activatePort.recoveryStatus = backend.activatePort.recoveryStatus.copy(apkShaValid = false)
        val response = activate()
        assertEquals(409, response.status)
        assertTrue(response.text().contains("APK_BACKUP_SHA_INVALID"))
        assertTrue(backend.activatePort.calls.isEmpty())
    }

    @Test
    fun prepareFailureStopsBeforeAnyMutation() {
        backend.activatePort.prepareStep = LiteWebRestoreStep("prepareBackup", false, "BACKUP_FAILED")
        val response = activate()
        assertEquals(409, response.status)
        assertEquals(listOf("prepareBackup"), backend.activatePort.calls)
        assertTrue(backend.activatePort.hiddenWrites.isEmpty())
        assertTrue(backend.activatePort.appliedPorts.isEmpty())
    }

    @Test
    fun applyPortFailureRollsBackPortAndStops() {
        backend.activatePort.applyStep = LiteWebRestoreStep("applyPort", false, LiteWebPortPolicy.CODE_CONFLICT)
        val response = activate()
        assertEquals(409, response.status)
        assertEquals(listOf("prepareBackup", "applyPort:18437", "revertPort"), backend.activatePort.calls)
        assertTrue(backend.activatePort.hiddenWrites.isEmpty())
        assertTrue(response.text().contains("rollback:revertPort"))
    }

    @Test
    fun daemonStartFailureRollsBack() {
        backend.activatePort.startStep = LiteWebRestoreStep("startDaemon", false, "DAEMON_FAILED")
        val response = activate()
        assertEquals(409, response.status)
        assertTrue(response.text().contains("rollback:revertPort"))
        assertTrue(backend.activatePort.hiddenWrites.isEmpty())
    }

    @Test
    fun pingFailureRollsBackDaemonAndPort() {
        backend.activatePort.pingStep = LiteWebRestoreStep("pingDaemon", false, "PING_FAILED")
        val response = activate()
        assertEquals(409, response.status)
        assertEquals(
            listOf("prepareBackup", "applyPort:18437", "startDaemon", "pingDaemon:18437", "stopDaemon", "revertPort"),
            backend.activatePort.calls,
        )
        assertTrue(backend.activatePort.hiddenWrites.isEmpty())
        assertTrue(response.text().contains("rollbackComplete"))
    }

    @Test
    fun hiddenWriteFailureRollsBackToVisibleState() {
        backend.activatePort.hiddenWriteStep = LiteWebRestoreStep("writeHidden", false, "WRITE_FAILED")
        val response = activate()
        assertEquals(409, response.status)
        assertEquals(listOf(true, false), backend.activatePort.hiddenWrites)
        assertTrue(response.text().contains("rollback:writeHiddenOff"))
    }

    @Test
    fun rollbackFailureIsReportedAsRollbackFailed() {
        backend.activatePort.pingStep = LiteWebRestoreStep("pingDaemon", false, "PING_FAILED")
        backend.activatePort.revertStep = LiteWebRestoreStep("revertPort", false, "REVERT_FAILED")
        val response = activate()
        assertEquals(409, response.status)
        assertTrue(response.text(), response.text().contains("ACTIVATE_ROLLBACK_FAILED"))
    }

    @Test
    fun activateUnavailableBackendIs501() {
        backend.activatePortOverride = UnavailableActivatePort
        val response = activate()
        assertEquals(501, response.status)
        assertTrue(response.text().contains("ACTIVATE_BACKEND_UNAVAILABLE"))
    }

    // ------------------------------------------------------------------ restore

    @Test
    fun restoreFullRunsReinstallThenUnhideThenComponents() {
        backend.restore.needRebootValue = true
        val response = post("/api/restore", "{\"action\":\"full\"}")
        assertEquals(200, response.status)
        assertEquals(
            listOf("verifyBackupSha", "installApk", "verifyPackageInstalled", "writeHidden:false", "restoreComponents", "verify"),
            backend.restore.calls,
        )
        val body = response.text()
        assertTrue(body, body.contains("\"ok\":true"))
        assertTrue(body, body.contains("\"needReboot\":true"))
        assertTrue(body, body.contains("\"installApk\""))
    }

    @Test
    fun restoreFullFailureIsFailClosed() {
        backend.restore.installStep = LiteWebRestoreStep("installApk", false, "PM_INSTALL_FAILED")
        val response = post("/api/restore", "{\"action\":\"full\"}")
        assertEquals(409, response.status)
        val body = response.text()
        assertTrue(body, body.contains("\"ok\":false"))
        assertTrue(body, body.contains("PM_INSTALL_FAILED"))
        assertFalse(body, body.contains("restoreComponents"))
        assertTrue(backend.restore.hiddenWrites.none { it })
    }

    @Test
    fun restoreIsIdempotent() {
        val first = post("/api/restore", "{\"action\":\"full\"}")
        val second = post("/api/restore", "{\"action\":\"full\"}")
        assertEquals(200, first.status)
        assertEquals(200, second.status)
        assertEquals(2, backend.restore.calls.count { it == "installApk" })
    }

    @Test
    fun restoreUnhideActionOnlyTouchesHiddenFlag() {
        val response = post("/api/restore", "{\"action\":\"unhide\"}")
        assertEquals(200, response.status)
        assertEquals(listOf("writeHidden:false", "verify"), backend.restore.calls)
    }

    @Test
    fun restoreUnavailableBackendIs501() {
        backend.restore.hiddenWriteStep = LiteWebRestoreStep("writeHidden", false, LiteWebRecoveryCodes.RESTORE_BACKEND_UNAVAILABLE)
        backend.restore.verifyStep = LiteWebRestoreStep("verify", false, LiteWebRecoveryCodes.RESTORE_BACKEND_UNAVAILABLE)
        val response = post("/api/restore", "{\"action\":\"unhide\"}")
        assertEquals(501, response.status)
        assertTrue(response.text().contains("NOT_IMPLEMENTED"))
    }

    @Test
    fun restoreRejectsInvalidAction() {
        assertEquals(400, post("/api/restore", "{\"action\":\"drill\"}").status)
        assertEquals(400, post("/api/restore", "{}").status)
        assertTrue(backend.restore.calls.isEmpty())
    }

    // ------------------------------------------------------------------ config / token

    @Test
    fun configPortUsesWebuiPortWithLegacyAlias() {
        val body = get("/api/config/port").text()
        assertTrue(body, body.contains("\"webuiPort\":18427"))
        assertTrue(body, body.contains("\"recoveryPort\":18427"))
    }

    @Test
    fun configPortSetRestartsAndReadsBack() {
        backend.configuredPort = 18437
        val response = post("/api/config/port", "{\"webuiPort\":18437}")
        assertEquals(response.text(), 200, response.status)
        assertEquals(listOf<Int?>(18437), backend.activatePort.appliedPorts)
        assertTrue(response.text(), response.text().contains("\"webuiPort\":18437"))
        assertTrue(response.text(), response.text().contains("\"recoveryPort\":18437"))
    }

    @Test
    fun configPortRejectsRangeAndMissingValue() {
        assertEquals(400, post("/api/config/port", "{\"webuiPort\":80}").status)
        assertEquals(400, post("/api/config/port", "{\"webuiPort\":70000}").status)
        assertEquals(400, post("/api/config/port", "{}").status)
        assertTrue(backend.activatePort.appliedPorts.isEmpty())
    }

    @Test
    fun configPortConflictIs409() {
        backend.activatePort.applyStep = LiteWebRestoreStep("applyPort", false, LiteWebPortPolicy.CODE_CONFLICT)
        val response = post("/api/config/port", "{\"webuiPort\":18437}")
        assertEquals(409, response.status)
        assertTrue(response.text().contains(LiteWebPortPolicy.CODE_CONFLICT))
    }

    @Test
    fun tokenResetUnavailableIs501AndSuccessIs200() {
        assertEquals(501, post("/api/config/token/reset", "{}").status)
        backend.resetTokenStep = LiteWebTestFixtures.ok("resetToken")
        assertEquals(200, post("/api/config/token/reset", "{}").status)
    }

    // ------------------------------------------------------------------ settings / diagnostics / workmode / module action

    @Test
    fun settingsGetAndWhitelistedWrite() {
        assertEquals(200, get("/api/settings").status)
        val response = post("/api/settings", "{\"theme\":\"dark\",\"snow\":\"true\"}")
        assertEquals(200, response.status)
        assertEquals(listOf("snow" to "true", "theme" to "dark"), backend.settings.writes.sortedBy { it.first })
        assertTrue(response.text(), response.text().contains("\"theme\":\"dark\""))
    }

    @Test
    fun settingsForbiddenRootKeysAre403() {
        val response = post("/api/settings", "{\"root\":\"true\"}")
        assertEquals(403, response.status)
        assertTrue(response.text().contains("SETTINGS_KEY_FORBIDDEN"))
        assertTrue(backend.settings.writes.isEmpty())
    }

    @Test
    fun settingsRejectsBadValuesAndUnavailableBackend() {
        assertEquals(400, post("/api/settings", "{\"snow\":\"maybe\"}").status)
        backend.settings.unavailable = true
        assertEquals(501, post("/api/settings", "{\"theme\":\"dark\"}").status)
    }

    @Test
    fun diagnosticsReportsRecoveryFacts() {
        val body = get("/api/diagnostics").text()
        assertTrue(body, body.contains("\"rootBackend\":\"lite\""))
        assertTrue(body, body.contains("\"webuiPort\":18427"))
        assertTrue(body, body.contains("\"apkBackupPresent\":true"))
        assertTrue(body, body.contains("\"apkShaValid\":true"))
        assertTrue(body, body.contains("\"daemonUptimeSeconds\":12"))
        assertTrue(body, body.contains("\"bootPersistence\":\"proven\""))
        assertFalse(body, body.contains("演练"))
    }

    @Test
    fun workModeIsReadOnly() {
        val body = get("/api/workmode").text()
        assertTrue(body, body.contains("\"mode\":\"LITE\""))
        assertTrue(body, body.contains("\"canSwitch\":false"))
        assertTrue(body, body.contains("MODE_SWITCH_READ_ONLY"))
    }

    @Test
    fun moduleActionUnavailableIs501AndOkIs200() {
        assertEquals(501, post("/api/module/action", "{\"id\":\"m1\",\"action\":\"service\"}").status)
        backend.moduleActionResult = LiteWebModuleActionResult.Ok("m1", "service", "done")
        val response = post("/api/module/action", "{\"id\":\"m1\",\"action\":\"service\"}")
        assertEquals(200, response.status)
        assertTrue(response.text(), response.text().contains("\"output\":\"done\""))
    }

    @Test
    fun moduleActionFailsClosed() {
        backend.moduleActionResult = LiteWebModuleActionResult.Failed("ACTION_FAILED", "exit=1")
        val response = post("/api/module/action", "{\"id\":\"m1\",\"action\":\"service\"}")
        assertEquals(409, response.status)
        assertTrue(response.text().contains("ACTION_FAILED"))
    }

    @Test
    fun noDrillOrTestRecoveryFieldsAnywhere() {
        for (path in listOf("/api/hidden", "/api/diagnostics", "/api/status")) {
            val body = get(path).text()
            assertFalse(path, body.contains("演练"))
            assertFalse(path, body.contains("drill"))
            assertFalse(path, body.contains("selfTest"))
        }
    }
}
