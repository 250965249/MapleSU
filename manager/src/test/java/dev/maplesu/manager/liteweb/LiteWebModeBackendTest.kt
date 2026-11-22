package dev.maplesu.manager.liteweb

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 两模式（A=Lite/Ultra、B=KSU）共用同一套 WebUI API：行为一致、diagnostics 字段、boot 证据、dry-run。 */
class LiteWebModeBackendTest {
    private val fixtures = LiteWebTestFixtures
    private val backend = FakeBackend()
    private val handler = fixtures.handler(backend)

    private fun get(path: String) = handler.handle(fixtures.request(target = fixtures.target(path)))

    private fun post(path: String, body: String = "{}") = handler.handle(
        fixtures.request(method = "POST", target = fixtures.target(path), body = body.toByteArray()),
    )

    private fun keysOf(json: String): Set<String> =
        Regex("\"([a-zA-Z0-9_]+)\"\\s*:").findAll(json).map { it.groupValues[1] }.toSet()

    private fun ksuMode(port: Int = 18427) {
        backend.modeBackendValue = FakeModeBackend(
            modeInfo = LiteWebModeInfo(
                mode = "KSU", rootBackend = "KSU", bootHook = LiteWebBootHooks.KSU_MODULE,
                daemonRunning = true, daemonPort = port,
            ),
        )
    }

    @Test
    fun diagnosticsReportsModeRootBackendAndBootHookForLite() {
        val body = get("/api/diagnostics").text()
        assertTrue(body, body.contains("\"mode\":\"LITE\""))
        assertTrue(body, body.contains("\"rootBackend\":\"lite\""))
        assertTrue(body, body.contains("\"bootHook\":\"ULTRA_MODULE\""))
        assertTrue(body, body.contains("\"apkBackupPresent\":true"))
        assertTrue(body, body.contains("\"bootPersistence\":\"proven\""))
    }

    @Test
    fun diagnosticsReportsKsuModeAndHook() {
        ksuMode()
        val body = get("/api/diagnostics").text()
        assertTrue(body, body.contains("\"mode\":\"KSU\""))
        assertTrue(body, body.contains("\"rootBackend\":\"KSU\""))
        assertTrue(body, body.contains("\"bootHook\":\"KSU_MODULE\""))
        assertTrue(body, body.contains("\"apkBackupPresent\":true"))
    }

    @Test
    fun diagnosticsShapeIsIdenticalInBothModes() {
        val lite = keysOf(get("/api/diagnostics").text())
        ksuMode()
        val ksu = keysOf(get("/api/diagnostics").text())
        assertEquals(lite, ksu)
        assertTrue(lite.containsAll(setOf("mode", "rootBackend", "bootHook", "apkBackupPresent", "apkShaValid", "bootPersistence", "webuiPort")))
    }

    @Test
    fun selfCheckShapeHasAllSelfCheckSections() {
        val body = get("/api/selfcheck").text()
        assertTrue(body, body.contains("\"mode\":{"))
        assertTrue(body, body.contains("\"link\":{"))
        assertTrue(body, body.contains("\"backup\":{"))
        assertTrue(body, body.contains("\"bootEvidence\":{"))
        assertTrue(body, body.contains("\"restoreDryRun\":{\"steps\":"))
        assertTrue(body, body.contains("\"daemonRunning\":true"))
        assertTrue(body, body.contains("\"tokenPresent\":true"))
        assertFalse(body, body.contains("演练"))
    }

    @Test
    fun selfCheckShapeIsIdenticalInBothModes() {
        val lite = keysOf(get("/api/selfcheck").text())
        ksuMode()
        val ksu = keysOf(get("/api/selfcheck").text())
        assertEquals(lite, ksu)
    }

    @Test
    fun bootEvidenceIsReflectedInDiagnosticsAndSelfCheck() {
        backend.modeBackendValue = FakeModeBackend(
            boot = LiteWebBootEvidence(
                bootIdObserved = false, persistent = false,
                bootPersistence = LiteWebBootPersistence.UNPROVEN, detail = "no boot hook evidence",
            ),
        )
        val diagnostics = get("/api/diagnostics").text()
        assertTrue(diagnostics, diagnostics.contains("\"bootPersistence\":\"unproven\""))
        val selfCheck = get("/api/selfcheck").text()
        assertTrue(selfCheck, selfCheck.contains("\"bootPersistence\":\"unproven\""))
        assertTrue(selfCheck, selfCheck.contains("\"persistent\":false"))
        assertTrue(selfCheck, selfCheck.contains("\"bootIdObserved\":false"))
    }

    @Test
    fun restoreDryRunListsSamePlanInBothModesWithoutExecuting() {
        val lite = get("/api/restore/dry-run").text()
        for (name in listOf("verifyBackupSha", "unhide", "installApk", "verifyPackageInstalled", "restoreComponents")) {
            assertTrue(lite, lite.contains("\"$name\""))
        }
        ksuMode()
        val ksu = get("/api/restore/dry-run").text()
        assertEquals(lite, ksu)
        assertTrue((backend.modeBackendValue as FakeModeBackend).calls.isEmpty())
    }

    @Test
    fun restoreDryRunUnavailableIsExplicit501() {
        backend.modeBackendValue = UnavailableHiddenModeBackend
        val response = get("/api/restore/dry-run")
        assertEquals(501, response.status)
        assertTrue(response.text(), response.text().contains("MODE_BACKEND_UNAVAILABLE"))
    }

    @Test
    fun daemonStartStopIsModeAgnostic() {
        assertEquals(200, post("/api/daemon/start").status)
        val lite = post("/api/daemon/start")
        assertTrue(lite.text(), lite.text().contains("\"running\":true"))
        assertEquals(200, post("/api/daemon/stop").status)
        ksuMode()
        assertEquals(200, post("/api/daemon/start").status)
        assertTrue(backend.activatePort.hiddenWrites.isEmpty())
    }

    @Test
    fun daemonFailureAndUnavailableAreExplicit() {
        backend.modeBackendValue = FakeModeBackend(
            startStep = LiteWebRestoreStep("startDaemon", false, "BOOT_HOOK_MISSING"),
        )
        val failed = post("/api/daemon/start")
        assertEquals(409, failed.status)
        assertTrue(failed.text(), failed.text().contains("BOOT_HOOK_MISSING"))

        backend.modeBackendValue = UnavailableHiddenModeBackend
        val unavailable = post("/api/daemon/start")
        assertEquals(501, unavailable.status)
        assertTrue(unavailable.text().contains("MODE_BACKEND_UNAVAILABLE"))
    }

    @Test
    fun restoreTransactionExecutesSameStepsInBothModes() {
        val liteBackend = FakeModeBackend()
        val lite = LiteWebModeRestoreTransaction(liteBackend).execute()
        assertEquals(
            listOf("verifyBackupSha", "restoreUnhide", "installApk", "verifyPackage", "restoreComponents"),
            lite.map { it.name },
        )
        assertTrue(lite.all { it.ok })

        val ksuBackend = FakeModeBackend(
            modeInfo = LiteWebModeInfo(mode = "KSU", rootBackend = "KSU", bootHook = LiteWebBootHooks.KSU_MODULE),
        )
        val ksu = LiteWebModeRestoreTransaction(ksuBackend).execute()
        assertEquals(lite.map { it.name }, ksu.map { it.name })
        assertTrue(ksu.all { it.ok })
    }

    @Test
    fun restoreTransactionStopsAtFailureAndBlocksOnInvalidBackup() {
        val failing = FakeModeBackend(
            installStep = LiteWebRestoreStep("installApk", false, "PM_INSTALL_FAILED"),
        )
        val steps = LiteWebModeRestoreTransaction(failing).execute()
        assertEquals(listOf("verifyBackupSha", "restoreUnhide", "installApk"), steps.map { it.name })
        assertTrue(steps.any { it.error == "PM_INSTALL_FAILED" })
        assertFalse(steps.any { it.name == "restoreComponents" })

        val invalid = FakeModeBackend(backupInfo = LiteWebBackupInfo(present = true, shaValid = false))
        val blocked = LiteWebModeRestoreTransaction(invalid).execute()
        assertEquals(listOf("verifyBackupSha"), blocked.map { it.name })
        assertTrue(!blocked.single().ok)
        assertTrue(invalid.calls.isEmpty())
    }

    @Test
    fun unavailableModeBackendSelfCheckIsHonest() {
        backend.modeBackendValue = UnavailableHiddenModeBackend
        val body = get("/api/selfcheck").text()
        assertTrue(body, body.contains("MODE_BACKEND_UNAVAILABLE"))
        assertTrue(body, body.contains("\"bootPersistence\":\"unknown\""))
    }

    @Test
    fun modeBackendIsCheckedByDiagnosticsWithoutHiddenSideEffects() {
        ksuMode()
        get("/api/diagnostics")
        get("/api/selfcheck")
        get("/api/restore/dry-run")
        assertTrue(backend.activatePort.hiddenWrites.isEmpty())
        assertTrue(backend.hiddenRequests.isEmpty())
        assertTrue((backend.modeBackendValue as FakeModeBackend).calls.isEmpty())
    }
}
