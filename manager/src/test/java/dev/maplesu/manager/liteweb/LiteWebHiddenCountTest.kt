package dev.maplesu.manager.liteweb

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** H2 追加契约：moduleCount 解析、隐藏开关、列表形状、/modweb 501。 */
class LiteWebHiddenCountTest {
    private val fixtures = LiteWebTestFixtures
    private val backend = FakeBackend()
    private val handler = fixtures.handler(backend)

    private fun get(path: String) = handler.handle(fixtures.request(target = fixtures.target(path)))

    private fun post(path: String, body: String) = handler.handle(
        fixtures.request(method = "POST", target = fixtures.target(path), body = body.toByteArray()),
    )

    // ------------------------------------------------------------------ moduleCount（顶层数组）

    @Test
    fun emptyModuleArrayCountsZeroWithoutError() {
        val parsed = LiteWebModuleList.count("[]")
        assertEquals(0, parsed.count)
        assertEquals("", parsed.error)
    }

    @Test
    fun oneAndManyModulesAreCounted() {
        assertEquals(1, LiteWebModuleList.count("[{\"id\":\"m1\"}]").count)
        val many = LiteWebModuleList.count(
            "[{\"id\":\"m1\",\"name\":\"a,b\"},{\"id\":\"m2\"},{\"id\":\"m3\",\"nested\":{\"x\":[1,2]}}]",
        )
        assertEquals(3, many.count)
        assertEquals("", many.error)
    }

    @Test
    fun legacyObjectWithModulesFieldIsCounted() {
        assertEquals(2, LiteWebModuleList.count("{\"modules\":[{\"id\":\"a\"},{\"id\":\"b\"}]}").count)
    }

    @Test
    fun malformedModuleJsonIsZeroWithErrorFlag() {
        val parsed = LiteWebModuleList.count("[{\"id\":")
        assertEquals(0, parsed.count)
        assertEquals("INVALID_JSON", parsed.error)
        assertEquals("INVALID_JSON", LiteWebModuleList.count("not-json").error)
        assertEquals("EMPTY_RESPONSE", LiteWebModuleList.count("  ").error)
        assertEquals("MODULES_FIELD_MISSING", LiteWebModuleList.count("{\"other\":1}").error)
    }

    @Test
    fun statusReportsModuleCountAndErrorFlag() {
        backend.statusValue = LiteWebStatusView(rootAvailable = true, moduleCount = 5)
        val body = get("/api/status").text()
        assertTrue(body, body.contains("\"moduleCount\":5"))
        assertTrue(body, !body.contains("moduleCountError"))
        backend.statusValue = LiteWebStatusView(
            rootAvailable = true, moduleCount = 0, moduleCountError = "INVALID_JSON",
        )
        val errorBody = get("/api/status").text()
        assertTrue(errorBody, errorBody.contains("\"moduleCount\":0"))
        assertTrue(errorBody, errorBody.contains("\"moduleCountError\":\"INVALID_JSON\""))
    }

    @Test
    fun androidStyleTopLevelArrayCountsRealModules() {
        // 与 LiteScriptModuleBackend.listJson() 一致的顶层数组形状（不是 {"modules":[...]}）。
        val listJson = "[{\"id\":\"a\",\"name\":\"A\"},{\"id\":\"b\",\"name\":\"B\"}]"
        assertEquals(2, LiteWebModuleList.count(listJson).count)
        assertEquals(2, LiteWebModuleList.count("[\n {\"id\":\"a\"},\n {\"id\":\"b\"}\n]").count)
    }

    // ------------------------------------------------------------------ hidden

    @Test
    fun statusUsesLiveHiddenPortWhenAvailable() {
        backend.statusValue = LiteWebStatusView(rootAvailable = true, moduleCount = 1, hidden = false)
        backend.hiddenValue = true
        val body = get("/api/status").text()
        assertTrue(body, body.contains("\"hidden\":true"))
    }

    @Test
    fun statusFallsBackToBackendHiddenWhenPortUnavailable() {
        backend.hiddenValue = null
        backend.statusValue = LiteWebStatusView(rootAvailable = true, moduleCount = 1, hidden = true)
        assertTrue(get("/api/status").text().contains("\"hidden\":true"))
    }

    @Test
    fun hiddenGetReportsWebuiPortAndRecoveryFacts() {
        backend.hiddenValue = null
        backend.activatePort.recoveryStatus = LiteWebRecoveryStatus(
            apkBackupPresent = true, apkShaValid = true, daemonRunning = true,
            bootPersistence = LiteWebBootPersistence.PROVEN,
        )
        backend.activatePort.portValue = 18437
        val body = get("/api/hidden").text()
        assertTrue(body, body.contains("\"webuiPort\":18437"))
        assertTrue(body, body.contains("\"apkBackupPresent\":true"))
        assertTrue(body, body.contains("\"apkShaValid\":true"))
        assertTrue(body, body.contains("\"daemonRunning\":true"))
        assertTrue(body, body.contains("\"bootPersistence\":\"proven\""))
        assertTrue(body, !body.contains("演练"))
        assertTrue(body, !body.contains("drill"))
    }

    @Test
    fun hiddenEnableTrueMustGoThroughActivate() {
        val response = post("/api/hidden", "{\"enable\":\"1\"}")
        assertEquals(409, response.status)
        assertTrue(response.text(), response.text().contains("USE_ACTIVATE_API"))
        assertTrue(backend.hiddenRequests.isEmpty())
    }

    @Test
    fun hiddenDisableRunsFullUnhideAndDoesNotReinstall() {
        // 2026-10-31 真机缺陷 2：`{enable:false}` 必须走**完整解除寄生**四步，
        // 不再只是"写 hidden=OFF"，也不再依赖未接线的 restorePort。
        backend.unhide = LiteWebUnhidePort {
            listOf(
                LiteWebRestoreStep(LiteWebUnhideSteps.RESTORE_HOST_SO, true, detail = "restored=45"),
                LiteWebRestoreStep(LiteWebUnhideSteps.REMOVE_LOADER, true, detail = "loader=absent"),
                LiteWebRestoreStep(LiteWebUnhideSteps.REVOKE_SU_AUTH, true, detail = "sdk=ok"),
                LiteWebRestoreStep(LiteWebUnhideSteps.STOP_DAEMON, true, detail = "exit_after_response"),
            )
        }
        val response = post("/api/hidden", "{\"enable\":\"0\"}")
        assertEquals(200, response.status)
        val body = response.text()
        assertTrue(body, body.contains("\"ok\":true"))
        assertTrue(body, body.contains("\"restore_host_so\""))
        assertTrue(body, body.contains("\"remove_loader\""))
        assertTrue(body, body.contains("\"revoke_su_auth\""))
        assertTrue(body, body.contains("\"stop_daemon\""))
        assertTrue(body, body.contains("\"failedStep\":\"\""))
        assertTrue(body, body.contains("\"retryable\":false"))
        // 解除寄生绝不能顺手重装 APK / 走 restore 事务。
        assertTrue("unhide 不能调用 restore 事务：${backend.restore.calls}", backend.restore.calls.isEmpty())
    }

    @Test
    fun hiddenDisableStepFailureIs409WithFailedStepAndNoFakeSuccess() {
        backend.unhide = LiteWebUnhidePort {
            listOf(
                LiteWebRestoreStep(LiteWebUnhideSteps.RESTORE_HOST_SO, true),
                LiteWebRestoreStep(LiteWebUnhideSteps.REMOVE_LOADER, true),
                LiteWebRestoreStep(
                    LiteWebUnhideSteps.REVOKE_SU_AUTH,
                    false,
                    LiteWebUnhideCodes.SU_AUTH_REVOKE_FAILED,
                    "still_listed",
                ),
                // 失败即停：停在 daemon 之前，保留重试入口。
            )
        }
        val response = post("/api/hidden", "{\"enable\":false}")
        assertEquals(409, response.status)
        val body = response.text()
        assertTrue(body, body.contains("\"ok\":false"))
        assertTrue(body, body.contains("\"hidden\":true"))
        assertTrue(body, body.contains("\"failedStep\":\"revoke_su_auth\""))
        assertTrue(body, body.contains("\"code\":\"HIDDEN_SU_AUTH_REVOKE_FAILED\""))
        assertTrue(body, body.contains("\"retryable\":true"))
        assertFalse("失败时绝不能出现 stop_daemon 已执行", body.contains("\"name\":\"stop_daemon\""))
    }

    @Test
    fun hiddenDisableDaemonStopFailureIs409() {
        backend.unhide = LiteWebUnhidePort {
            listOf(
                LiteWebRestoreStep(LiteWebUnhideSteps.RESTORE_HOST_SO, true),
                LiteWebRestoreStep(LiteWebUnhideSteps.REMOVE_LOADER, true),
                LiteWebRestoreStep(LiteWebUnhideSteps.REVOKE_SU_AUTH, true),
                LiteWebRestoreStep(
                    LiteWebUnhideSteps.STOP_DAEMON,
                    false,
                    LiteWebUnhideCodes.DAEMON_STOP_FAILED,
                    "exit_not_scheduled",
                ),
            )
        }
        val response = post("/api/hidden", "{\"enable\":\"0\"}")
        assertEquals(409, response.status)
        val body = response.text()
        assertTrue(body, body.contains("\"failedStep\":\"stop_daemon\""))
        assertTrue(body, body.contains("LITEWEB_DAEMON_STOP_FAILED"))
    }

    @Test
    fun hiddenDisableWithoutTokenIs401() {
        val wrong = "/${fixtures.PREFIX}/${"c".repeat(LiteWebConstants.TOKEN_HEX_LENGTH)}/api/hidden"
        val response = handler.handle(
            fixtures.request(method = "POST", target = wrong, body = "{\"enable\":false}".toByteArray()),
        )
        assertEquals(401, response.status)
        assertTrue(backend.hiddenRequests.isEmpty())
    }

    @Test
    fun hiddenDisableUnavailableIs501NotFakeSuccess() {
        // 后端完全未接线（默认 UnavailableUnhidePort）→ 501，绝不 200。
        val response = post("/api/hidden", "{\"enable\":false}")
        assertEquals(501, response.status)
        assertTrue(response.text(), response.text().contains("NOT_IMPLEMENTED"))
        assertTrue(response.text(), response.text().contains("RESTORE_BACKEND_UNAVAILABLE"))
    }

    @Test
    fun hiddenRejectsInvalidBodies() {
        assertEquals(400, post("/api/hidden", "not-json").status)
        assertEquals(400, post("/api/hidden", "{}").status)
        assertEquals(400, post("/api/hidden", "{\"enable\":\"maybe\"}").status)
        assertTrue(backend.hiddenRequests.isEmpty())
    }

    // ------------------------------------------------------------------ list shapes / modweb

    @Test
    fun modulesEndpointIsAnArray() {
        val body = get("/api/modules").text().trim()
        assertTrue(body, body.startsWith("["))
        assertTrue(body, body.endsWith("]"))
    }

    @Test
    fun superusersEndpointIsReadOnlyUidArray() {
        backend.superusers = "[{\"uid\":10200,\"allowed\":true},{\"uid\":1000,\"allowed\":false}]"
        val body = get("/api/superusers").text().trim()
        assertTrue(body, body.startsWith("["))
        assertTrue(body, body.contains("\"uid\":10200"))
    }

    @Test
    fun modwebIs501WithReasonWhenBackendIsUnwired() {
        // v2：/modweb/<id>/ 已实现；后端没接线（这里是 FakeBackend 默认值之外的显式不可用）
        // 仍要 501 + 原因，绝不伪装成 404。
        backend.moduleWebUnavailable = "MODULE_WEB_BACKEND_UNAVAILABLE"
        val response = handler.handle(fixtures.request(target = fixtures.target("/modweb/tee/index.html")))
        assertEquals(501, response.status)
        assertTrue(response.text(), response.text().contains("MODWEB_PROXY_UNAVAILABLE"))
        assertTrue(response.text(), response.text().contains("MODULE_WEB_BACKEND_UNAVAILABLE"))
    }

    @Test
    fun modwebWithoutIdIs400NotSilent404() {
        val response = handler.handle(fixtures.request(target = fixtures.target("/modweb")))
        assertEquals(400, response.status)
        assertTrue(response.text(), response.text().contains("MODWEB_ID_MISSING"))
    }

    @Test
    fun sulogShapeStaysContract() {
        backend.sulogValue = LiteWebSulogView(false, reason = "unsupported")
        val body = get("/api/sulog").text()
        assertTrue(body, body.contains("\"available\":false"))
        assertTrue(body, body.contains("\"lines\":[]"))
        assertTrue(body, body.contains("\"reason\":\"unsupported\""))
    }

    @Test
    fun moduleCountParserHandlesStringsWithBrackets() {
        assertEquals(1, LiteWebModuleList.count("[{\"name\":\"a]b,c\"}]").count)
        assertEquals(2, LiteWebModuleList.count("[{\"name\":\"[x]\"},{\"name\":\"y\"}]").count)
    }

    @Test
    fun statusStillHasFrontendFields() {
        val body = get("/api/status").text()
        for (field in listOf("mode", "root", "moduleCount", "hidden", "uapi", "serverVersion")) {
            assertTrue("missing $field in $body", body.contains("\"$field\":"))
        }
        assertTrue(body.contains("\"uapi\":\"lite\""))
        assertNotNull(LiteWebConstants.SERVER_VERSION)
    }
}
