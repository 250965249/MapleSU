package dev.maplesu.manager.liteweb

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LiteWebSuperuserHandlerTest {
    private val port = HandlerSuPort()
    private var modules = "[]"
    private val backend = object : LiteWebBackend {
        override fun status() = LiteWebStatusView(rootAvailable = true, moduleCount = 0)
        override fun modulesJson(): String = modules
        override fun superusersJson(): String = error("SDK port must handle legacy lists too")
        override fun superuserPort(): LiteWebSuperuserPort = port
        override fun sulog() = LiteWebSulogView(false)
        override fun toggleModule(moduleId: String, enabled: Boolean) = LiteWebToggleView.Unavailable("unused")
        override fun assets() = FakeAssets()
    }
    private val handler = LiteWebRequestHandler({ LiteWebTestFixtures.TOKEN }, backend)

    private fun get(path: String) = handler.handle(LiteWebTestFixtures.request(target = LiteWebTestFixtures.target(path)))
    private fun post(path: String, body: String, json: Boolean = true): LiteWebHttpResponse {
        val request = LiteWebTestFixtures.request(method = "POST", target = LiteWebTestFixtures.target(path), body = body.toByteArray())
        return handler.handle(if (json) request.copy(headers = request.headers + ("Content-Type" to "application/json; charset=utf-8")) else request)
    }

    @Test fun completeCatalogUsesGlobalCapabilitiesAndLegacyRemainsArray() {
        val current = get("/api/superuser")
        assertEquals(200, current.status)
        assertTrue(current.text().contains("\"scope\":\"package-global\""))
        assertTrue(current.text().contains("\"expiry\":false"))
        assertTrue(get("/api/superusers").text().startsWith("["))
        assertFalse(current.text().contains(LiteWebTestFixtures.TOKEN))
    }

    @Test fun unreadableBackendFailsBothNewAndLegacyRoutes() {
        port.failure = LiteWebSuResult.Failed("SU_AUTH_LIST_UNREADABLE", unavailable = true)
        for (path in listOf("/api/superuser", "/api/superusers")) {
            val response = get(path)
            assertEquals(503, response.status)
            assertTrue(response.text().contains("SU_AUTH_LIST_UNREADABLE"))
            assertFalse(response.text().contains("\"apps\":[]"))
        }
    }

    @Test fun grantRequiresExplicitConfirmationAndJsonAndRejectsUnsupportedProfileFields() {
        val body = "{\"packageName\":\"com.example.app\",\"allow\":true,\"confirm\":true}"
        assertEquals(400, post("/api/superuser", body, json = false).status)
        assertEquals(400, post("/api/superuser", body.replace("\"confirm\":true", "\"confirm\":false")).status)
        for (field in listOf("uid", "userId", "expiry", "profile")) {
            assertEquals(400, post("/api/superuser", body.dropLast(1) + ",\"$field\":1}").status)
        }
        assertTrue(port.writes.isEmpty())
        val response = post("/api/superuser", body)
        assertEquals(200, response.status)
        assertEquals(listOf("com.example.app" to true), port.writes)
        assertTrue(response.text().contains("\"allowed\":true"))
    }

    @Test fun protectedAndRollbackFailuresHaveExplicitStatuses() {
        port.failure = LiteWebSuResult.Failed("SU_AUTH_PROTECTED")
        val body = "{\"packageName\":\"com.example.app\",\"allow\":false,\"confirm\":true}"
        assertEquals(403, post("/api/superuser", body).status)
        port.failure = LiteWebSuResult.Failed("SU_AUTH_READBACK_FAILED", rollback = "verified")
        val failed = post("/api/superuser", body)
        assertEquals(409, failed.status)
        assertTrue(failed.text().contains("\"rollback\":\"verified\""))
        assertFalse(failed.text().contains("\"ok\":true"))
    }

    @Test fun environmentLogIsEscapedAndLoggingAndClearHaveConfirmedReplies() {
        val log = get("/api/superuser/log")
        assertEquals(200, log.status)
        assertTrue(log.text().contains("\"source\":\"ultra-environment\""))
        assertTrue(log.text().contains("line\\n\\\"quoted\\\""))
        assertEquals(400, post("/api/superuser/log", "{\"action\":\"clear\"}").status)
        val cleared = post("/api/superuser/log", "{\"action\":\"clear\",\"confirm\":true}")
        assertEquals(200, cleared.status)
        assertTrue(cleared.text().contains("\"cleared\":true"))
        val enabled = post("/api/superuser/logging", "{\"enabled\":true,\"confirm\":true}")
        assertEquals(200, enabled.status)
        assertTrue(enabled.text().contains("\"enabled\":true"))
    }

    @Test fun moduleFailureObjectsAre503NotAnEmptySuccess() {
        modules = "{\"ok\":false,\"error\":\"DAEMON_MODE_UNRESOLVED\"}"
        val failure = get("/api/modules")
        assertEquals(503, failure.status)
        assertEquals(modules, failure.text())
        modules = ""
        assertEquals(503, get("/api/modules").status)
    }

    @Test fun invalidTokenCannotInvokeGrant() {
        val request = LiteWebTestFixtures.request(method = "POST", target = "/x7k9f/${LiteWebTestFixtures.OTHER_TOKEN}/api/superuser",
            body = "{\"packageName\":\"com.example.app\",\"allow\":true,\"confirm\":true}".toByteArray())
        assertEquals(401, handler.handle(request).status)
        assertTrue(port.writes.isEmpty())
    }
}

private class HandlerSuPort : LiteWebSuperuserPort {
    var failure: LiteWebSuResult.Failed? = null
    val writes = mutableListOf<Pair<String, Boolean>>()
    override fun snapshot(): LiteWebSuResult<LiteWebSuSnapshot> = failure ?: LiteWebSuResult.Ok(
        LiteWebSuSnapshot(setOf("com.example.app"), LiteWebSuCatalog(), setOf("dev.maplesu.manager"), false))
    override fun setAllowed(packageName: String, allowed: Boolean): LiteWebSuResult<LiteWebSuMutation> {
        failure?.let { return it }
        writes += packageName to allowed
        return LiteWebSuResult.Ok(LiteWebSuMutation(packageName, allowed, true))
    }
    override fun log(): LiteWebSuResult<LiteWebSuLog> = failure ?: LiteWebSuResult.Ok(LiteWebSuLog("line\n\"quoted\""))
    override fun clearLog(): LiteWebSuResult<Unit> = failure ?: LiteWebSuResult.Ok(Unit)
    override fun setLogging(enabled: Boolean): LiteWebSuResult<Boolean> = failure ?: LiteWebSuResult.Ok(enabled)
}
