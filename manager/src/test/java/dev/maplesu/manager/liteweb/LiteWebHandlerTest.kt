package dev.maplesu.manager.liteweb

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Handler / router / API 子集（纯 JVM，fake backend）。 */
class LiteWebHandlerTest {
    private val fixtures = LiteWebTestFixtures
    private val backend = FakeBackend()
    private val handler = fixtures.handler(backend)

    private fun get(path: String): LiteWebHttpResponse =
        handler.handle(fixtures.request(target = fixtures.target(path)))

    private fun post(path: String, body: String): LiteWebHttpResponse =
        handler.handle(fixtures.request(method = "POST", target = fixtures.target(path), body = body.toByteArray()))

    @Test
    fun pingReturnsOkWithoutTokenEcho() {
        val response = get("/api/ping")
        assertEquals(200, response.status)
        assertEquals(LiteWebHttpResponse.APPLICATION_JSON, response.contentType)
        assertTrue(response.text().contains("\"ok\":true"))
        assertFalse(response.text().contains(fixtures.TOKEN))
    }

    @Test
    fun statusReportsLiteFacts() {
        backend.statusValue = LiteWebStatusView(rootAvailable = true, moduleCount = 7, hidden = true)
        val response = get("/api/status")
        assertEquals(200, response.status)
        val body = response.text()
        assertTrue(body, body.contains("\"mode\":\"LITE\""))
        assertTrue(body, body.contains("\"root\":true"))
        assertTrue(body, body.contains("\"moduleCount\":7"))
        assertTrue(body, body.contains("\"hidden\":true"))
        assertTrue(body, body.contains("\"uapi\":\"lite\""))
        assertTrue(body, body.contains("\"serverVersion\":1"))
    }

    @Test
    fun modulesAreServedReadOnly() {
        backend.modules = "[{\"id\":\"m1\"},{\"id\":\"m2\"}]"
        assertEquals(backend.modules, get("/api/modules").text())
        assertEquals(200, get("/api/modules").status)
    }

    @Test
    fun emptyModulesReportUnavailableInsteadOfInventingAnEmptyList() {
        backend.modules = ""
        assertEquals(503, get("/api/modules").status)
        assertTrue(get("/api/modules").text().contains("MODULES_BACKEND_UNAVAILABLE"))
    }

    @Test
    fun superusersAreServedReadOnly() {
        backend.superusers = "[{\"uid\":10200,\"allowed\":true}]"
        assertEquals(backend.superusers, get("/api/superusers").text())
    }

    @Test
    fun sulogUnavailableHasReason() {
        backend.sulogValue = LiteWebSulogView(false, reason = "lite has no su log")
        val body = get("/api/sulog").text()
        assertTrue(body, body.contains("\"available\":false"))
        assertTrue(body, body.contains("lite has no su log"))
    }

    @Test
    fun sulogAvailableEscapesLines() {
        backend.sulogValue = LiteWebSulogView(true, lines = listOf("u:0 c:\"quoted\"", "line2"))
        val body = get("/api/sulog").text()
        assertTrue(body, body.contains("\"available\":true"))
        assertTrue(body, body.contains("quoted"))
        assertTrue(body, body.contains("line2"))
    }

    @Test
    fun toggleCallsBackend() {
        backend.toggleResult = LiteWebToggleView.Ok("m1", true)
        val response = post("/api/module/toggle", "{\"id\":\"m1\",\"enabled\":true}")
        assertEquals(200, response.status)
        assertEquals(listOf("m1" to true), backend.toggles)
        assertTrue(response.text().contains("\"enabled\":true"))
    }

    @Test
    fun toggleAcceptsModuleAliasAndFalse() {
        backend.toggleResult = LiteWebToggleView.Ok("m2", false)
        val response = post("/api/module/toggle", "{\"module\":\"m2\",\"enabled\":\"false\"}")
        assertEquals(200, response.status)
        assertEquals(listOf("m2" to false), backend.toggles)
    }

    @Test
    fun toggleAcceptsNativeModuleIdentity() {
        val id = "maplesu:" + "a".repeat(32)
        backend.toggleResult = LiteWebToggleView.Ok(id, false, needsReboot = true)
        val response = post("/api/module/toggle", "{\"id\":\"$id\",\"enabled\":false}")
        assertEquals(200, response.status)
        assertEquals(listOf(id to false), backend.toggles)
        assertTrue(response.text().contains("\"needsReboot\":true"))
    }

    @Test
    fun nativeToggleUsesDescriptorComponentAndUtf8Bounds() {
        for (component in listOf("a", "p0_probe", "z".repeat(32), "a".repeat(33), "a".repeat(1023),
            "中".repeat(341), "😀".repeat(255), "module with space", "module:colon", "module\\backslash")) {
            val id = "maplesu:$component"
            backend.toggleResult = LiteWebToggleView.Ok(id, false, needsReboot = true)
            val response = post("/api/module/toggle", "{\"id\":${org.json.JSONObject.quote(id)},\"enabled\":false}")
            assertEquals(id, 200, response.status)
            assertEquals(id to false, backend.toggles.last())
        }
        val calls = backend.toggles.size
        for (component in listOf("", ".", "..", "a/b", "a\u0000b", "a".repeat(1024), "中".repeat(342), "😀".repeat(256))) {
            val response = post("/api/module/toggle",
                "{\"id\":${org.json.JSONObject.quote("maplesu:$component")},\"enabled\":false}")
            assertEquals(component, 400, response.status)
        }
        assertEquals(calls, backend.toggles.size)
    }

    @Test
    fun toggleRejectsBadJson() {
        assertEquals(400, post("/api/module/toggle", "not-json").status)
        assertTrue(backend.toggles.isEmpty())
    }

    @Test
    fun toggleRejectsMissingId() {
        assertEquals(400, post("/api/module/toggle", "{\"enabled\":true}").status)
    }

    @Test
    fun toggleRejectsUnsafeId() {
        assertEquals(400, post("/api/module/toggle", "{\"id\":\"../etc\",\"enabled\":true}").status)
        assertEquals(400, post("/api/module/toggle", "{\"id\":\"\",\"enabled\":true}").status)
        assertEquals(400, post("/api/module/toggle", "{\"id\":\"${"x".repeat(129)}\",\"enabled\":true}").status)
    }

    @Test
    fun toggleRejectsInvalidEnabled() {
        assertEquals(400, post("/api/module/toggle", "{\"id\":\"m1\",\"enabled\":\"yes\"}").status)
    }

    @Test
    fun toggleBackendFailureIsReported() {
        backend.toggleResult = LiteWebToggleView.Failed("MODULE_TOGGLE_REJECTED", "backend false")
        val response = post("/api/module/toggle", "{\"id\":\"m1\",\"enabled\":false}")
        assertEquals(409, response.status)
        assertTrue(response.text().contains("MODULE_TOGGLE_REJECTED"))
    }

    @Test
    fun toggleBackendUnavailableIs503() {
        backend.toggleResult = LiteWebToggleView.Unavailable("native backend missing")
        val response = post("/api/module/toggle", "{\"id\":\"m1\",\"enabled\":true}")
        assertEquals(503, response.status)
        assertTrue(response.text().contains("BACKEND_UNAVAILABLE"))
    }

    @Test
    fun otherWritesAre501WithReason() {
        val response = post("/api/superuser/grant", "{}")
        assertEquals(501, response.status)
        assertTrue(response.text().contains("NOT_IMPLEMENTED"))
        assertTrue(response.text().contains("not implemented"))
    }

    @Test
    fun unknownGetIs404() {
        assertEquals(404, get("/api/does-not-exist").status)
    }

    @Test
    fun staticIndexIsServed() {
        val response = handler.handle(fixtures.request(target = fixtures.target("/")))
        assertEquals(200, response.status)
        assertEquals("text/html; charset=utf-8", response.contentType)
        assertTrue(response.text().contains("<html>"))
        assertTrue(backend.assets.requested.contains("index.html"))
    }

    @Test
    fun staticContentTypeFollowsExtension() {
        val response = handler.handle(fixtures.request(target = fixtures.target("/app.css")))
        assertEquals(200, response.status)
        assertEquals("text/css; charset=utf-8", response.contentType)
    }

    @Test
    fun missingStaticFileIs404() {
        assertEquals(404, handler.handle(fixtures.request(target = fixtures.target("/missing.js"))).status)
    }

    @Test
    fun traversalIsRejectedBeforeAssetLookup() {
        val response = handler.handle(fixtures.request(target = fixtures.target("/../webadmin.conf")))
        assertEquals(400, response.status)
        assertTrue(backend.assets.requested.none { it.contains("..") })
    }

    @Test
    fun tokenProviderMissingIs503() {
        val noToken = fixtures.handler(backend, token = null)
        val response = noToken.handle(fixtures.request())
        assertEquals(503, response.status)
        assertTrue(response.text().contains("TOKEN_UNAVAILABLE"))
    }

    @Test
    fun bodyLimitIsEnforcedInHandlerToo() {
        val body = ByteArray(LiteWebConstants.MAX_BODY_BYTES + 1)
        val response = handler.handle(
            fixtures.request(method = "POST", target = fixtures.target("/api/module/toggle"), body = body),
        )
        assertEquals(413, response.status)
    }

    @Test
    fun nonLoopbackRequestIsRejectedByHandler() {
        val response = handler.handle(fixtures.request(remoteLoopback = false))
        assertEquals(403, response.status)
    }
}
