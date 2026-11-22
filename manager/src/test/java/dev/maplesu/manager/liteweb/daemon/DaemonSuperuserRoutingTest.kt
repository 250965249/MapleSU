package dev.maplesu.manager.liteweb.daemon

import dev.maplesu.manager.liteweb.FakeBackend
import dev.maplesu.manager.liteweb.LiteWebBackend
import dev.maplesu.manager.liteweb.LiteWebRequestHandler
import dev.maplesu.manager.liteweb.LiteWebSuApplication
import dev.maplesu.manager.liteweb.LiteWebSuCatalog
import dev.maplesu.manager.liteweb.LiteWebSuResult
import dev.maplesu.manager.liteweb.LiteWebSuSdk
import dev.maplesu.manager.liteweb.LiteWebSuperuserManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Real daemon → HTTP handler → transaction, with an in-memory SDK and no device. */
class DaemonSuperuserRoutingTest {
    private val token = "a".repeat(64)
    private val sdk = RoutingSdk()
    private val manager = LiteWebSuperuserManager(
        sdk = sdk,
        catalog = { LiteWebSuCatalog(listOf(LiteWebSuApplication("com.example.app", 10_123)), true, true) },
        protectedPackages = { setOf("dev.maplesu.manager") },
    )
    private val backend = object : LiteWebBackend by FakeBackend() {
        override fun superuserPort() = manager
    }
    private val core = LiteWebDaemonCore(
        config = LiteWebDaemonConfig(18427, token),
        handler = LiteWebRequestHandler({ token }, backend),
    )
    private val grant = """{"packageName":"com.example.app","allow":true,"confirm":true}"""

    private fun post(path: String, body: String, type: String? = "application/json; charset=utf-8"): DaemonResponse {
        val headers = mutableMapOf("Host" to "127.0.0.1:18427")
        if (type != null) headers["cOnTeNt-TyPe"] = type
        return core.handle("POST", "/x7k9f/$token$path", headers, body)
    }

    @Test
    fun jsonContentTypeSurvivesDaemonDelegationAndGrantReadsBack() {
        val response = post("/api/superuser", grant)
        assertEquals(response.body, 200, response.status)
        assertTrue(response.body.contains("\"allowed\":true"))
        assertEquals(setOf("com.example.app"), sdk.grants)
        val readback = core.handle("GET", "/x7k9f/$token/api/superuser", mapOf("Host" to "localhost:18427"), "")
        assertEquals(200, readback.status)
        assertTrue(readback.body.contains("\"grants\":[\"com.example.app\"]"))
        assertFalse(response.body.contains(token))
    }

    @Test
    fun missingOrNonJsonContentTypeIsStillRejectedBeforeMutation() {
        assertEquals(400, post("/api/superuser", grant, null).status)
        assertEquals(400, post("/api/superuser", grant, "text/plain").status)
        assertTrue(sdk.grants.isEmpty())
    }

    @Test
    fun loggingAndClearRequestsAlsoKeepTheirJsonContentType() {
        val logging = post("/api/superuser/logging", """{"enabled":true,"confirm":true}""")
        assertEquals(logging.body, 200, logging.status)
        assertTrue(sdk.logging)
        val cleared = post("/api/superuser/log", """{"action":"clear","confirm":true}""")
        assertEquals(cleared.body, 200, cleared.status)
        assertEquals("", sdk.text)
    }

    @Test
    fun invalidTokenOrHostNeverReachesTheSdk() {
        val headers = mapOf("Host" to "127.0.0.1:18427", "Content-Type" to "application/json")
        assertEquals(401, core.handle("POST", "/x7k9f/${"b".repeat(64)}/api/superuser", headers, grant).status)
        assertEquals(403, core.handle("POST", "/x7k9f/$token/api/superuser", headers + ("Host" to "example.invalid"), grant).status)
        assertTrue(sdk.grants.isEmpty())
    }
}

private class RoutingSdk : LiteWebSuSdk {
    val grants = linkedSetOf<String>()
    var logging = false
    var text = "environment log"
    override fun packages() = LiteWebSuResult.Ok(grants.toSet())
    override fun setAllowed(packageName: String, allowed: Boolean): LiteWebSuResult<Unit> {
        if (allowed) grants += packageName else grants -= packageName
        return LiteWebSuResult.Ok(Unit)
    }
    override fun loggingEnabled() = LiteWebSuResult.Ok(logging)
    override fun setLogging(enabled: Boolean): LiteWebSuResult<Unit> {
        logging = enabled
        return LiteWebSuResult.Ok(Unit)
    }
    override fun log() = LiteWebSuResult.Ok(text)
    override fun clearLog(): LiteWebSuResult<Unit> {
        text = ""
        return LiteWebSuResult.Ok(Unit)
    }
}
