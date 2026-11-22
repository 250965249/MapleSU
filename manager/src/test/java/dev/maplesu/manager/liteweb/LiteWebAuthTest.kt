package dev.maplesu.manager.liteweb

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Auth / token / config / path / redaction（纯 JVM）。 */
class LiteWebAuthTest {
    private val token = LiteWebTestFixtures.TOKEN

    private fun authorize(request: LiteWebHttpRequest, expected: String = token) =
        LiteWebAuth.authorize(request, expected)

    private fun response(result: LiteWebAuthorization): LiteWebHttpResponse =
        (result as LiteWebAuthorization.Rejected).response

    @Test
    fun validGetIsAllowedAndRouteIsPreserved() {
        val result = authorize(LiteWebTestFixtures.request(target = LiteWebTestFixtures.target("/api/status")))
        assertTrue(result is LiteWebAuthorization.Allowed)
        assertEquals("/api/status", (result as LiteWebAuthorization.Allowed).route)
    }

    @Test
    fun validPostIsAllowed() {
        val result = authorize(
            LiteWebTestFixtures.request(method = "POST", target = LiteWebTestFixtures.target("/api/module/toggle")),
        )
        assertTrue(result is LiteWebAuthorization.Allowed)
    }

    @Test
    fun rootRouteIsAllowed() {
        val result = authorize(LiteWebTestFixtures.request(target = LiteWebTestFixtures.target("/")))
        assertEquals("/", (result as LiteWebAuthorization.Allowed).route)
    }

    @Test
    fun missingTokenIsRejected() {
        val request = LiteWebTestFixtures.request(target = "/${LiteWebTestFixtures.PREFIX}/")
        assertEquals(401, response(authorize(request)).status)
    }

    @Test
    fun wrongTokenIsRejected() {
        val request = LiteWebTestFixtures.request(
            target = "/${LiteWebTestFixtures.PREFIX}/${LiteWebTestFixtures.OTHER_TOKEN}/api/ping",
        )
        assertEquals(401, response(authorize(request)).status)
    }

    @Test
    fun tokenComparisonIsExact() {
        assertTrue(LiteWebToken.matches(token, token))
        assertFalse(LiteWebToken.matches(token, token.uppercase()))
        assertFalse(LiteWebToken.matches(token, token.dropLast(1)))
        assertFalse(LiteWebToken.matches(null, token))
    }

    @Test
    fun wrongPrefixIsHiddenAs404() {
        val request = LiteWebTestFixtures.request(target = "/other/$token/api/ping")
        assertEquals(404, response(authorize(request)).status)
    }

    @Test
    fun nonLoopbackIsRejected() {
        val request = LiteWebTestFixtures.request(remoteLoopback = false)
        assertEquals(403, response(authorize(request)).status)
    }

    @Test
    fun methodOtherThanGetPostIsRejected() {
        assertEquals(405, response(authorize(LiteWebTestFixtures.request(method = "PUT"))).status)
        assertEquals(405, response(authorize(LiteWebTestFixtures.request(method = "DELETE"))).status)
    }

    @Test
    fun hostHeaderMustBeLoopback() {
        assertEquals(403, response(authorize(LiteWebTestFixtures.request(host = "evil.example"))).status)
        assertEquals(403, response(authorize(LiteWebTestFixtures.request(host = "127.0.0.1.evil"))).status)
        assertEquals(403, response(authorize(LiteWebTestFixtures.request(host = null))).status)
        assertEquals(403, response(authorize(LiteWebTestFixtures.request(host = "user@127.0.0.1"))).status)
    }

    @Test
    fun localhostAndPortAreAccepted() {
        assertTrue(authorize(LiteWebTestFixtures.request(host = "localhost:18427")) is LiteWebAuthorization.Allowed)
        assertTrue(authorize(LiteWebTestFixtures.request(host = "127.0.0.1")) is LiteWebAuthorization.Allowed)
        assertTrue(authorize(LiteWebTestFixtures.request(host = "LOCALHOST:1")) is LiteWebAuthorization.Allowed)
    }

    @Test
    fun queryStringIsIgnoredForTokenAndRoute() {
        val request = LiteWebTestFixtures.request(
            target = LiteWebTestFixtures.target("/api/ping") + "?x=1",
        )
        val result = authorize(request)
        assertEquals("/api/ping", (result as LiteWebAuthorization.Allowed).route)
    }

    @Test
    fun tokenGenerationIs64Hex() {
        val generated = LiteWebToken.generate()
        assertEquals(64, generated.length)
        assertTrue(generated.matches(Regex("[0-9a-f]{64}")))
        assertTrue(LiteWebToken.isValid(generated))
        assertFalse(LiteWebToken.isValid(generated.uppercase()))
        assertFalse(LiteWebToken.isValid(generated.dropLast(1)))
        assertFalse(LiteWebToken.isValid(null))
    }

    @Test
    fun configRoundTrips() {
        val config = LiteWebConfig(token = token, port = 18437, enabled = true, startedAt = 42L)
        assertEquals(config, LiteWebConfig.parse(config.render()))
    }

    @Test
    fun configRejectsCorruptContent() {
        assertNull(LiteWebConfig.parse(""))
        assertNull(LiteWebConfig.parse("schema=1\ntoken=nothex\nport=18427\n"))
        assertNull(LiteWebConfig.parse("schema=1\ntoken=$token\nport=99999\n"))
        assertNull(LiteWebConfig.parse("schema=1\ntoken=$token\ngarbage-line\n"))
        assertNull(LiteWebConfig.parse("schema=2\ntoken=$token\nport=18427\n"))
    }

    @Test
    fun configAcceptsDaemonWrittenFormatWithoutSchema() {
        // daemon/激活写的是 `webuiPort=`（无 schema 行）；必须能读，否则 App 会误配新 token。
        val parsed = LiteWebConfig.parse("webuiPort=18427\ntoken=$token\n")
        assertEquals(token, parsed?.token)
        assertEquals(18427, parsed?.port)
        // 也接受 `port=` 但没有 schema 行。
        assertEquals(18437, LiteWebConfig.parse("token=$token\nport=18437\n")?.port)
    }

    @Test
    fun configRejectsInvalidConstruction() {
        var rejected = false
        try {
            LiteWebConfig(token = "short", port = 18427)
        } catch (_: IllegalArgumentException) {
            rejected = true
        }
        assertTrue(rejected)
    }

    @Test
    fun redactionRemovesTokenAndQuery() {
        val message = "GET /x7k9f/$token/api/status?secret=1"
        val redacted = LiteWebRedaction.redact(message, token)
        assertFalse(redacted.contains(token))
        assertFalse(redacted.contains("secret=1"))
        assertTrue(redacted.contains("<token>"))
        assertEquals("/x7k9f/<token>/api/ping?<redacted>",
            LiteWebRedaction.redactTarget(LiteWebTestFixtures.target("/api/ping") + "?q=1", token))
    }

    // ------------------------------------------------------------------ static paths

    @Test
    fun staticRootMapsToIndexHtml() {
        assertEquals("index.html", LiteWebPaths.normalizeStatic(""))
        assertEquals("index.html", LiteWebPaths.normalizeStatic("/"))
        assertEquals("index.html", LiteWebPaths.normalizeStatic("///"))
    }

    @Test
    fun staticNestedPathIsKept() {
        assertEquals("assets/app.css", LiteWebPaths.normalizeStatic("/assets/app.css"))
        assertEquals("js/main.js", LiteWebPaths.normalizeStatic("//js//main.js"))
    }

    @Test
    fun staticTraversalIsRejected() {
        assertNull(LiteWebPaths.normalizeStatic("/../etc/passwd"))
        assertNull(LiteWebPaths.normalizeStatic("/assets/../../x"))
        assertNull(LiteWebPaths.normalizeStatic("/./index.html"))
        assertNull(LiteWebPaths.normalizeStatic("/assets\\..\\x"))
        assertNull(LiteWebPaths.normalizeStatic("/a%\u0000b"))
    }

    @Test
    fun percentEncodedTraversalIsRejectedAfterDecode() {
        val decoded = LiteWebPaths.decode("/%2e%2e/%2e%2e/etc/passwd")
        assertNotNull(decoded)
        assertNull(LiteWebPaths.normalizeStatic(decoded!!))
    }

    @Test
    fun urlsContainTokenOnlyForLoopback() {
        val url = LiteWebUrls.url(18427, token)
        assertEquals("http://127.0.0.1:18427/x7k9f/$token/", url)
        assertEquals("http://127.0.0.1:18427/x7k9f/$token/api/ping",
            LiteWebUrls.apiUrl(18427, token, "/api/ping"))
        assertFalse(url.contains("0.0.0.0"))
    }
}
