package dev.maplesu.manager.liteweb

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Lite webadmin 与 KernelSU `webadmin.rs` 的 `/modweb` 语义对齐（纯 JVM）。
 *
 * 覆盖：路径解析/防穿越、MIME、HTML 桥注入、405/404/501 三种降级、token 前缀强校验、
 * Host 限制、日志脱敏、无外部 CDN。
 */
class LiteWebModWebTest {
    private val fixtures = LiteWebTestFixtures
    private val backend = FakeBackend()
    private val handler = LiteWebRequestHandler(tokenProvider = { fixtures.TOKEN }, backend = backend)

    private fun get(route: String, token: String = fixtures.TOKEN): LiteWebHttpResponse =
        handler.handle(fixtures.request(target = "/${fixtures.PREFIX}/$token$route"))

    private fun post(route: String, body: String = "{}"): LiteWebHttpResponse =
        handler.handle(
            fixtures.request(
                method = "POST",
                target = fixtures.target(route),
                body = body.toByteArray(),
            ),
        )

    // ------------------------------------------------------------------ parse

    @Test
    fun modwebDefaultsToIndexHtml() {
        val parsed = LiteWebModWeb.parse("/modweb/tee")
        assertTrue(parsed is LiteWebModWeb.Parsed.File)
        assertEquals("tee", (parsed as LiteWebModWeb.Parsed.File).moduleId)
        assertEquals("index.html", parsed.rel)
    }

    @Test
    fun modwebAcceptsNestedRelativePath() {
        val parsed = LiteWebModWeb.parse("/modweb/tee/static/app.js") as LiteWebModWeb.Parsed.File
        assertEquals("tee", parsed.moduleId)
        assertEquals("static/app.js", parsed.rel)
    }

    @Test
    fun modwebRejectsMissingAndInvalidIds() {
        val missing = LiteWebModWeb.parse("/modweb") as LiteWebModWeb.Parsed.Rejected
        assertEquals(400, missing.response.status)
        assertTrue(missing.response.text().contains("MODWEB_ID_MISSING"))

        val traversal = LiteWebModWeb.parse("/modweb/..%2Fetc") as LiteWebModWeb.Parsed.Rejected
        assertEquals(400, traversal.response.status)
        assertTrue(traversal.response.text().contains("MODWEB_ID_INVALID"))

        val dotdot = LiteWebModWeb.parse("/modweb/../x") as LiteWebModWeb.Parsed.Rejected
        assertEquals(400, dotdot.response.status)
    }

    @Test
    fun modwebRejectsTraversalAndDotFilesInRelativePath() {
        listOf(
            "/modweb/tee/../../etc/passwd",
            "/modweb/tee/a/../../x",
            "/modweb/tee/.ssh/id_rsa",
            "/modweb/tee/a\\b",
            "/modweb/tee/a//b",
            "/modweb/tee/a/./b",
        ).forEach { route ->
            val parsed = LiteWebModWeb.parse(route)
            assertTrue("route=$route should be rejected", parsed is LiteWebModWeb.Parsed.Rejected)
        }
    }

    @Test
    fun modwebNormalizesRootOnlyPathsToIndex() {
        assertEquals("index.html", LiteWebModWeb.normalizeRel(""))
        assertEquals("index.html", LiteWebModWeb.normalizeRel("/"))
        assertEquals("a/b.css", LiteWebModWeb.normalizeRel("/a/b.css/"))
        assertEquals(null, LiteWebModWeb.normalizeRel("a/\u0000b"))
    }

    // ------------------------------------------------------------------ serving

    @Test
    fun modwebServesFileWithContentTypeAndCsp() {
        backend.moduleWeb = mapOf("tee/index.html" to "<html><head></head><body>tee</body></html>".toByteArray())
        val response = get("/modweb/tee/")
        assertEquals(200, response.status)
        assertTrue(response.contentType.startsWith("text/html"))
        assertEquals(LiteWebModWeb.CSP_MODWEB, response.headers["Content-Security-Policy"])
        assertTrue(response.text().contains("tee"))
    }

    @Test
    fun modwebInjectsTokenScopedBridgeIntoHtmlOnly() {
        backend.moduleWeb = mapOf(
            "tee/index.html" to "<html><head><title>t</title></head><body>x</body></html>".toByteArray(),
            "tee/app.js" to "console.log(1)".toByteArray(),
        )
        val html = get("/modweb/tee/index.html").text()
        assertTrue(html, html.contains("window.__7K_BASE__=\"/${fixtures.PREFIX}/${fixtures.TOKEN}\""))
        assertTrue(html, html.contains("/${fixtures.PREFIX}/${fixtures.TOKEN}/a/modbridge.js"))
        // 注入点必须在 </head> 之前，页面自己的样式/脚本顺序不被破坏
        assertTrue(html.indexOf("modbridge.js") < html.indexOf("</head>"))
        // 已经在页面里注入过就不重复
        assertEquals(1, Regex("__7K_BASE__").findAll(html).count())

        val js = get("/modweb/tee/app.js")
        assertEquals(200, js.status)
        assertTrue(js.contentType.startsWith("application/javascript"))
        assertFalse(js.text().contains("__7K_BASE__"))
    }

    @Test
    fun modwebMissingFileIs404AndUnwiredBackendIs501() {
        backend.moduleWeb = emptyMap()
        val missing = get("/modweb/tee/index.html")
        assertEquals(404, missing.status)
        assertTrue(missing.text().contains("NOT_FOUND"))

        backend.moduleWebUnavailable = "MODULE_WEBROOT_ABSENT: tee"
        val unavailable = get("/modweb/tee/index.html")
        assertEquals(501, unavailable.status)
        assertTrue(unavailable.text().contains("MODWEB_PROXY_UNAVAILABLE"))
        assertTrue(unavailable.text().contains("MODULE_WEBROOT_ABSENT"))
    }

    @Test
    fun modwebIsReadOnlyAndPostGets405() {
        backend.moduleWeb = mapOf("tee/index.html" to "<html></html>".toByteArray())
        val response = post("/modweb/tee/")
        assertEquals(405, response.status)
        assertTrue(response.text().contains("METHOD_NOT_ALLOWED"))
        assertTrue(backend.moduleWebRequests.isEmpty())
    }

    @Test
    fun modwebNeverBypassesTokenOrHostChecks() {
        backend.moduleWeb = mapOf("tee/index.html" to "<html></html>".toByteArray())
        // 错误 token → 401，且不会碰后端
        val badToken = get("/modweb/tee/", token = "b".repeat(64))
        assertEquals(401, badToken.status)
        assertTrue(backend.moduleWebRequests.isEmpty())
        // 非回环 Host → 403
        val foreignHost = handler.handle(
            fixtures.request(target = fixtures.target("/modweb/tee/"), host = "127.0.0.1.evil.example"),
        )
        assertEquals(403, foreignHost.status)
        // 非回环来源 → 403
        val notLoopback = handler.handle(
            fixtures.request(target = fixtures.target("/modweb/tee/"), remoteLoopback = false),
        )
        assertEquals(403, notLoopback.status)
    }

    // ------------------------------------------------------------------ alignment hardening

    @Test
    fun tokenSegmentMustBeExactlySixtyFourLowercaseHex() {
        // 结构对但长度/字符集不对：与「值不对」同一个 401（不泄露差异）
        val shortToken = handler.handle(
            fixtures.request(target = "/${fixtures.PREFIX}/${"a".repeat(63)}/api/ping"),
        )
        assertEquals(401, shortToken.status)
        val upperToken = handler.handle(
            fixtures.request(target = "/${fixtures.PREFIX}/${"A".repeat(64)}/api/ping"),
        )
        assertEquals(401, upperToken.status)
        val queryToken = handler.handle(
            fixtures.request(target = "/${fixtures.PREFIX}/?token=${fixtures.TOKEN}"),
        )
        // token 只认路径段：query 里的 token 不参与鉴权 → 与「没带 token」同一个 401
        assertEquals(401, queryToken.status)
    }

    @Test
    fun unknownPrefixIs404SoExistenceIsNotDisclosed() {
        val response = handler.handle(
            fixtures.request(target = "/other/${fixtures.TOKEN}/api/ping"),
        )
        assertEquals(404, response.status)
        assertEquals("", response.text())
    }

    @Test
    fun hostHeaderOnlyAllowsLoopbackForms() {
        assertTrue(LiteWebAuth.hostAllowed("127.0.0.1"))
        assertTrue(LiteWebAuth.hostAllowed("127.0.0.1:18427"))
        assertTrue(LiteWebAuth.hostAllowed("localhost:18427"))
        assertFalse(LiteWebAuth.hostAllowed("localhost.evil.example"))
        assertFalse(LiteWebAuth.hostAllowed("127.0.0.1@evil.example"))
        assertFalse(LiteWebAuth.hostAllowed("10.0.0.2:18427"))
        assertFalse(LiteWebAuth.hostAllowed(null))
    }

    @Test
    fun redactionHidesTokenInModwebTargets() {
        val target = "/${fixtures.PREFIX}/${fixtures.TOKEN}/modweb/tee/index.html?x=1"
        val redacted = LiteWebRedaction.redactTarget(target, fixtures.TOKEN)
        assertFalse(redacted.contains(fixtures.TOKEN))
        assertTrue(redacted.contains("modweb/tee/index.html"))
        assertTrue(redacted.endsWith("?<redacted>"))
    }

    @Test
    fun shippedWebAssetsHaveNoExternalCdnReference() {
        val root = java.io.File("src/main/assets/liteweb")
        if (!root.isDirectory) return // 从仓库根跑测试时路径不同，跳过而不是假绿
        // 只找「会被加载」的外部引用：script/link/img 的 src/href、fetch、@import。
        // SVG 的 xmlns 与许可证正文里的 URL 不是网络请求，不算 CDN。
        val loads = Regex(
            """(?i)(?:\b(?:src|href)\s*=\s*["']?(?:https?:)?//|\bfetch\s*\(\s*["'](?:https?:)?//|@import\s+(?:url\()?\s*["']?(?:https?:)?//)([A-Za-z0-9.-]+)""",
        )
        val allowedHosts = setOf("127.0.0.1", "localhost")
        val offenders = mutableListOf<String>()
        root.walkTopDown()
            .filter { it.isFile && it.extension.lowercase() in setOf("html", "htm", "css", "js") }
            .forEach { file ->
                loads.findAll(file.readText()).forEach { match ->
                    val host = match.groupValues[1].lowercase()
                    if (host !in allowedHosts) offenders.add("${file.name}: $host")
                }
            }
        assertTrue("assets must not load external resources: $offenders", offenders.isEmpty())
    }

    @Test
    fun bridgeTagMatchesKsudShapeAndStaysSameOrigin() {
        val tag = LiteWebModWeb.bridgeTag("/x7k9f/${fixtures.TOKEN}", "tee")
        assertTrue(tag.contains("window.__7K_BASE__"))
        assertTrue(tag.contains("window.__7K_MODULE__"))
        assertTrue(tag.contains("src=\"/x7k9f/${fixtures.TOKEN}/a/modbridge.js\""))
        assertFalse(tag.contains("http://"))
        assertFalse(tag.contains("https://"))
        assertNotNull(LiteWebModWeb.contentType("x.svg"))
    }
}
