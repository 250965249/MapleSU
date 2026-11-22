package dev.maplesu.manager.liteweb.daemon

import dev.maplesu.manager.liteweb.LiteWebConstants
import dev.maplesu.manager.liteweb.LiteWebHandler
import dev.maplesu.manager.liteweb.LiteWebHttpRequest
import dev.maplesu.manager.liteweb.LiteWebRequestHandler
import dev.maplesu.manager.liteweb.LiteWebServer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.net.Socket

/**
 * daemon 路由（纯 JVM）：恢复链接形状的静态资源 + `/api/...` 只读面 + 三条既有契约。
 *
 * 这里驱动的是真实组合：`LiteWebDaemonCore`（daemon 契约层）+ `LiteWebRequestHandler`
 * （App 侧同一套路由）+ `DaemonLiteWebBackend`（临时 `/data/adb` + 假 APK）。
 */
class DaemonLiteWebRoutingTest {
    @get:Rule
    val temporary = TemporaryFolder()

    private val token = "a".repeat(64)
    private val port = 18427
    private val restoreActions = mutableListOf<String>()
    private lateinit var env: DaemonLiteWebTestEnv
    private lateinit var backend: DaemonLiteWebBackend
    private lateinit var core: LiteWebDaemonCore

    @Before
    fun setUp() {
        env = DaemonLiteWebTestEnv(temporary.newFolder("env"))
        env.createTextApk(
            mapOf(
                "assets/liteweb/index.html" to "<html><body>lite webui</body></html>",
                "assets/liteweb/a/app.js" to "console.log(\"lite\")",
                "assets/liteweb/a/app.css" to "body{color:#fff}",
            ),
        )
        env.addModule("demo", "id=demo\nname=Demo\nversion=1.0\nversionCode=7\nauthor=me\n")
        backend = env.backend(port = port)
        core = coreFor(backend)
    }

    private fun coreFor(target: DaemonLiteWebBackend): LiteWebDaemonCore = LiteWebDaemonCore(
        config = LiteWebDaemonConfig(port = port, token = token),
        restore = { action ->
            restoreActions.add(action)
            // 与 LiteWebDaemonRestore.run 一致：只有 "full" 有真实动作，其它显式不支持。
            if (action == "full") """{"ok":true,"code":"","steps":["verify:ok"]}"""
            else """{"ok":false,"code":"RESTORE_ACTION_UNSUPPORTED"}"""
        },
        status = { DaemonLiteWebStatus.render(target) },
        handler = LiteWebRequestHandler(tokenProvider = { token }, backend = target),
    )

    private fun url(route: String = "/"): String = "/x7k9f/$token$route"

    private fun get(
        path: String,
        host: String = "127.0.0.1:$port",
    ): DaemonResponse = core.handle("GET", path, mapOf("Host" to host), "")

    private fun post(
        path: String,
        body: String,
        host: String = "127.0.0.1:$port",
    ): DaemonResponse = core.handle("POST", path, mapOf("Host" to host), body)

    private fun wire(
        path: String,
        host: String? = "127.0.0.1:$port",
        method: String = "GET",
        body: String = "",
    ): LiteWebHttpRequest = LiteWebHttpRequest(
        method = method,
        target = path,
        headers = if (host == null) emptyMap() else mapOf("Host" to host),
        body = body.toByteArray(Charsets.UTF_8),
    )

    // ------------------------------------------------------------------ static

    @Test
    fun servesIndexHtmlAtTheRecoveryLinkRoot() {
        val response = get(url())
        assertEquals(response.body, 200, response.status)
        assertEquals("text/html; charset=utf-8", response.contentType)
        assertTrue(response.body, response.body.contains("lite webui"))
        assertNotNull(response.binary)
    }

    @Test
    fun servesNestedAssetsWithTheirContentType() {
        val script = get(url("/a/app.js"))
        assertEquals(script.body, 200, script.status)
        assertEquals("application/javascript; charset=utf-8", script.contentType)
        assertEquals("console.log(\"lite\")", script.body)

        val style = get(url("/a/app.css"))
        assertEquals(200, style.status)
        assertEquals("text/css; charset=utf-8", style.contentType)
    }

    @Test
    fun missingAssetIs404NotNullServerError() {
        val response = get(url("/a/nope.js"))
        assertEquals(404, response.status)
        assertTrue(response.body, response.body.contains("NOT_FOUND"))
    }

    @Test
    fun rejectsRawAndEncodedPathTraversal() {
        assertEquals(400, get(url("/../../etc/passwd")).status)
        assertEquals(400, get(url("/%2e%2e/%2e%2e/etc/passwd")).status)
        assertEquals(400, get(url("/a/%2e%2e%2f%2e%2e%2fetc/passwd")).status)
        // 前缀都不对的路径不暴露 daemon 存在性。
        assertEquals(404, get("/nope/$token/").status)
    }

    // ------------------------------------------------------------------ auth

    @Test
    fun pathTokenMustMatchTheConfiguredToken() {
        assertEquals(401, get("/x7k9f/${"b".repeat(64)}/").status)
        assertEquals(401, get("/x7k9f/${"b".repeat(64)}/ping").status)
        // token 段不是 64-hex 形状时按路由处理，仍然是「未鉴权」而不是「不存在」。
        assertEquals(401, get("/x7k9f/abc/ping").status)
        assertEquals(401, get("/x7k9f/?token=abc").status)
    }

    @Test
    fun queryAndHeaderTokensStayCompatible() {
        val query = get("/x7k9f/?token=$token")
        assertEquals(query.body, 200, query.status)
        assertTrue(query.body, query.body.contains("lite webui"))

        val header = core.handle(
            "GET",
            "/x7k9f/",
            mapOf("Host" to "127.0.0.1:$port", "X-MapleSU-Token" to token),
            "",
        )
        assertEquals(header.body, 200, header.status)

        // 路径 token 优先：路径错、query 对 → 仍然 401（不让 query 覆盖路径凭证）。
        assertEquals(401, get("/x7k9f/${"b".repeat(64)}/?token=$token").status)
    }

    @Test
    fun nonHexConfiguredTokenStillServesTheUi() {
        val legacyToken = "0123456789abcdef0123456789abcdef"
        val legacyBackend = env.backend(port = port)
        try {
            val legacyCore = LiteWebDaemonCore(
                config = LiteWebDaemonConfig(port = port, token = legacyToken),
                status = { DaemonLiteWebStatus.render(legacyBackend) },
                handler = LiteWebRequestHandler(
                    tokenProvider = { DaemonBridgeToken.derive(legacyToken) },
                    backend = legacyBackend,
                ),
            )
            val response = legacyCore.handle(
                "GET",
                "/x7k9f/$legacyToken/",
                mapOf("Host" to "127.0.0.1"),
                "",
            )
            assertEquals(response.body, 200, response.status)
            assertTrue(response.body, response.body.contains("lite webui"))
        } finally {
            legacyBackend.close()
        }
    }

    @Test
    fun bridgeTokenIsAlwaysSixtyFourLowerHex() {
        val derived = DaemonBridgeToken.derive("AbC1234567890abcdef")
        assertEquals(64, derived.length)
        assertTrue(derived, derived.all { it in '0'..'9' || it in 'a'..'f' })
        val alreadyValid = "a".repeat(64)
        assertEquals(alreadyValid, DaemonBridgeToken.derive(alreadyValid))
    }

    // ------------------------------------------------------------------ wire guards

    @Test
    fun hostHeaderMustBeLoopback() {
        assertEquals(403, get(url("/"), host = "evil.example").status)
        assertEquals(403, get(url("/ping"), host = "127.0.0.1.evil.example").status)
        assertEquals(200, get(url("/"), host = "localhost:$port").status)
    }

    @Test
    fun nonLoopbackConnectionIsRejected() {
        val response = core.handle("GET", url("/"), mapOf("Host" to "127.0.0.1"), "", remoteLoopback = false)
        assertEquals(403, response.status)
        assertTrue(response.body, response.body.contains("LOOPBACK_ONLY"))
    }

    @Test
    fun wireHandlerRequiresHostAndPassesBinaryThrough() {
        val handler: LiteWebHandler = DaemonRequestHandler(core)
        assertEquals(403, handler.handle(wire(url("/"), host = null)).status)

        val ok = handler.handle(wire(url("/")))
        assertEquals(200, ok.status)
        assertEquals("text/html; charset=utf-8", ok.contentType)

        // 二进制资源不能被文本桥改写（png 之类必须逐字节一致）。
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xFF.toByte())
        env.createApk(
            mapOf(
                "assets/liteweb/index.html" to "<html>bin</html>".toByteArray(Charsets.UTF_8),
                "assets/liteweb/a/icon.png" to png,
            ),
        )
        val freshBackend = env.backend(port = port)
        try {
            val freshHandler = DaemonRequestHandler(coreFor(freshBackend))
            val icon = freshHandler.handle(wire(url("/a/icon.png")))
            assertEquals(200, icon.status)
            assertEquals("image/png", icon.contentType)
            assertArrayEquals(png, icon.body)
        } finally {
            freshBackend.close()
        }
    }

    // ------------------------------------------------------------------ legacy contracts

    @Test
    fun pingKeepsTheExactLegacyContract() {
        val response = get(url("/ping"))
        assertEquals(200, response.status)
        assertEquals(LiteWebDaemonCore.PING_JSON, response.body)
        assertEquals("""{"ok":true,"service":"maplesu-liteweb-daemon"}""", response.body)
        assertTrue(response.body.contains("maplesu-liteweb-daemon"))

        // App 侧探活用的 HTTP/1.0 + 无端口的 Host 也能过（Host 白名单不看端口）。
        val probe = DaemonRequestHandler(core).handle(wire(url("/ping"), host = "127.0.0.1"))
        assertEquals(200, probe.status)
        assertTrue(probe.body.toString(Charsets.UTF_8).contains("maplesu-liteweb-daemon"))
    }

    @Test
    fun statusKeepsServiceMarkerAndCarriesRealFacts() {
        val response = get(url("/status"))
        assertEquals(200, response.status)
        assertTrue(response.body, response.body.contains("\"service\":\"maplesu-liteweb-daemon\""))
        assertTrue(response.body, response.body.contains("\"ok\":true"))
        assertTrue(response.body, response.body.contains("\"uapi\":\"daemon\""))
        assertTrue(response.body, response.body.contains("\"mode\":\"KSU\""))
        assertTrue(response.body, response.body.contains("\"root\":true"))
        assertTrue(response.body, response.body.contains("\"moduleCount\":1"))
        assertTrue(response.body, response.body.contains("\"webuiPort\":$port"))
        assertTrue(
            "授权库不可读要在能表达的地方标注: ${response.body}",
            response.body.contains("\"superusers\":\"unavailable\""),
        )
        assertTrue("没有隐藏状态文件时输出 null: ${response.body}", response.body.contains("\"hidden\":null"))

        env.hiddenFile.parentFile.mkdirs()
        env.hiddenFile.writeText("1\n", Charsets.UTF_8)
        val hidden = get(url("/status"))
        assertTrue(hidden.body, hidden.body.contains("\"hidden\":true"))
    }

    @Test
    fun restorePostRunsTheInProcessRootAction() {
        val response = post(url("/api/restore"), """{"action":"full"}""")
        assertEquals(response.body, 200, response.status)
        assertEquals(listOf("full"), restoreActions)
        assertTrue(response.body, response.body.contains("verify:ok"))
    }

    @Test
    fun restoreKeepsItsOldMethodAndBodyRules() {
        assertEquals(404, get(url("/api/restore")).status)
        val missing = post(url("/api/restore"), "{}")
        assertEquals(400, missing.status)
        assertTrue(missing.body, missing.body.contains("RESTORE_ACTION_MISSING"))
        // 非 "full" 的动作仍然显式不支持（不是静默成功）。
        val unsupported = post(url("/api/restore"), """{"action":"unhide"}""")
        assertEquals(200, unsupported.status)
        assertTrue(unsupported.body, unsupported.body.contains("RESTORE_ACTION_UNSUPPORTED"))
    }

    // ------------------------------------------------------------------ read-only api

    @Test
    fun unresolvedDaemonReturns503InsteadOfNormalRowsAndAllModesAgree() {
        env.backend(runtime = UnavailableDaemonRuntimeSource).use { unresolved ->
            val route = coreFor(unresolved)
            fun read(path: String) = route.handle("GET", url(path), mapOf("Host" to "127.0.0.1:$port"), "")
            val modules = read("/api/modules")
            assertEquals(modules.body, 503, modules.status)
            assertTrue(modules.body, modules.body.contains("DAEMON_MODE_UNRESOLVED"))
            assertFalse(modules.body, modules.body.contains("demo"))
            for (path in listOf("/api/status", "/api/diagnostics", "/api/workmode")) {
                val response = read(path)
                assertEquals(response.body, 200, response.status)
                assertTrue(response.body, response.body.contains("\"mode\":\"UNKNOWN\""))
            }
            assertTrue(read("/api/status").body.contains("\"moduleCountError\":\"DAEMON_MODE_UNRESOLVED\""))
        }
    }

    @Test
    fun sdkListFailureIs503AndNeverReturnsNormalRows() {
        val runtime = object : DaemonRuntimeSource {
            override fun snapshot() = DaemonRuntimePolicy.resolve(DaemonUltraState.RUNNING)
            override fun ultraModules() = DaemonModulesSnapshot(error = "ULTRA_MODULES_UNAVAILABLE")
        }
        env.backend(runtime = runtime).use { unreadable ->
            val response = coreFor(unreadable).handle("GET", url("/api/modules"), mapOf("Host" to "127.0.0.1:$port"), "")
            assertEquals(response.body, 503, response.status)
            assertTrue(response.body, response.body.contains("ULTRA_MODULES_UNAVAILABLE"))
            assertFalse(response.body, response.body.contains("demo"))
        }
    }

    @Test
    fun apiStatusExposesTheFrontendFields() {
        val response = get(url("/api/status"))
        assertEquals(response.body, 200, response.status)
        assertTrue(response.body, response.body.contains("\"ok\":true"))
        assertTrue(response.body, response.body.contains("\"mode\":\"KSU\""))
        assertTrue(response.body, response.body.contains("\"uapi\":\"daemon\""))
        assertTrue(response.body, response.body.contains("\"root\":true"))
        assertTrue(response.body, response.body.contains("\"moduleCount\":1"))
        assertTrue(response.body, response.body.contains("\"webuiPort\":$port"))
        assertTrue(response.body, response.body.contains("\"serverVersion\":1"))
        assertTrue("读不到隐藏态时不冒充 false: ${response.body}", response.body.contains("\"hidden\":null"))
    }

    @Test
    fun apiModulesAndSuperusersAndSulog() {
        val modules = get(url("/api/modules"))
        assertEquals(200, modules.status)
        assertTrue(modules.body, modules.body.trimStart().startsWith("["))
        assertTrue(modules.body, modules.body.contains("\"id\":\"demo\""))
        assertTrue(modules.body, modules.body.contains("\"enabled\":true"))

        val superusers = get(url("/api/superusers"))
        assertEquals(200, superusers.status)
        assertEquals("[]", superusers.body.trim())

        val sulog = get(url("/api/sulog"))
        assertEquals(200, sulog.status)
        assertTrue(sulog.body, sulog.body.contains("\"available\":false"))
        assertTrue(sulog.body, sulog.body.contains("SULOG_NOT_FOUND"))
    }

    @Test
    fun apiPingStaysAvailableForTheFrontend() {
        val response = get(url("/api/ping"))
        assertEquals(200, response.status)
        assertEquals("""{"ok":true}""", response.body)
    }

    @Test
    fun moduleToggleIsTheOnlyRealWritePath() {
        val disable = java.io.File(env.modulesRoot, "demo/disable")
        val off = post(url("/api/module/toggle"), """{"id":"demo","enabled":false}""")
        assertEquals(off.body, 200, off.status)
        assertTrue(off.body, off.body.contains("\"enabled\":false"))
        assertTrue(disable.isFile)

        val on = post(url("/api/module/toggle"), """{"id":"demo","enabled":true}""")
        assertEquals(200, on.status)
        assertFalse(disable.exists())
    }

    @Test
    fun unsafeModuleIdsAreRejectedAtBothLayers() {
        // handler 层：非法字符 → 400。
        val invalid = post(url("/api/module/toggle"), """{"id":"../escape","enabled":false}""")
        assertEquals(400, invalid.status)
        assertTrue(invalid.body, invalid.body.contains("MODULE_ID_INVALID"))

        // backend 层：形状合法但超 64 字符 → 409 + 明确错误码，不写文件。
        val longId = "a".repeat(65)
        val rejected = post(url("/api/module/toggle"), """{"id":"$longId","enabled":false}""")
        assertEquals(rejected.body, 409, rejected.status)
        assertTrue(rejected.body, rejected.body.contains("MODULE_ID_INVALID"))
        assertFalse(java.io.File(env.modulesRoot, "$longId/disable").exists())
    }

    @Test
    fun unimplementedWriteApisReturn501InsteadOfFakeSuccess() {
        val activate = post(url("/api/activate"), """{"confirm":true}""")
        assertEquals(activate.body, 501, activate.status)
        assertTrue(activate.body, activate.body.contains("NOT_IMPLEMENTED"))

        val action = post(url("/api/module/action"), """{"id":"demo","action":"run"}""")
        assertEquals(action.body, 501, action.status)
        assertTrue(action.body, action.body.contains("NOT_IMPLEMENTED"))

        val settings = post(url("/api/settings"), """{"theme":"dark"}""")
        assertEquals(settings.body, 501, settings.status)
        assertTrue(settings.body, settings.body.contains("NOT_IMPLEMENTED"))

        val hiddenOn = post(url("/api/hidden"), """{"enable":true}""")
        assertEquals(409, hiddenOn.status)
        assertTrue(hiddenOn.body, hiddenOn.body.contains("USE_ACTIVATE_API"))

        val port = post(url("/api/config/port"), """{"webuiPort":18500}""")
        assertEquals(port.body, 501, port.status)
        assertTrue(port.body, port.body.contains("ACTIVATE_BACKEND_UNAVAILABLE"))
        assertFalse("端口没被改就别说成功: ${port.body}", port.body.contains("\"ok\":true"))
    }

    // ------------------------------------------------------------------ unhide (设备缺陷 2)

    private fun coreWithUnhide(steps: List<dev.maplesu.manager.liteweb.LiteWebRestoreStep>): LiteWebDaemonCore {
        val target = env.backend(port = port, unhidePort = { steps })
        return coreFor(target)
    }

    private fun postWith(core: LiteWebDaemonCore, path: String, body: String): DaemonResponse =
        core.handle("POST", path, mapOf("Host" to "127.0.0.1:$port"), body)

    @Test
    fun postHiddenDisableRunsTheFullUnhideAndReturnsEveryStep() {
        val steps = listOf(
            dev.maplesu.manager.liteweb.LiteWebRestoreStep("restore_host_so", true, detail = "restored=45"),
            dev.maplesu.manager.liteweb.LiteWebRestoreStep("remove_loader", true, detail = "loader=absent"),
            dev.maplesu.manager.liteweb.LiteWebRestoreStep("revoke_su_auth", true, detail = "sdk=ok"),
            dev.maplesu.manager.liteweb.LiteWebRestoreStep("stop_daemon", true, detail = "exit_after_response"),
        )
        val response = postWith(coreWithUnhide(steps), url("/api/hidden"), """{"enable":false}""")
        assertEquals(response.body, 200, response.status)
        assertTrue(response.body, response.body.contains("\"ok\":true"))
        assertTrue(response.body, response.body.contains("\"name\":\"restore_host_so\""))
        assertTrue(response.body, response.body.contains("\"name\":\"stop_daemon\""))
        assertTrue(response.body, response.body.contains("\"failedStep\":\"\""))
    }

    @Test
    fun postHiddenDisableFailureIs409WithFailedStepAndRetryable() {
        val steps = listOf(
            dev.maplesu.manager.liteweb.LiteWebRestoreStep("restore_host_so", true),
            dev.maplesu.manager.liteweb.LiteWebRestoreStep(
                "remove_loader",
                false,
                "HIDDEN_LOADER_DELETE_FAILED",
                "exit=60",
            ),
        )
        val response = postWith(coreWithUnhide(steps), url("/api/hidden"), """{"enable":false}""")
        assertEquals(response.body, 409, response.status)
        assertTrue(response.body, response.body.contains("\"ok\":false"))
        assertTrue(response.body, response.body.contains("\"hidden\":true"))
        assertTrue(response.body, response.body.contains("\"failedStep\":\"remove_loader\""))
        assertTrue(response.body, response.body.contains("\"code\":\"HIDDEN_LOADER_DELETE_FAILED\""))
        assertTrue(response.body, response.body.contains("\"retryable\":true"))
    }

    @Test
    fun postHiddenDisableWithoutTokenIs401() {
        val wrongToken = "c".repeat(64)
        val response = post("/x7k9f/$wrongToken/api/hidden", """{"enable":false}""")
        assertEquals(response.body, 401, response.status)
        assertFalse("token 错误时不能执行任何解除动作", response.body.contains("restore_host_so"))
    }

    // ------------------------------------------------------------------ real socket

    @Test
    fun servesTheUiThroughTheRealHttpLayer() {
        val server = LiteWebServer(
            handler = DaemonRequestHandler(core),
            portCandidates = listOf(0),
        )
        server.start()
        try {
            assertTrue(server.isRunning())
            Socket(LiteWebConstants.LOOPBACK, server.boundPort).use { socket ->
                socket.soTimeout = 5_000
                socket.getOutputStream().write(
                    ("GET ${url("/a/app.js")} HTTP/1.1\r\n" +
                        "Host: 127.0.0.1:${server.boundPort}\r\n\r\n").toByteArray(Charsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()
                val response = socket.getInputStream().readBytes().toString(Charsets.ISO_8859_1)
                assertTrue(response, response.startsWith("HTTP/1.1 200"))
                assertTrue(response, response.contains("application/javascript"))
                assertTrue(response, response.contains("console.log"))
            }

            // 不带 Host 的连接在 wire 层被拒（DNS rebinding 防线）。
            Socket(LiteWebConstants.LOOPBACK, server.boundPort).use { socket ->
                socket.soTimeout = 5_000
                socket.getOutputStream().write(
                    ("GET ${url("/ping")} HTTP/1.0\r\n\r\n").toByteArray(Charsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()
                val response = socket.getInputStream().readBytes().toString(Charsets.ISO_8859_1)
                assertTrue(response, response.startsWith("HTTP/1.1 403"))
                assertFalse(response, response.contains("maplesu-liteweb-daemon"))
            }
        } finally {
            server.stop()
        }
    }

    @Test
    fun traversalNeverEscapesTheAssetsPrefix() {
        // 假 APK 里塞一个 assets/liteweb/../secret.txt：即使条目名存在，也不能被读到。
        env.createApk(
            mapOf(
                "assets/liteweb/index.html" to "<html>ok</html>".toByteArray(Charsets.UTF_8),
                "assets/secret.txt" to "TOP SECRET".toByteArray(Charsets.UTF_8),
            ),
        )
        val freshBackend = env.backend(port = port)
        try {
            assertNull(freshBackend.assets().read("../secret.txt"))
            assertNull(freshBackend.assets().read("secret.txt"))
            val response = coreFor(freshBackend).handle(
                "GET",
                url("/../secret.txt"),
                mapOf("Host" to "127.0.0.1:$port"),
                "",
            )
            assertEquals(400, response.status)
            assertFalse(response.body, response.body.contains("TOP SECRET"))
        } finally {
            freshBackend.close()
        }
    }
}
