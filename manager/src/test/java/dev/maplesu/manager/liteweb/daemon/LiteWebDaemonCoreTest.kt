package dev.maplesu.manager.liteweb.daemon

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import com.sun.net.httpserver.HttpServer
import dev.maplesu.manager.litehidden.HttpHiddenManagerRemoval
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicReference
import dev.maplesu.manager.liteweb.LiteWebRequestHandler
import java.nio.file.Files

/** 自包含 daemon：config 解析/token 鉴权/路由/恢复动作转发（无 Android 依赖）。 */
class LiteWebDaemonCoreTest {
    private val config = LiteWebDaemonConfig(port = 18437, token = "0123456789abcdef0123456789abcdef")

    private fun core(
        restore: (String) -> String = { """{"ok":true,"code":"","steps":["x"]}""" },
        status: () -> String = { """{"service":"x","running":true}""" },
    ) = LiteWebDaemonCore(config, restore, status)

    @Test
    fun handoverRoutesAuthenticateAndOnlyTheRootOnlyNonceConfirms() {
        var confirmations = 0
        val nonce = "01234567-89ab-cdef-0123-456789abcdef"
        val service = LiteWebDaemonCore(config,
            restoreStatus = { DaemonResponse(200, """{"ok":true,"awaitingConfirmation":true}""") },
            confirmRestore = { received ->
                assertEquals(nonce, received)
                confirmations++
                DaemonResponse(200, """{"ok":true}""")
            },
        )
        val prefix = "/x7k9f/${config.token}"
        val status = service.handle("GET", "$prefix/api/restore/status", emptyMap(), "")
        assertTrue(status.body.contains("\"awaitingConfirmation\":true"))
        assertFalse(status.body.contains(nonce))
        assertEquals(401, service.handle("POST", "/x7k9f/api/manager/confirm", emptyMap(), """{"nonce":"$nonce"}""").status)
        assertEquals(400, service.handle("POST", "$prefix/api/manager/confirm", emptyMap(), "{}").status)
        assertEquals(0, confirmations)
        assertEquals(200, service.handle("POST", "$prefix/api/manager/confirm", emptyMap(), """{"nonce":"$nonce"}""").status)
        assertEquals(1, confirmations)
    }

    @Test
    fun ultraLegacyUnhideKeepsTheSameManagerConfirmationTransactionWhenInstalled() {
        var restored = 0
        val service = LiteWebDaemonCore(config.copy(workMode = "LITE"),
            restoreResponse = { restored++; DaemonResponse(200, """{"ok":true,"awaitingConfirmation":true}""") },
            managerInstalled = { true },
        )
        val response = service.handle("POST", "/x7k9f/${config.token}/api/hidden", emptyMap(), """{"enable":false}""")
        assertEquals(200, response.status)
        assertEquals(1, restored)
        assertTrue(response.body.contains("\"awaitingConfirmation\":true"))
        assertNull(response.afterResponse)
    }

    @Test
    fun configParseAndReject() {
        assertEquals(config, LiteWebDaemonConfig.parse("port=18437\ntoken=${config.token}"))
        assertNull(LiteWebDaemonConfig.parse("port=0\ntoken=${config.token}"))
        assertNull(LiteWebDaemonConfig.parse("port=18437\ntoken=short"))
        assertNull(LiteWebDaemonConfig.parse("token=${config.token}"))
        assertNull(LiteWebDaemonConfig.parse("port=18437"))
        assertEquals("KSU", LiteWebDaemonConfig.parse("port=18437\ntoken=${config.token}\nworkMode=KSU\n")?.workMode)
        assertEquals("LITE", LiteWebDaemonConfig.parse("port=18437\ntoken=${config.token}\nworkMode=LITE\n")?.workMode)
        assertNull(LiteWebDaemonConfig.parse("port=18437\ntoken=${config.token}\nworkMode=auto\n"))
    }

    @Test
    fun unauthorizedRequestsAreRejectedBeforeRouting() {
        val response = core().handle("GET", "/x7k9f/ping", emptyMap(), "")
        assertEquals(401, response.status)
        assertTrue(response.body.contains("LITEWEB_UNAUTHORIZED"))
        assertFalse(response.body.contains("\"ok\":true"))
    }

    @Test
    fun tokenAcceptedFromQueryOrHeader() {
        val query = core().handle("GET", "/x7k9f/ping?token=${config.token}", emptyMap(), "")
        assertEquals(200, query.status)
        assertTrue(query.body.contains("\"ok\":true"))
        val header = core().handle(
            "GET", "/x7k9f/ping", mapOf("X-MapleSU-Token" to config.token), "",
        )
        assertEquals(200, header.status)
    }

    @Test
    fun pingAndStatusRoutes() {
        val ping = core().handle("GET", "/x7k9f/ping?token=${config.token}", emptyMap(), "")
        assertTrue(ping.body.contains("maplesu-liteweb-daemon"))
        val status = core().handle("GET", "/x7k9f/status?token=${config.token}", emptyMap(), "")
        assertEquals(200, status.status)
        assertTrue(status.body.contains("\"running\":true"))
    }

    @Test
    fun restoreRouteRequiresPostAndAction() {
        var action: String? = null
        val service = core(restore = { value ->
            action = value
            """{"ok":true,"steps":["verify:ok"]}"""
        })
        val missing = service.handle("POST", "/x7k9f/api/restore?token=${config.token}", emptyMap(), "{}")
        assertEquals(400, missing.status)
        assertTrue(missing.body.contains("RESTORE_ACTION_MISSING"))

        val ok = service.handle(
            "POST", "/x7k9f/api/restore?token=${config.token}", emptyMap(), """{"action":"full"}""",
        )
        assertEquals(200, ok.status)
        assertEquals("full", action)
        assertTrue(ok.body.contains("verify:ok"))

        val wrongMethod = service.handle("GET", "/x7k9f/api/restore?token=${config.token}", emptyMap(), "")
        assertEquals(404, wrongMethod.status)
    }

    @Test
    fun pathTraversalAndUnknownRoutesAreRejected() {
        assertEquals(
            400,
            core().handle("GET", "/x7k9f/../etc/passwd?token=${config.token}", emptyMap(), "").status,
        )
        assertEquals(
            404,
            core().handle("GET", "/x7k9f/nope?token=${config.token}", emptyMap(), "").status,
        )
    }

    @Test
    fun tokenAcceptedFromPathLikeTheRecoveryLink() {
        // 恢复链接形状：/x7k9f/<token>/ —— 必须与 ping 用同一形状，链接才是活的。
        val ping = core().handle("GET", "/x7k9f/${config.token}/ping", emptyMap(), "")
        assertEquals(200, ping.status)
        assertTrue(ping.body.contains("maplesu-liteweb-daemon"))
        val status = core().handle("GET", "/x7k9f/${config.token}/status", emptyMap(), "")
        assertEquals(200, status.status)
        // token 之后的多段路由（webuiPathPrefix/token/api/restore）也要能定位到 /api/restore。
        val restore = core().handle(
            "POST",
            "/x7k9f/${config.token}/api/restore",
            emptyMap(),
            """{"action":"full"}""",
        )
        assertEquals(200, restore.status)
    }

    @Test
    fun pathTokenMustMatchExactlyAndNeverBeTreatedAsRoute() {
        assertEquals(
            401,
            core().handle("GET", "/x7k9f/${"f".repeat(32)}/ping", emptyMap(), "").status,
        )
        // 前缀不对 → 404（不暴露 daemon 存在性）；token 段太短按路由处理 → 未鉴权 401。
        assertEquals(404, core().handle("GET", "/nope/${config.token}/ping", emptyMap(), "").status)
        assertEquals(401, core().handle("GET", "/x7k9f/abc/ping", emptyMap(), "").status)
    }

    @Test
    fun configParsesTheProductionWebuiConfShape() {
        val token = "a".repeat(64)
        val parsed = LiteWebDaemonConfig.parse("webuiPort=18427\ntoken=$token\n")
        assertEquals(18427, parsed?.port)
        assertEquals(token, parsed?.token)
    }

    @Test
    fun mismatchTokenIsUnauthorized() {
        assertEquals(
            401,
            core().handle("GET", "/x7k9f/ping?token=ffffffffffffffffffffffffffffffff", emptyMap(), "").status,
        )
    }

    @Test
    fun managerRemovalIsAuthenticatedFixedBodyAndSynchronous() {
        var removed = 0
        val service = LiteWebDaemonCore(config, uninstallManager = {
            removed++
            """{"ok":true,"state":"absent","data":"retained"}"""
        })
        val path = "/x7k9f/${config.token}/api/manager/uninstall"
        assertEquals(401, service.handle("POST", "/x7k9f/api/manager/uninstall", emptyMap(), "{}").status)
        assertEquals(404, service.handle("GET", path, emptyMap(), "{}").status)
        assertEquals(400, service.handle("POST", path, emptyMap(), """{"package":"other.app"}""").status)
        assertEquals(0, removed)
        assertEquals(200, service.handle("POST", path, emptyMap(), "{}").status)
        assertEquals(1, removed)
    }

    @Test
    fun capabilitiesRejectOlderRestorationCodeBeforeDaemonReuse() {
        val expected = """{"ok":true,"managerUninstall":1,"fullRestore":6}"""
        val response = core().handle("GET", "/x7k9f/${config.token}/api/manager/capabilities", emptyMap(), "")
        assertEquals(200, response.status)
        assertEquals(expected, response.body)
        val body = AtomicReference(expected)
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/x7k9f/${config.token}/api/manager/capabilities") { exchange ->
            val bytes = body.get().toByteArray()
            exchange.sendResponseHeaders(200, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        server.start()
        try {
            val client = HttpHiddenManagerRemoval()
            assertTrue(client.supported(server.address.port, config.token))
            body.set("""{"ok":true,"managerUninstall":1,"fullRestore":5}""")
            assertFalse(client.supported(server.address.port, config.token))
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun installedNormalUnhideStillUsesFullKernelRestoration() {
        var restored = 0
        val service = LiteWebDaemonCore(config.copy(workMode = "KSU"), restoreResponse = {
            assertEquals("full", it); restored++; DaemonResponse(200, "{}")
        }, managerInstalled = { true })
        assertEquals(200, service.handle("POST", "/x7k9f/${config.token}/api/hidden", emptyMap(), """{"enable":false}""").status)
        assertEquals(1, restored)
    }

    @Test
    fun installedApkClasspathCannotAdvertiseIndependentRestoration() {
        val service = LiteWebDaemonCore(config, independentCodeReady = { false })
        val response = service.handle("GET", "/x7k9f/${config.token}/api/manager/capabilities", emptyMap(), "")
        assertEquals(409, response.status)
        assertTrue(response.body.contains("RECOVERY_CLASSPATH_NOT_INDEPENDENT"))
    }

    @Test
    fun restorationCompletionIsCarriedToTheWireWithoutRunningEarly() {
        var completed = false
        val service = LiteWebDaemonCore(config, restoreResponse = {
            DaemonResponse(200, "{}", afterResponse = { completed = true })
        })
        val response = DaemonRequestHandler(service).handle(dev.maplesu.manager.liteweb.LiteWebHttpRequest(
            "POST", "/x7k9f/${config.token}/api/restore", mapOf("Host" to "127.0.0.1"),
            """{"action":"full"}""".toByteArray(),
        ))
        assertFalse(completed)
        assertNotNull(response.afterResponse)
        response.afterResponse?.invoke()
        assertTrue(completed)
    }

    @Test
    fun legacyUnhideAliasesRestoreTheManagerBeforeTearingDownItsOnlyEntry() {
        var restored = 0
        val service = LiteWebDaemonCore(config, restoreResponse = {
            assertEquals("full", it)
            restored++
            DaemonResponse(200, """{"ok":true}""")
        }, managerInstalled = { false })
        for (body in listOf("""{"enable":false}""", """{"enable":"0"}""", """{"hidden":"off"}""", """{"hidden":"disable"}""")) {
            assertEquals(200, service.handle("POST", "/x7k9f/${config.token}/api/hidden", emptyMap(), body).status)
        }
        assertEquals(4, restored)
    }

    @Test
    fun unreadableManagerPresenceDoesNotTearDownRecovery() {
        var restored = 0
        val service = LiteWebDaemonCore(config, restoreResponse = { restored++; DaemonResponse(200, "{}") }, managerInstalled = { null })
        val response = service.handle("POST", "/x7k9f/${config.token}/api/hidden", emptyMap(), """{"enable":false}""")
        assertEquals(409, response.status)
        assertEquals(0, restored)
        assertTrue(response.body.contains("MANAGER_PRESENCE_UNVERIFIED"))
    }

    @Test
    fun hiddenStatusCarriesUnknownManagerPresenceThroughTheRealHandler() {
        val dir = Files.createTempDirectory("maplesu-hidden-presence-").toFile()
        try {
            DaemonLiteWebBackend(adbRoot = dir.absolutePath).use { backend ->
                val handler = LiteWebRequestHandler({ DaemonBridgeToken.derive(config.token) }, backend)
                val service = LiteWebDaemonCore(config, handler = handler)
                val response = service.handle("GET", "/x7k9f/${config.token}/api/hidden", emptyMap(), "")
                assertEquals(200, response.status)
                assertTrue(response.body, response.body.contains("\"managerUninstalled\":null"))
            }
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun hiddenStatusReportsVerifiedPresentAbsentUnknownAndProbeFailure() {
        val dir = Files.createTempDirectory("maplesu-hidden-presence-").toFile()
        try {
            val probes: List<Pair<() -> Boolean?, String>> = listOf(
                ({ true }) to "false",
                ({ false }) to "true",
                ({ null }) to "null",
                ({ throw IllegalStateException("pm failed") }) to "null",
            )
            for ((probe, expected) in probes) {
                DaemonLiteWebBackend(adbRoot = dir.absolutePath, managerInstalled = probe).use { backend ->
                    val handler = LiteWebRequestHandler({ DaemonBridgeToken.derive(config.token) }, backend)
                    val service = LiteWebDaemonCore(config, handler = handler, managerInstalled = probe)
                    val response = service.handle("GET", "/x7k9f/${config.token}/api/hidden", emptyMap(), "")
                    assertEquals(200, response.status)
                    assertTrue(response.body, response.body.contains("\"managerUninstalled\":$expected"))
                }
            }
        } finally {
            dir.deleteRecursively()
        }
    }
}
