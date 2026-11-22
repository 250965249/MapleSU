package dev.maplesu.manager.litehidden

import com.sun.net.httpserver.HttpServer
import org.junit.Assert.*
import org.junit.Test
import java.net.InetSocketAddress

class HttpHiddenManagerRemovalTest {
    private val token = "0".repeat(32)

    private fun request(body: String, status: Int = 200): HiddenManagerRemovalResult {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        var requests = 0
        server.createContext("/x7k9f/$token/api/manager/uninstall") { exchange ->
            requests++
            assertEquals("POST", exchange.requestMethod)
            assertEquals("{}", exchange.requestBody.bufferedReader().use { it.readText() })
            val bytes = body.toByteArray()
            exchange.sendResponseHeaders(status, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        server.start()
        return try {
            HttpHiddenManagerRemoval().uninstall(server.address.port, token).also {
                assertEquals("a removal request must never be replayed", 1, requests)
            }
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun confirmedRemovalRequiresTheDaemonReceipt() {
        val result = request("""{"ok":true,"state":"absent","data":"retained"}""")
        assertTrue(result.removed)
        assertEquals("", result.code)
    }

    @Test
    fun successfulJsonIsNotRejectedBecauseOfFieldOrderOrWhitespace() {
        assertTrue(request("""{ "data": "retained", "state": "absent", "ok": true }""").removed)
    }

    @Test
    fun daemonFailureCodesSurviveTheHttpBoundary() {
        listOf("MANAGER_HIDE_NOT_VERIFIED", "MANAGER_RECOVERY_NOT_VERIFIED",
            "MANAGER_FULL_RESTORE_UNAVAILABLE", "MANAGER_UNINSTALL_FAILED",
            "MANAGER_UNINSTALL_UNVERIFIED", "MANAGER_UNINSTALL_UNAVAILABLE").forEach { code ->
            val result = request("""{"ok":false,"code":"$code"}""")
            assertFalse(result.removed)
            assertEquals(code, result.code)
        }
    }

    @Test
    fun daemonFailureOnAnHttpErrorIsPreserved() {
        assertEquals("MANAGER_UNINSTALL_UNAVAILABLE",
            request("""{"ok":false,"code":"MANAGER_UNINSTALL_UNAVAILABLE"}""", 501).code)
    }

    @Test
    fun unconfirmedRepliesStayUnconfirmedAndNeverExposeArbitraryContent() {
        listOf("", "{", """{"ok":true}""",
            """{"ok":"true","state":"absent","data":"retained"}""",
            """{"ok":true,"state":"present","data":"retained"}""",
            """{"ok":false,"code":"private-$token"}""").forEach { body ->
            assertEquals(HiddenManagerRemovalResult(false, "MANAGER_UNINSTALL_UNVERIFIED"), request(body))
        }
        assertFalse(request("""{"ok":true,"state":"absent","data":"retained"}""", 500).removed)
    }
}
