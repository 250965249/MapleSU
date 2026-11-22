package dev.maplesu.manager.liteweb

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress

/** HTTP parser + socket server（含端口回退/真实 loopback 请求/停止关闭）。 */
class LiteWebServerTest {
    private val fixtures = LiteWebTestFixtures
    private val token = fixtures.TOKEN

    // ------------------------------------------------------------------ parser

    private fun raw(request: String): LiteWebParseResult =
        LiteWebHttpParser.parse(ByteArrayInputStream(request.toByteArray(Charsets.ISO_8859_1)))

    private fun parsed(result: LiteWebParseResult): LiteWebHttpRequest =
        (result as LiteWebParseResult.Parsed).request

    private fun rejectedStatus(result: LiteWebParseResult): Int =
        (result as LiteWebParseResult.Rejected).response.status

    private fun getRequest(path: String = "/api/ping", host: String = "127.0.0.1:18427"): String =
        "GET /${fixtures.PREFIX}/$token$path HTTP/1.1\r\nHost: $host\r\nUser-Agent: test\r\n\r\n"

    @Test
    fun parsesGetRequestLineAndHeaders() {
        val request = parsed(raw(getRequest()))
        assertEquals("GET", request.method)
        assertEquals("/${fixtures.PREFIX}/$token/api/ping", request.target)
        assertEquals("127.0.0.1:18427", request.header("host"))
        assertEquals("test", request.header("User-Agent"))
        assertEquals(0, request.body.size)
        assertTrue(request.remoteLoopback)
    }

    @Test
    fun parsesPostBodyByContentLength() {
        val body = "{\"id\":\"m1\"}"
        val request = parsed(
            raw(
                "POST /${fixtures.PREFIX}/$token/api/module/toggle HTTP/1.1\r\n" +
                    "Host: 127.0.0.1\r\nContent-Length: ${body.length}\r\n\r\n$body",
            ),
        )
        assertEquals("POST", request.method)
        assertEquals(body, request.textBody())
    }

    @Test
    fun rejectsOversizedBody() {
        val request = "POST /${fixtures.PREFIX}/$token/api/module/toggle HTTP/1.1\r\n" +
            "Host: 127.0.0.1\r\nContent-Length: ${LiteWebConstants.MAX_BODY_BYTES + 1}\r\n\r\n"
        assertEquals(413, rejectedStatus(raw(request)))
    }

    @Test
    fun rejectsOversizedHeaders() {
        val huge = "X-Huge: " + "a".repeat(LiteWebConstants.MAX_HEADER_BYTES)
        assertEquals(431, rejectedStatus(raw(getRequest().replace("User-Agent: test", huge))))
    }

    @Test
    fun rejectsTransferEncoding() {
        val request = "POST /${fixtures.PREFIX}/$token/api/module/toggle HTTP/1.1\r\n" +
            "Host: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        assertEquals(400, rejectedStatus(raw(request)))
    }

    @Test
    fun rejectsMalformedRequestLine() {
        assertEquals(400, rejectedStatus(raw("NONSENSE\r\n\r\n")))
        assertEquals(400, rejectedStatus(raw("GET relative HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")))
    }

    @Test
    fun rejectsTruncatedBody() {
        val request = "POST /${fixtures.PREFIX}/$token/api/module/toggle HTTP/1.1\r\n" +
            "Host: 127.0.0.1\r\nContent-Length: 10\r\n\r\nabc"
        assertEquals(400, rejectedStatus(raw(request)))
    }

    @Test
    fun rejectsHeaderWithoutColon() {
        assertEquals(400, rejectedStatus(raw("GET /x HTTP/1.1\r\nBrokenHeader\r\n\r\n")))
    }

    // ------------------------------------------------------------------ server

    private fun failingFactory(failPorts: Set<Int>): LiteWebSocketFactory = LiteWebSocketFactory {
        object : ServerSocket() {
            override fun bind(endpoint: SocketAddress?, backlog: Int) {
                val port = (endpoint as? InetSocketAddress)?.port ?: -1
                if (port in failPorts) throw IOException("busy:$port")
                super.bind(endpoint, backlog)
            }
        }
    }

    private fun readAll(socket: Socket): String =
        socket.getInputStream().readBytes().toString(Charsets.ISO_8859_1)

    @Test
    fun fallbackSkipsBusyPort() {
        val server = LiteWebServer(
            handler = fixtures.handler(FakeBackend()),
            address = java.net.InetAddress.getByName(LiteWebConstants.LOOPBACK),
            portCandidates = listOf(18427, 0),
            socketFactory = failingFactory(setOf(18427)),
        )
        try {
            val result = server.start()
            assertTrue(result is LiteWebStartResult.Started)
            val started = result as LiteWebStartResult.Started
            assertTrue(started.attempts.any { it.startsWith("18427:") })
            assertTrue(started.port > 0)
        } finally {
            server.stop()
        }
    }

    @Test
    fun allCandidatesFailingReturnsFailure() {
        val server = LiteWebServer(
            handler = fixtures.handler(FakeBackend()),
            portCandidates = listOf(18427, 18437),
            socketFactory = failingFactory(setOf(18427, 18437)),
        )
        val result = server.start()
        assertTrue(result is LiteWebStartResult.Failed)
        assertEquals("LITEWEB_BIND_FAILED", (result as LiteWebStartResult.Failed).code)
        assertEquals(2, result.attempts.size)
    }

    @Test
    fun realLoopbackRequestIsServedAndTokenIsRedactedFromLogs() {
        val logs = mutableListOf<String>()
        val server = LiteWebServer(
            handler = fixtures.handler(FakeBackend()),
            portCandidates = listOf(0),
            logger = { logs.add(it) },
            secretProvider = { fixtures.TOKEN },
        )
        server.start()
        try {
            assertTrue(server.isRunning())
            val port = server.boundPort
            Socket(LiteWebConstants.LOOPBACK, port).use { socket ->
                socket.soTimeout = 5_000
                socket.getOutputStream().write(
                    getRequest(host = "127.0.0.1:$port").toByteArray(Charsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()
                val response = readAll(socket)
                assertTrue(response, response.startsWith("HTTP/1.1 200"))
                assertTrue(response, response.contains("{\"ok\":true}"))
                assertTrue(response, response.contains("Content-Length:"))
            }
            assertTrue(logs.isNotEmpty())
            assertTrue(logs.none { it.contains(token) })
        } finally {
            server.stop()
        }
    }

    @Test
    fun wrongHostOverRealSocketIsRejected() {
        val server = LiteWebServer(
            handler = fixtures.handler(FakeBackend()),
            portCandidates = listOf(0),
        )
        server.start()
        try {
            val port = server.boundPort
            Socket(LiteWebConstants.LOOPBACK, port).use { socket ->
                socket.soTimeout = 5_000
                socket.getOutputStream().write(
                    ("GET /${fixtures.PREFIX}/$token/api/ping HTTP/1.1\r\n" +
                        "Host: evil.example\r\n\r\n").toByteArray(Charsets.ISO_8859_1),
                )
                socket.getOutputStream().flush()
                val response = readAll(socket)
                assertTrue(response, response.startsWith("HTTP/1.1 403"))
            }
        } finally {
            server.stop()
        }
    }

    @Test
    fun stopClosesListener() {
        val server = LiteWebServer(
            handler = fixtures.handler(FakeBackend()),
            portCandidates = listOf(0),
        )
        server.start()
        val port = server.boundPort
        assertTrue(ServerSocket().use { probe ->
            probe.reuseAddress = true
            runCatching { probe.bind(InetSocketAddress(LiteWebConstants.LOOPBACK, port)) }.isFailure
        })
        server.stop()
        assertFalse(server.isRunning())
        var bound = false
        for (attempt in 0 until 20) {
            val socket = ServerSocket()
            try {
                socket.reuseAddress = true
                socket.bind(InetSocketAddress(LiteWebConstants.LOOPBACK, port))
                bound = true
            } catch (_: IOException) {
                Thread.sleep(25)
            } finally {
                runCatching { socket.close() }
            }
            if (bound) break
        }
        assertTrue("listener still bound after stop", bound)
    }

    @Test
    fun slowClientDoesNotBlockOtherRequests() {
        val server = LiteWebServer(
            handler = fixtures.handler(FakeBackend()),
            portCandidates = listOf(0),
            socketTimeoutMs = 250,
        )
        server.start()
        try {
            val port = server.boundPort
            val idle = Socket(LiteWebConstants.LOOPBACK, port)
            try {
                Thread.sleep(100)
                Socket(LiteWebConstants.LOOPBACK, port).use { socket ->
                    socket.soTimeout = 5_000
                    socket.getOutputStream().write(
                        getRequest(host = "127.0.0.1:$port").toByteArray(Charsets.ISO_8859_1),
                    )
                    socket.getOutputStream().flush()
                    val response = readAll(socket)
                    assertTrue(response, response.startsWith("HTTP/1.1 200"))
                }
            } finally {
                runCatching { idle.close() }
            }
        } finally {
            server.stop()
        }
    }

    @Test
    fun urlsHelperRejectsInvalidToken() {
        var rejected = false
        try {
            LiteWebUrls.url(18427, "short")
        } catch (_: IllegalArgumentException) {
            rejected = true
        }
        assertTrue(rejected)
        assertNotNull(LiteWebUrls.apiUrl(18427, token, "api/ping"))
    }
}
