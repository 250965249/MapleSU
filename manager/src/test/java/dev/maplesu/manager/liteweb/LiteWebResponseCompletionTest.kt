package dev.maplesu.manager.liteweb

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket
import org.junit.Assert.*
import org.junit.Test

class LiteWebResponseCompletionTest {
    private class Client(private val output: OutputStream) : Socket() {
        override fun setSoTimeout(timeout: Int) = Unit
        override fun setTcpNoDelay(on: Boolean) = Unit
        override fun getInetAddress(): InetAddress = InetAddress.getLoopbackAddress()
        override fun getInputStream() = ByteArrayInputStream("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".toByteArray())
        override fun getOutputStream() = output
        override fun close() = Unit
    }

    @Test fun completionRunsOnlyAfterResponseHasFlushed() {
        var flushed = false
        var completed = false
        val output = object : ByteArrayOutputStream() {
            override fun flush() { super.flush(); flushed = true }
        }
        val server = LiteWebServer(LiteWebHandler {
            LiteWebHttpResponse.json(200, "{}").copy(afterResponse = { assertTrue(flushed); completed = true })
        })
        server.handleConnection(Client(output))
        assertTrue(completed)
        assertTrue(output.toString().contains("HTTP/1.1 200"))
    }

    @Test fun writeFailureRetainsServiceAndSkipsCompletion() {
        var completed = false
        val server = LiteWebServer(LiteWebHandler {
            LiteWebHttpResponse.json(200, "{}").copy(afterResponse = { completed = true })
        })
        server.handleConnection(Client(object : OutputStream() {
            override fun write(value: Int) { throw IOException("closed") }
        }))
        assertFalse(completed)
    }

    @Test fun handlerErrorSkipsCompletion() {
        val server = LiteWebServer(LiteWebHandler { throw AssertionError("handler") })
        try {
            server.handleConnection(Client(ByteArrayOutputStream()))
            fail("handler Error must propagate")
        } catch (expected: AssertionError) {
            assertEquals("handler", expected.message)
        }
    }

    @Test fun flushFailureSkipsCompletion() {
        var completed = false
        val server = LiteWebServer(LiteWebHandler {
            LiteWebHttpResponse.json(200, "{}").copy(afterResponse = { completed = true })
        })
        server.handleConnection(Client(object : ByteArrayOutputStream() {
            override fun flush() { throw IOException("flush failed") }
        }))
        assertFalse(completed)
    }
}
