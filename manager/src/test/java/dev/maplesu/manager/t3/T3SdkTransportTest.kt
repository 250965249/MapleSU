package dev.maplesu.manager.t3

import t3sdk.T3Verify
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InterruptedIOException
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import org.junit.Assert.*
import org.junit.Test

class T3SdkTransportTest {
    private class Sdk : T3Verify() {
        val calls = mutableListOf<Pair<URI, Map<String, String>>>()
        var response = """{"code":"200","msg":"成功","statecode":"session-value"}"""
        var failure: (() -> IOException)? = null

        override fun httpPostOnce(urlStr: String, postData: String): String {
            val parameters = postData.split('&').associate { pair ->
                val parts = pair.split('=', limit = 2)
                URLDecoder.decode(parts[0], "UTF-8") to URLDecoder.decode(parts[1], "UTF-8")
            }
            calls += URI(urlStr) to parameters
            failure?.let { throw it() }
            return read(response)
        }

        fun read(value: String): String = readResponse(ByteArrayInputStream(value.toByteArray(StandardCharsets.UTF_8)))
    }

    @Test fun operationsUseOfficialHttpsRoutesAndPlainFormParameters() {
        val sdk = Sdk()
        val transport = T3SdkTransport(sdk)
        val credentials = mapOf("user" to "user +中文", "pass" to "pass&=+")
        val cases = listOf(
            Triple(T3Operation.REGISTER, "7DB96ED993B8F15C", credentials + ("email" to "user+test@maplesu.app")),
            Triple(T3Operation.LOGIN, "6BB1C459D63AE8FC", credentials + ("imei" to "device-id")),
            Triple(T3Operation.HEARTBEAT, "8007E66F777EE16F", credentials + ("statecode" to "cached-session")),
            Triple(T3Operation.UPDATE_CORE, "A4EE92F2C6743A91", credentials + ("core" to "kernel\n中文 & model")),
            Triple(T3Operation.NOTICE, "9E7ED731C40B8EFE", emptyMap()),
        )

        cases.forEach { (operation, code, parameters) ->
            val result = transport.call(operation, parameters)
            assertEquals(200, result.code)
            assertEquals(if (operation == T3Operation.LOGIN) "session-value" else null, result.statecode)
            val (url, form) = sdk.calls.last()
            assertEquals("https", url.scheme)
            assertTrue(url.host in setOf("w.t3yanzheng.com", "w2.t3yanzheng.com", "w3.t3yanzheng.com",
                "w4.t3yanzheng.com", "w5.t3yanzheng.com", "w.t3data.net"))
            assertEquals("/$code", url.path)
            assertEquals(parameters, form - "t")
            assertTrue(form.getValue("t").toLong() > 0)
            assertFalse(form.containsKey("s"))
        }
    }

    @Test fun noticePreservesJsonEscapesAndLiteralLineBreaks() {
        val sdk = Sdk()
        val transport = T3SdkTransport(sdk)
        sdk.response = "{\n\"code\":\"200\",\n\"msg\":\"首行\\n第二行\\r\\n末行\"\n}"
        assertEquals(T3Response(200, "首行\n第二行\r\n末行"), transport.call(T3Operation.NOTICE, emptyMap()))
        assertEquals("raw\r\ntext\n", sdk.read("raw\r\ntext\n"))
    }

    @Test fun serviceFailuresKeepOriginalMessageForAccountClassification() {
        val sdk = Sdk()
        sdk.response = """{"code":201,"msg":"用户不存在"}"""
        val result = T3SdkTransport(sdk).call(T3Operation.LOGIN,
            mapOf("user" to "device", "pass" to "password", "imei" to "device"))
        assertEquals(201, result.code)
        assertEquals("用户不存在", result.message)
        assertNull(result.statecode)
    }

    @Test fun malformedResponsesNeverBecomeSuccessOrProgramDisabledMessages() {
        val sdk = Sdk()
        val transport = T3SdkTransport(sdk)
        listOf(
            "{\"code\":200,\"msg\":\"程序已禁用\"",
            "{\"code\":201,\"msg\":\"程序已禁用}",
            "{\"code\":201,\"msg\":\"程序已禁用\"} trailing",
            "{\"code\":200,\"msg\":\"invalid\\q\"}",
            "{\"code\":200,\"msg\":\"raw\nnewline\"}",
            "{\"code\":200,}",
            "{\"code\":0200}",
            "{\"code\":201,\"code\":200}",
            "{\"code\":200,\"data\":[1,]}",
            "{\"code\":200,\"data\":truefalse}",
        ).forEach { malformed ->
            sdk.response = malformed
            val notice = transport.call(T3Operation.NOTICE, emptyMap())
            assertEquals(malformed, 201, notice.code)
            assertFalse(malformed, T3AccountClient.isProgramDisabled(notice.message))
            assertEquals("响应不是有效的JSON格式", notice.message)
            assertEquals(201, transport.call(T3Operation.LOGIN,
                mapOf("user" to "device", "pass" to "password", "imei" to "device")).code)
        }
    }

    @Test fun fractionalAndOverflowingStatusCodesDoNotBecomeSuccess() {
        val sdk = Sdk()
        val transport = T3SdkTransport(sdk)
        listOf("200.5", "4294967496", "200.0000000000000000001", "2e3").forEach { code ->
            sdk.response = "{\"code\":$code,\"msg\":\"status rejected\"}"
            assertEquals(code, 201, transport.call(T3Operation.NOTICE, emptyMap()).code)
            assertEquals(code, 201, transport.call(T3Operation.LOGIN,
                mapOf("user" to "device", "pass" to "password", "imei" to "device")).code)
        }
    }

    @Test fun validNestedMetadataAndEscapedNoticeStillParse() {
        val sdk = Sdk()
        sdk.response = """{"code":200,"data":{"ok":true,"items":[null,-2,0.5,2e3]},"msg":"\u516c\u544a\ntext"}"""
        assertEquals(T3Response(200, "公告\ntext"), T3SdkTransport(sdk).call(T3Operation.NOTICE, emptyMap()))
    }

    @Test fun excessiveNestingFailsWithoutRecursiveStackOverflow() {
        val sdk = Sdk()
        sdk.response = "{\"code\":200,\"data\":" + "[".repeat(100) + "0" + "]".repeat(100) + "}"
        val result = T3SdkTransport(sdk).call(T3Operation.NOTICE, emptyMap())
        assertEquals(201, result.code)
        assertEquals("响应不是有效的JSON格式", result.message)
    }

    @Test fun lineFailoverMakesAtMostSixAttempts() {
        val sdk = Sdk()
        sdk.failure = { IOException("offline") }
        val result = T3SdkTransport(sdk).call(T3Operation.NOTICE, emptyMap())
        assertEquals(201, result.code)
        assertEquals(6, sdk.calls.size)
        assertEquals(6, sdk.calls.map { it.first.host }.distinct().size)
    }

    @Test fun cancellationStopsLineFailoverAndPreservesInterruptFlag() {
        val sdk = Sdk()
        sdk.failure = {
            Thread.currentThread().interrupt()
            InterruptedIOException("cancelled")
        }
        try {
            val result = T3SdkTransport(sdk).call(T3Operation.NOTICE, emptyMap())
            assertEquals("cancelled", result.message)
            assertEquals(1, sdk.calls.size)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally {
            Thread.interrupted()
        }
    }

    @Test fun responseReaderAcceptsExactlyLimitAndRejectsLargerBodies() {
        val sdk = Sdk()
        assertEquals(256 * 1024, sdk.read("字".repeat(256 * 1024)).length)
        try {
            sdk.read("字".repeat(256 * 1024 + 1))
            fail("Expected oversized response failure")
        } catch (expected: IOException) {
            assertTrue(expected.message.orEmpty().contains("256"))
        }
    }

    @Test fun alreadyInterruptedCallMakesNoNetworkAttempt() {
        val sdk = Sdk()
        val transport = T3SdkTransport(sdk)
        try {
            Thread.currentThread().interrupt()
            assertEquals(201, transport.call(T3Operation.NOTICE, emptyMap()).code)
            assertTrue(sdk.calls.isEmpty())
        } finally {
            Thread.interrupted()
        }
    }
}
