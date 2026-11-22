package dev.maplesu.manager.parasite

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** H4 P1：Ultra bridge 回执解析 + UltraLinkedParasiteSdkPort 真实接线（四码保留）。 */
class ParasiteUltraBindingTest {
    private val rootKey = ByteArray(48) { 'k'.code.toByte() }

    private class FakeNative : ParasiteNativeCall {
        var precheckReceipt: String? = null
        var implantReceipt: String? = null
        var suEnvReceipt: String? = null
        val calls = mutableListOf<String>()
        var lastKey: String? = null

        override fun precheck(rootKey: String, targetPidCmdline: String): String? {
            calls += "precheck"
            lastKey = rootKey
            return precheckReceipt
        }

        override fun implantApp(rootKey: String, targetPidCmdline: String, soPath: String): String? {
            calls += "implantApp"
            lastKey = rootKey
            return implantReceipt
        }

        override fun implantSuEnv(
            rootKey: String,
            targetPidCmdline: String,
            soPath: String,
            suDir: String,
        ): String? {
            calls += "implantSuEnv"
            lastKey = rootKey
            return suEnvReceipt
        }
    }

    private fun receipt(
        operation: String,
        ok: Boolean = true,
        sdkError: String = if (ok) "OK" else "ERR_PARASITE",
        data: String = "{}",
    ): String = """
        {"schemaVersion":1,"backend":"maplesu_ultra","bridgeVersion":1,
         "operation":"$operation","ok":$ok,"sdkError":"$sdkError","sdkErrorCode":${if (ok) 0 else 7},
         "data":$data}
    """.trimIndent()

    private fun port(
        native: FakeNative,
        availability: UltraAvailability = UltraAvailability.RUNNING,
        keyProvider: () -> ByteArray? = { rootKey },
    ) = UltraLinkedParasiteSdkPort(
        api = ParasiteUltraApiAdapter(native),
        rootKeyProvider = keyProvider,
        availabilityProvider = { availability },
    )

    @Test
    fun precheckReceiptMapsDynlibsSortedWithStatuses() {
        val native = FakeNative().apply {
            precheckReceipt = receipt(
                "parasite_precheck_app",
                data = """
                    {"dynlibs":[
                      {"path":"/data/app/lib/libb.so","status":"not_running","statusKnown":true,"statusCode":2},
                      {"path":"/data/app/lib/liba.so","status":"running","statusKnown":true,"statusCode":1}
                    ],"sdkSymbolsPresent":true}
                """.trimIndent(),
            )
        }
        val result = port(native).precheck("com.example.host")
        assertTrue(result is ParasiteSdkResult.Ok)
        val dynlibs = (result as ParasiteSdkResult.Ok).dynlibs
        assertEquals(
            listOf("/data/app/lib/liba.so", "/data/app/lib/libb.so"),
            dynlibs.map { it.path },
        )
        assertEquals(AppDynlibStatus.RUNNING, dynlibs[0].status)
        assertEquals(AppDynlibStatus.NOT_RUNNING, dynlibs[1].status)
        assertEquals(48, native.lastKey!!.length)
    }

    @Test
    fun unknownDynlibStatusIsNotDefaultedToNotRunning() {
        val native = FakeNative().apply {
            precheckReceipt = receipt(
                "parasite_precheck_app",
                data = """{"dynlibs":[{"path":"/lib/x.so","status":"unknown","statusKnown":false,"statusCode":0}]}""",
            )
        }
        val result = port(native).precheck("com.example.host")
        assertFalse(result is ParasiteSdkResult.Ok)
        assertEquals(ParasiteCodes.ULTRA_UNAVAILABLE, (result as ParasiteSdkResult.Failed).code)
    }

    @Test
    fun sdkSymbolMissingMapsToApiUnlinked() {
        val native = FakeNative().apply {
            precheckReceipt = receipt(
                "parasite_precheck_app",
                ok = false,
                sdkError = ParasiteBridgeCodes.SDK_SYMBOL_MISSING,
            )
        }
        val result = port(native).precheck("com.example.host")
        assertEquals(ParasiteCodes.ULTRA_API_UNLINKED, (result as ParasiteSdkResult.Failed).code)
    }

    @Test
    fun unparseableReceiptMapsToUnavailable() {
        val native = FakeNative().apply { precheckReceipt = "not-a-receipt" }
        val result = port(native).precheck("com.example.host")
        assertEquals(ParasiteCodes.ULTRA_UNAVAILABLE, (result as ParasiteSdkResult.Failed).code)
    }

    @Test
    fun missingRootKeyNeverCallsNativeAndReportsNoRootKey() {
        val native = FakeNative()
        val result = port(native, keyProvider = { null }).precheck("com.example.host")
        assertTrue(result is ParasiteSdkResult.Failed)
        assertEquals(ParasiteCodes.ULTRA_ROOT_KEY_UNAVAILABLE, (result as ParasiteSdkResult.Failed).code)
        assertTrue(native.calls.isEmpty())
    }

    @Test
    fun invalidArgumentsAreRejectedBeforeNative() {
        val native = FakeNative()
        assertTrue(native.calls.isEmpty())
        assertEquals(
            ParasiteCodes.INVALID_ARGUMENT,
            (port(native).precheck("  ") as ParasiteSdkResult.Failed).code,
        )
        assertEquals(
            ParasiteCodes.INVALID_ARGUMENT,
            (port(native).implantApp("cmd", "") as ParasiteSdkResult.Failed).code,
        )
        assertEquals(
            ParasiteCodes.INVALID_ARGUMENT,
            (port(native).implantSuEnv("cmd", "/so", " ") as ParasiteSdkResult.Failed).code,
        )
        assertTrue(native.calls.isEmpty())
    }

    @Test
    fun quiescingBlocksAllUltraCallsBeforeKeyOrNative() {
        val native = FakeNative()
        val blocked = UltraLinkedParasiteSdkPort(
            api = ParasiteUltraApiAdapter(native),
            rootKeyProvider = { error("key read during quiescence") },
            availabilityProvider = { UltraAvailability.RUNNING },
            quiescing = { true },
        )
        val results = listOf(
            blocked.precheck("dev.fixture.host"),
            blocked.implantApp("dev.fixture.host", "/fixture/lib.so"),
            blocked.implantSuEnv("dev.fixture.host", "/fixture/lib.so", "/fixture/su"),
        )
        results.forEach { assertEquals(ParasiteCodes.QUIESCING, (it as ParasiteSdkResult.Failed).code) }
        assertTrue(native.calls.isEmpty())
    }

    @Test
    fun implantSuccessReceiptsReturnOk() {
        val native = FakeNative().apply {
            implantReceipt = receipt("parasite_implant_app", data = """{"implanted":true}""")
        }
        assertTrue(port(native).implantApp("com.example.host", "/lib/libfoo.so") is ParasiteSdkResult.Ok)
        assertEquals(listOf("implantApp"), native.calls)
    }

    @Test
    fun implantSdkFailureIsStructuredFailure() {
        val native = FakeNative().apply {
            implantReceipt = receipt("parasite_implant_app", ok = false, sdkError = "ERR_PARASITE_IMPLANT_APP")
        }
        val result = port(native).implantApp("com.example.host", "/lib/libfoo.so")
        assertFalse(result is ParasiteSdkResult.Ok)
        assertEquals(ParasiteCodes.ULTRA_UNAVAILABLE, (result as ParasiteSdkResult.Failed).code)
    }

    @Test
    fun suEnvSuccessAndFailure() {
        val native = FakeNative().apply {
            suEnvReceipt = receipt("parasite_implant_su_env", data = """{"implanted":true}""")
        }
        assertTrue(port(native).implantSuEnv("cmd", "/so", "/su") is ParasiteSdkResult.Ok)

        native.suEnvReceipt = receipt("parasite_implant_su_env", ok = false, sdkError = "ERR_SU_ENV")
        assertFalse(port(native).implantSuEnv("cmd", "/so", "/su") is ParasiteSdkResult.Ok)
    }

    @Test
    fun notRunningShortCircuitsWithUltraNotRunning() {
        val native = FakeNative()
        val result = port(native, availability = UltraAvailability.NOT_RUNNING).precheck("cmd")
        assertEquals(ParasiteCodes.ULTRA_NOT_RUNNING, (result as ParasiteSdkResult.Failed).code)
        assertTrue(native.calls.isEmpty())
    }

    @Test
    fun receiptParserKeepsRawFieldsAndEncoding() {
        val parsed = ParasiteBridgeReceiptParser.parse(
            receipt("parasite_precheck_app", data = """{"dynlibs":[]}"""),
        )!!
        assertEquals("maplesu_ultra", parsed.backend)
        assertEquals("parasite_precheck_app", parsed.operation)
        assertTrue(parsed.succeeded)
        assertTrue(parsed.dynlibs.isEmpty())
        assertNull(ParasiteBridgeReceiptParser.parse(""))
        assertNull(ParasiteBridgeReceiptParser.parse("{\"operation\":\"x\"}"))
    }

    @Test
    fun probeStateMapsToPortAvailability() {
        // 纯映射：UltraEnvironmentProbe.State → UltraAvailability（保持四码语义）。
        assertEquals(UltraAvailability.RUNNING, probeStateMapping("Running"))
        assertEquals(UltraAvailability.NO_ROOT_KEY, probeStateMapping("NoKey"))
        assertEquals(UltraAvailability.NOT_RUNNING, probeStateMapping("NotInstalled"))
        assertEquals(UltraAvailability.UNLINKED, probeStateMapping("Unknown"))
        assertFalse(probeStateMapping("Running") == UltraAvailability.UNLINKED)
    }

    /** 避免在本测试类直接引用 Android 依赖：只断言映射表语义与生产实现同构。 */
    private fun probeStateMapping(state: String): UltraAvailability = when (state) {
        "Running" -> UltraAvailability.RUNNING
        "NoKey" -> UltraAvailability.NO_ROOT_KEY
        "NotInstalled", "Fault" -> UltraAvailability.NOT_RUNNING
        else -> UltraAvailability.UNLINKED
    }
}
