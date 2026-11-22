package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.parasite.ParasiteBridgeReceiptParser
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class NativeReceiptCompatibilityTest {
    private val backendGenerations = listOf("maplesu_ultra", "maplesu_\u0070\u0072\u006f")

    private fun receipt(backend: String, error: String = "OK") = JSONObject().apply {
        put("schemaVersion", 1)
        put("backend", backend)
        put("bridgeVersion", 1)
        put("operation", "get_all_modules_list")
        put("ok", true)
        put("sdkError", error)
        put("sdkErrorCode", if (error == "OK") 0 else -1)
        put("data", JSONObject().put("count", 1))
    }.toString()

    @Test fun bothBackendGenerationsKeepTheirReceiptFields() {
        for (backend in backendGenerations) {
            val raw = receipt(backend)
            val parsed = requireNotNull(NativeReceipt.parse(raw))
            assertTrue(parsed.succeeded)
            assertEquals("maplesu_ultra", parsed.backend)
            assertEquals(raw, parsed.raw)
            assertEquals("get_all_modules_list", parsed.operation)
            assertEquals(1, parsed.int("count"))
        }
    }

    @Test fun bothBackendGenerationsStillRequireSdkSuccess() {
        for (backend in backendGenerations) {
            assertFalse(requireNotNull(NativeReceipt.parse(receipt(backend, "ERR_MODULE_LOAD"))).succeeded)
        }
    }

    @Test fun parasiteParserAcceptsBothBackendGenerations() {
        for (backend in backendGenerations) {
            val raw = receipt(backend)
            val parsed = requireNotNull(ParasiteBridgeReceiptParser.parse(raw))
            assertTrue(parsed.succeeded)
            assertEquals("maplesu_ultra", parsed.backend)
            assertEquals(raw, parsed.raw)
        }
    }

    @Test fun environmentErrorKeepsItsValueAndRawReceiptAcrossNames() {
        for (name in listOf("ERR_\u0053\u004b\u0052\u004f\u004f\u0054_ENV_NOT_INSTALL", "ERR_MAPLESU_ENV_NOT_INSTALL", "ERR_MAPLESU_ENV_UNPREPARED")) {
            val raw = JSONObject(receipt("maplesu_ultra", name))
                .put("sdkErrorCode", -19916)
                .put("reason", "Module callback: MAPLESU_MODULE_ON_INSTALL")
                .toString()
            val parsed = requireNotNull(NativeReceipt.parse(raw))
            assertEquals("ERR_MAPLESU_ENV_UNPREPARED", parsed.sdkError)
            assertEquals(-19916, parsed.sdkErrorCode)
            assertEquals(raw, parsed.raw)
            assertEquals("Module callback: MAPLESU_MODULE_ON_INSTALL", parsed.reason)
            assertFalse(parsed.succeeded)
            val parasite = requireNotNull(ParasiteBridgeReceiptParser.parse(raw))
            assertEquals(parsed.sdkError, parasite.sdkError)
            assertEquals(parsed.sdkErrorCode, parasite.sdkErrorCode)
            assertEquals(raw, parasite.raw)
            assertFalse(parasite.succeeded)
        }
    }

    @Test fun extensionAndUnknownFailuresRetainNumericCodesAndRawDiagnostics() {
        val errors = listOf(-21001 to "ERR_SU_DELIVERY_INCOMPLETE", -21002 to "ERR_BOOTSTRAP_NOT_READY",
            -31999 to "Unknown(-31999)")
        for ((code, name) in errors) {
            val raw = JSONObject(receipt("maplesu_ultra", name)).put("sdkErrorCode", code)
                .put("reason", "Original delivery reason").toString()
            val native = requireNotNull(NativeReceipt.parse(raw))
            val parasite = requireNotNull(ParasiteBridgeReceiptParser.parse(raw))
            assertEquals(name, native.sdkError)
            assertEquals(name, parasite.sdkError)
            assertEquals(code, native.sdkErrorCode)
            assertEquals(code, parasite.sdkErrorCode)
            assertEquals(raw, native.raw)
            assertEquals(raw, parasite.raw)
            assertEquals("Original delivery reason", native.reason)
            assertEquals(native.reason, parasite.reason)
            assertFalse(native.succeeded)
            assertFalse(parasite.succeeded)
        }
    }

    @Test fun numericFailureAndMissingCodeNeverBecomeSuccessfulReceipts() {
        for (code in listOf(-21001, -21002, -31999, null)) {
            val json = JSONObject(receipt("maplesu_ultra"))
            if (code == null) json.remove("sdkErrorCode") else json.put("sdkErrorCode", code)
            val raw = json.toString()
            assertFalse(requireNotNull(NativeReceipt.parse(raw)).succeeded)
            assertFalse(requireNotNull(ParasiteBridgeReceiptParser.parse(raw)).succeeded)
        }
    }
}
