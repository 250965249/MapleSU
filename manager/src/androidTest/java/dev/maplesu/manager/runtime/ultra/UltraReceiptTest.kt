package dev.maplesu.manager.runtime.ultra

// Instrumented rather than a JVM unit test: the receipt code parses with android's org.json,
// which the JVM test runtime does not implement. Running it on device tests the real parser.

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Receipt contract tests. These lock the rule that decides success: a receipt is
 * successful only when `ok` is true **and** `sdkError` is `OK`, and a parse failure is a
 * bridge failure rather than a success.
 */
class UltraReceiptTest {

    @Test
    fun parsesSuccessReceipt() {
        val receipt = NativeReceipt.parse(
            """{"schemaVersion":1,"backend":"maplesu_ultra","bridgeVersion":1,
               "operation":"get_sdk_version","ok":true,"sdkError":"OK","sdkErrorCode":0,
               "data":{"version":"4.6.5"}}""".trimIndent().replace("\n", ""),
        )
        assertTrue(receipt!!.succeeded)
        assertEquals("4.6.5", receipt.string("version"))
    }

    @Test
    fun keepsSdkErrorNameAndCode() {
        val receipt = NativeReceipt.parse(
            """{"schemaVersion":1,"backend":"maplesu_ultra","bridgeVersion":1,
               "operation":"get_all_modules_list","ok":false,
               "sdkError":"ERR_MODULE_NO_BOOT","sdkErrorCode":-19998}""".trimIndent().replace("\n", ""),
        )
        assertFalse(receipt!!.succeeded)
        assertEquals("ERR_MODULE_NO_BOOT", receipt.sdkError)
        assertEquals(-19998, receipt.sdkErrorCode)
        assertNull("a refused list must not invent data", receipt.data)
    }

    @Test
    fun okTrueButNonOkSdkErrorIsNotSuccess() {
        // The bridge never emits this, but a future edit could: the decision must not
        // depend on `ok` alone.
        val receipt = NativeReceipt.parse(
            """{"schemaVersion":1,"backend":"maplesu_ultra","operation":"x","ok":true,
               "sdkError":"ERR_MODULE_ASM","sdkErrorCode":-20009}""".trimIndent().replace("\n", ""),
        )
        assertFalse(receipt!!.succeeded)
    }

    @Test
    fun nonReceiptTextIsNotSuccess() {
        assertNull(NativeReceipt.parse("install_maplesu_environment: OK，可能会自动重启"))
        assertNull(NativeReceipt.parse(""))
        assertNull(NativeReceipt.parse(null))
        // A JSON object without the backend marker is not a receipt either.
        assertNull(NativeReceipt.parse("""{"ok":true,"sdkError":"OK"}"""))
    }

    @Test
    fun bridgeFailureCarriesAnError() {
        val failure = NativeReceipt.bridgeFailure("get_sdk_version", "MAPLESU_BRIDGE_UNAVAILABLE", "dlopen failed")
        assertFalse(failure.succeeded)
        assertEquals("MAPLESU_BRIDGE_UNAVAILABLE", failure.sdkError)
        assertEquals("dlopen failed", failure.reason)
    }

    @Test
    fun managerReceiptDistinguishesPendingRebootFromCompleted() {
        val installed = NativeReceipt.parse(
            """{"schemaVersion":1,"backend":"maplesu_ultra","operation":"install_module","ok":true,
               "sdkError":"OK","sdkErrorCode":0,"data":{"mode":"normal"}}""".trimIndent().replace("\n", ""),
        )
        val pending = UltraReceipt.of(
            "op-1", "install_module", installed,
            phase = UltraPhase.HOST_ACCEPTED,
            outcome = UltraOutcome.PENDING_REBOOT,
            moduleId = "teesimulator601skpro202607210000",
            installedVersion = "6.0.1-r3",
            activeVersion = null,
            needsReboot = true,
            unknowns = mapOf("activeVersion" to "module is NotRunning"),
        )
        val json = pending.toJson()
        assertEquals("PENDING_REBOOT", json.getString("outcome"))
        assertTrue(json.getBoolean("needsReboot"))
        assertTrue(json.isNull("activeVersion"))
        assertEquals("6.0.1-r3", json.getString("installedVersion"))
        assertEquals(
            "module is NotRunning",
            json.getJSONObject("unknowns").getString("activeVersion"),
        )
        // Unknown fields stay null rather than being defaulted to a plausible value.
        assertTrue(json.isNull("environmentVersion"))
        assertTrue(json.isNull("environmentGeneration"))
    }

    @Test
    fun conditionUnmetIsItsOwnOutcome() {
        val unmet = UltraReceipt.of(
            "op-2", "install_module",
            NativeReceipt.bridgeFailure("install_module", "MAPLESU_ULTRA_ROOT_KEY_ABSENT", null),
            phase = UltraPhase.PREPARED,
            outcome = UltraOutcome.CONDITION_UNMET,
            unknowns = mapOf("environmentState" to "NotInstalled"),
        )
        assertEquals("CONDITION_UNMET", unmet.outcome.name)
        assertEquals("MAPLESU_ULTRA_ROOT_KEY_ABSENT", unmet.sdkError)
        assertEquals(
            "NotInstalled",
            JSONObject(unmet.unknowns as Map<*, *>).getString("environmentState"),
        )
    }
}
