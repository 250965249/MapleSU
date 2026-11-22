package dev.maplesu.manager.liteweb.daemon

import dev.maplesu.manager.runtime.ultra.NativeReceipt
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class DaemonSdkFactMappingTest {
    @get:Rule val temporary = TemporaryFolder()
    private fun receipt(data: JSONObject, success: Boolean = true) = NativeReceipt(
        1, "maplesu-ultra", 1, "test", success, if (success) "OK" else "SDK_ERROR", 0, null, data, "",
    )

    @Test fun sdkReceiptMapsOnlyExplicitSuccessfulStates() {
        assertEquals(DaemonUltraState.RUNNING, DaemonSdkFactMapping.state(receipt(JSONObject().put("state", "Running"))))
        assertEquals(DaemonUltraState.NOT_INSTALLED, DaemonSdkFactMapping.state(receipt(JSONObject().put("state", "NotInstalled"))))
        assertEquals(DaemonUltraState.UNKNOWN, DaemonSdkFactMapping.state(receipt(JSONObject().put("state", "NotInstalled"), false)))
        assertEquals(DaemonUltraState.UNKNOWN, DaemonSdkFactMapping.state(receipt(JSONObject().put("state", "FutureState"))))
    }

    @Test fun sdkModulesDecodeOneReceiptAndKeepUnknownRuntimeState() {
        val row = JSONObject().put("state", "FutureState").put("desc", JSONObject()
            .put("id32", "tee").put("name", "TEE+Simulator").put("desc", "a%2Bb")
            .put("ver", "6.0").put("author", "MapleSU").put("web_ui", true))
        val actual = DaemonSdkFactMapping.modules(receipt(JSONObject().put("modules", JSONArray().put(row))))
        assertEquals("", actual.error)
        assertTrue(actual.json, actual.json.contains("\"name\":\"TEE Simulator\""))
        assertTrue(actual.json, actual.json.contains("\"description\":\"a+b\""))
        assertTrue(actual.json, actual.json.contains("\"ultraState\":\"FutureState\""))
        assertTrue(actual.json, actual.json.contains("\"enabled\":false"))
        assertFalse(actual.json, actual.json.contains("ksu"))
    }

    @Test fun newControlReceiptPreservesDesiredStateAndLegacyRowsHaveNoToggle() {
        val control = JSONObject().put("abiVersion", 1).put("enabled", false)
            .put("needsReboot", true).put("supportsEnableToggle", true)
        val row = JSONObject().put("state", "Running").put("control", control)
            .put("desc", JSONObject().put("id32", "a".repeat(32)))
        fun mapped() = DaemonSdkFactMapping.modules(receipt(JSONObject().put("modules", JSONArray().put(row)))).json
        assertTrue(mapped().contains("\"canToggle\":true"))
        assertTrue(mapped().contains("\"enabled\":false"))
        assertTrue(mapped().contains("\"needsReboot\":true"))
        row.remove("control")
        assertTrue(mapped().contains("\"canToggle\":false"))
        assertTrue(mapped().contains("\"enabled\":true"))
        row.put("control", control.put("enabled", "false"))
        assertTrue(mapped().contains("\"canToggle\":false"))
    }

    @Test fun unreadableOrMalformedListIsNotAnEmptySuccessfulList() {
        for (actual in listOf(
            DaemonSdkFactMapping.modules(receipt(JSONObject(), false)),
            DaemonSdkFactMapping.modules(receipt(JSONObject())),
            DaemonSdkFactMapping.modules(receipt(JSONObject().put("modules", JSONArray().put(JSONObject())))),
        )) {
            assertTrue(actual.error.isNotEmpty())
            assertTrue(actual.responseJson().contains("\"ok\":false"))
        }
        assertEquals("[]", DaemonSdkFactMapping.modules(receipt(JSONObject().put("modules", JSONArray()))).json)
    }

    @Test fun committedMetadataRequiresSchemaBootVerificationAndNoPending() {
        val json = JSONObject().put("schema", 1).put("bootId", "now").put("current", "B")
            .put("boot", JSONObject().put("activeMode", "B").put("verifiedBootId", "now"))
        assertTrue(DaemonSdkFactMapping.committedMode(json.toString())!!.isCurrentNormal("now"))
        json.put("pending", JSONObject().put("to", "A"))
        assertFalse(DaemonSdkFactMapping.committedMode(json.toString())!!.isCurrentNormal("now"))
        json.put("schema", 99)
        assertEquals(null, DaemonSdkFactMapping.committedMode(json.toString()))
        assertEquals(null, DaemonSdkFactMapping.committedMode("not json"))
    }

    @Test fun realRecoveryAccessWithNoKeyStaysUnknownAndCoalescesReads() {
        var sdkOpenReads = 0
        var metadataReads = 0
        var nanos = 0L
        val sdk = DaemonUltraSdkAccess(
            shell = DaemonShell { sdkOpenReads++; DaemonShellResult(1, "") },
            recoveryRoot = temporary.newFolder("recovery").absolutePath,
        )
        val source = DaemonUltraRuntimeFacts(
            access = sdk,
            readBootId = { "now" },
            readCommittedMode = { metadataReads++; DaemonCommittedMode("now", "now", "B", "B", false) },
            nowNanos = { nanos },
        )
        assertEquals("UNKNOWN", source.snapshot().mode)
        assertEquals("NoKey", source.snapshot().probe)
        assertEquals(1, sdkOpenReads)
        assertEquals(0, metadataReads)
        assertTrue(source.ultraModules().error.isNotEmpty())
        assertEquals(1, sdkOpenReads)
        nanos = 1_000_000_000L
        assertEquals("UNKNOWN", source.snapshot().mode)
        assertEquals(2, sdkOpenReads)
        assertEquals(0, metadataReads)
    }
}
