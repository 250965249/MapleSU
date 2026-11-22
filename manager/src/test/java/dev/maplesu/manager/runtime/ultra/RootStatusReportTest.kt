package dev.maplesu.manager.runtime.ultra

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RootStatusReportTest {
    private fun source(): JSONObject {
        val facts = JSONObject()
        for (field in listOf("uidObserved", "gidObserved", "fsidsObserved", "capsObserved", "ambientPresent",
            "capLimitObserved", "securebitsObserved", "matchesRoot")) facts.put(field, true)
        for (field in listOf("ruid", "euid", "suid", "rgid", "egid", "sgid", "fsuid", "fsgid", "securebits",
            "uidError", "gidError", "fsuidError", "fsgidError", "capLimitError", "securebitsError")) facts.put(field, 0)
        facts.put("capsError", "0").put("capLastCap", 40)
        for (field in listOf("capabilityMask", "inheritable", "permitted", "effective", "bounding", "ambient")) {
            facts.put(field, "000001ffffffffff")
        }
        val data = JSONObject().put("diagnosticVersion", 1).put("error", "0").put("rootError", "0")
            .put("phase", 6).put("process", 100).put("childPid", 101).put("childStatus", 0)
            .put("systemError", 0).put("transportError", 0).put("waitError", 0)
            .put("rootVerified", true).put("rootAttempted", true).put("rootReturned", true)
            .put("receiptComplete", true).put("childStatusValid", true).put("facts", facts)
            .put("reportAvailable", true).put("report", "get_root%3A%20OK").put("encoding", "url")
        return JSONObject().put("schemaVersion", 1).put("bridgeVersion", 1)
            .put("backend", "maplesu_ultra").put("operation", "get_root_status_report")
            .put("ok", true).put("sdkError", "OK").put("sdkErrorCode", 0).put("data", data)
    }

    private fun receipt(json: JSONObject) = requireNotNull(NativeReceipt.parse(json.toString()))

    @Test
    fun sameCallCredentialProofIsAcceptedWithoutAnotherRootCommand() {
        val original = receipt(source())
        assertTrue(rootStatusReportVerified(original))
        assertEquals(original, parseRootStatusReport(original))
    }

    @Test
    fun missingFalseOrCoercedProofAndIncompleteWorkerNeverBecomeRoot() {
        for (field in listOf("rootVerified", "rootAttempted", "rootReturned", "receiptComplete", "childStatusValid", "reportAvailable")) {
            for (value in listOf(null, false, "true", 1)) {
                val json = source()
                val data = json.getJSONObject("data")
                if (value == null) data.remove(field) else data.put(field, value)
                val parsed = parseRootStatusReport(receipt(json))
                assertFalse("$field=$value", parsed.succeeded)
                assertEquals("OK", parsed.sdkError)
                assertEquals(0, parsed.sdkErrorCode)
                assertEquals("MAPLESU_ROOT_PROOF_INVALID", JSONObject(parsed.raw).getString("bridgeError"))
                assertEquals("get_root%3A%20OK", parsed.string("report"))
            }
        }
    }

    @Test
    fun trueProofCannotHideBadCredentialsOrChildFailure() {
        for ((section, field, value) in listOf(
            Triple("facts", "euid", 10000), Triple("facts", "fsuid", 10000),
            Triple("facts", "ambient", "0000000000000000"), Triple("facts", "securebits", 1),
            Triple("data", "childStatus", 9), Triple("data", "waitError", 10),
            Triple("data", "transportError", 5), Triple("data", "rootError", "-123"),
            Triple("data", "diagnosticVersion", 2), Triple("data", "phase", 3),
        )) {
            val json = source()
            val data = json.getJSONObject("data")
            (if (section == "facts") data.getJSONObject("facts") else data).put(field, value)
            assertFalse("$section.$field", parseRootStatusReport(receipt(json)).succeeded)
        }
    }

    @Test
    fun sdkFirstErrorAndOwnerRouteArePreserved() {
        val failed = receipt(source().put("ok", false).put("sdkError", "ERR_MODULE_ROOT_KEY").put("sdkErrorCode", -123))
        assertEquals(failed, parseRootStatusReport(failed))
        val owner = receipt(source().put("operation", "probe_manager_owner_root"))
        assertEquals(owner, parseRootStatusReport(owner))
        assertFalse(rootStatusReportVerified(owner))
    }

    @Test
    fun sdkOkWithRejectedCredentialsKeepsSdkZeroAndOriginalDiagnostics() {
        val json = source().put("ok", false).put("reason", "credential proof is incomplete")
        json.getJSONObject("data").put("rootVerified", false).put("phase", 3).put("rootErrno", 17)
        json.getJSONObject("data").getJSONObject("facts").put("euid", 10000)
        val parsed = parseRootStatusReport(receipt(json))
        assertFalse(parsed.succeeded)
        assertEquals("OK", parsed.sdkError)
        assertEquals(0, parsed.sdkErrorCode)
        assertEquals("credential proof is incomplete", parsed.reason)
        assertEquals(17, parsed.int("rootErrno"))
        assertEquals(10000, parsed.obj("facts")!!.getInt("euid"))
    }
}
