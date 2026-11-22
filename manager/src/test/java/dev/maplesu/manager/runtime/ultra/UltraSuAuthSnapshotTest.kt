// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime.ultra

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class UltraSuAuthSnapshotTest {
    private fun receipt(data: JSONObject? = null, ok: Boolean = true, error: String = "OK") =
        NativeReceipt.parse(JSONObject()
            .put("backend", "maplesu_ultra").put("operation", "get_su_auth_list")
            .put("ok", ok).put("sdkError", error).put("data", data).toString())!!

    private fun data(vararg packages: Any) = JSONObject()
        .put("packages", JSONArray(packages.toList())).put("count", packages.size).put("encoding", "url")

    @Test fun missingPayloadIsFailureRatherThanEmptySuccess() {
        assertFalse(parseSuAuthSnapshot(receipt()).ok)
        assertFalse(parseSuAuthSnapshot(receipt(JSONObject())).ok)
    }

    @Test fun genuineEmptyListIsLoadedSuccessfully() {
        val snapshot = parseSuAuthSnapshot(receipt(data()))
        assertTrue(snapshot.ok)
        assertEquals(emptyList<String>(), snapshot.packages)
    }

    @Test fun validEncodedNamesAreDecoded() {
        val snapshot = parseSuAuthSnapshot(receipt(data("com.example.%61pp", "dev.maplesu.manager")))
        assertTrue(snapshot.ok)
        assertEquals(listOf("com.example.app", "dev.maplesu.manager"), snapshot.packages)
    }

    @Test fun truncatedListAndWrongEncodingAreFailures() {
        assertFalse(parseSuAuthSnapshot(receipt(data("com.example.app").put("count", 2))).ok)
        assertFalse(parseSuAuthSnapshot(receipt(data("com.example.app").put("count", "1"))).ok)
        assertFalse(parseSuAuthSnapshot(receipt(data("com.example.app").put("encoding", "raw"))).ok)
    }

    @Test fun malformedEntriesAreNotSilentlyDropped() {
        for (entry in listOf<Any>(42, JSONObject.NULL, "", "null", "com.example.%", "com.example.+app", "app%00")) {
            assertFalse("Malformed entry: $entry", parseSuAuthSnapshot(receipt(data(entry))).ok)
        }
    }

    @Test fun failedReceiptPreservesSdkFailure() {
        val original = receipt(ok = false, error = "EIO")
        val snapshot = parseSuAuthSnapshot(original)
        assertFalse(snapshot.ok)
        assertSame(original, snapshot.receipt)
    }

    @Test fun writeAdapterRequiresBothSuccessFields() {
        assertEquals("OK", receipt(ok = true, error = "OK").suAuthWriteError())
        assertEquals("INVALID_RECEIPT", receipt(ok = false, error = "OK").suAuthWriteError())
        assertEquals("EIO", receipt(ok = true, error = "EIO").suAuthWriteError())
    }
}
