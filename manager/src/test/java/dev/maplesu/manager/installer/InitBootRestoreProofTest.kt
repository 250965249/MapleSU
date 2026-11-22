package dev.maplesu.manager.installer

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class InitBootRestoreProofTest {
    @Test fun ownedInitBootRemovalKeepsItsCarrierAndDoesNotBecomeStock() {
        val current = "a".repeat(64)
        val restored = "b".repeat(64)
        val snapshot = InstallerSnapshot("6.6-test", "fw", "_a", "Enforcing", mapOf(
            "boot" to BootPartitionSnapshot("boot", "", "", 8192, "c".repeat(64)),
            "init_boot" to BootPartitionSnapshot("init_boot", "", "", 8192, current)))
        val record = JSONObject().put("operation", "RESTORE_STOCK")
            .put("originalSource", "maplesu-owned").put("restorationKind", "OWNED_WRITES_REMOVED")
            .put("ownedRemovalSource", "IMAGE_BOUND_INIT_BOOT_INPUT")
            .put("stockRestoreCoverage", "IMAGE_OWNED_RECORD").put("stockRestoreSources", JSONObject())
            .put("stockRestoreTargets", JSONArray(listOf("init_boot")))
            .put("ownedRemovalProof", JSONObject().put("init_boot", current))
            .put("originals", JSONObject().put("init_boot", restored))
        assertEquals(setOf("init_boot"), StockRestoreTargets.saved(record, snapshot, emptyList()))
        assertEquals(ImageRestorationKind.OWNED_WRITES_REMOVED, StockRestoreTargets.restorationKind(record))
        record.getJSONObject("ownedRemovalProof").put("init_boot", "d".repeat(64))
        assertTrue(runCatching { StockRestoreTargets.saved(record, snapshot, emptyList()) }.isFailure)
    }
}
