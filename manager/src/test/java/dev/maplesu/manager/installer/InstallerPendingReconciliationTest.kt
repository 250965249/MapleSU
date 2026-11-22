package dev.maplesu.manager.installer

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class InstallerPendingReconciliationTest {
    private val boot = "1".repeat(64)
    private val init = "2".repeat(64)
    private val candidate = "3".repeat(64)
    private fun snapshot(bootHash: String = boot, initHash: String = init, slot: String = "_b") =
        InstallerSnapshot("kernel", "firmware", slot, "Enforcing", listOf("boot" to bootHash, "init_boot" to initHash)
            .associate { (name, hash) -> name to BootPartitionSnapshot(name,
                "/dev/block/by-name/$name$slot", "/dev/block/$name", 4096, hash) })

    private fun record(state: String = "RECOVERY_REQUIRED") = JSONObject().apply {
        put("kind", "NATIVE"); put("state", state); put("bootId", "old-boot")
        put("snapshot", JSONObject().apply {
            put("slotSuffix", "_b"); put("firmware", "firmware")
            put("partitions", JSONObject().apply {
                put("boot", JSONObject().put("size", 4096).put("sha256", boot))
                put("init_boot", JSONObject().put("size", 4096).put("sha256", init))
            })
        })
        put("expected", JSONObject().put("boot", candidate).put("init_boot", init))
    }

    @Test fun restoredBytesRetireAStaleRecoveryRecordWithoutRewritingPartitions() {
        assertEquals("RESTORED", InstallerPending.reconciledInstallState(record(), snapshot(), "new-boot"))
    }

    @Test fun completeTargetBytesAreVerifiedOnlyAfterAReboot() {
        assertEquals("BOOT_IMAGE_VERIFIED", InstallerPending.reconciledInstallState(record(), snapshot(candidate), "new-boot"))
        assertEquals("REBOOT_REQUIRED", InstallerPending.reconciledInstallState(record(), snapshot(candidate), "old-boot"))
    }

    @Test fun partialWritesAndAnotherSlotRemainPending() {
        assertNull(InstallerPending.reconciledInstallState(record(), snapshot(candidate, "4".repeat(64)), "new-boot"))
        assertNull(InstallerPending.reconciledInstallState(record(), snapshot(slot = "_a"), "new-boot"))
        val changedFirmware = record().apply { getJSONObject("snapshot").put("firmware", "other-firmware") }
        assertNull(InstallerPending.reconciledInstallState(changedFirmware, snapshot(), "new-boot"))
    }

    @Test fun anExplicitNewSwitchSupersedesOnlyUnwrittenPreparations() {
        for (state in listOf("PREPARING", "PREPARED")) {
            assertEquals("CANCELLED", InstallerPending.reconciledInstallState(record(state), null, "new-boot"))
        }
        assertNull(InstallerPending.reconciledInstallState(record("BOOT_IMAGE_VERIFIED"), snapshot(), "new-boot"))
    }

    @Test fun statusObservationPreservesCandidatePreparations() {
        for (state in listOf("PREPARING", "PREPARED")) {
            assertNull(InstallerPending.reconciledInstallState(record(state), null, "new-boot", cancelPrepared = false))
        }
    }

    @Test fun statusObservationOnlyRetiresCompletelyVerifiedInterruptedWrites() {
        for (state in listOf("WRITING", "RESTORING", "RECOVERY_REQUIRED")) {
            assertEquals("RESTORED", InstallerPending.reconciledInstallState(record(state), snapshot(), "new-boot", cancelPrepared = false))
            assertEquals("BOOT_IMAGE_VERIFIED", InstallerPending.reconciledInstallState(record(state), snapshot(candidate), "new-boot", cancelPrepared = false))
            assertNull(InstallerPending.reconciledInstallState(record(state), snapshot(candidate, "4".repeat(64)), "new-boot", cancelPrepared = false))
        }
    }

    @Test fun anUnchangedCandidateWithARecordedRestoreIsRestoredRatherThanWaitingAgain() {
        val restored = record().put("expected", JSONObject().put("boot", boot).put("init_boot", init))
        assertEquals("RESTORED", InstallerPending.reconciledInstallState(restored, snapshot(), "new-boot"))
    }

    @Test fun legacyBootRecordsUseTheirOriginalAndExpectedDigests() {
        val native = record()
        val legacy = native.getJSONObject("snapshot")
        legacy.put("state", "RECOVERY_REQUIRED").put("bootId", "old-boot").put("expectedSha256", candidate)
        assertEquals("RESTORED", InstallerPending.reconciledInstallState(legacy, snapshot(), "new-boot"))
        assertEquals("BOOT_IMAGE_VERIFIED", InstallerPending.reconciledInstallState(legacy, snapshot(candidate), "new-boot"))
    }

    @Test fun vivoReconciliationChecksVendorBytesAsPartOfTheWholeBatch() {
        val beforeVendor = "5".repeat(64)
        val afterVendor = "6".repeat(64)
        val pending = record().apply {
            getJSONObject("snapshot").getJSONObject("partitions").put("vendor_boot",
                JSONObject().put("size", 4096).put("sha256", beforeVendor))
            getJSONObject("expected").put("vendor_boot", afterVendor)
        }
        fun vivo(bootHash: String, vendorHash: String) = snapshot(bootHash).let { base ->
            InstallerSnapshot(base.kernelRelease, base.firmware, base.slotSuffix, base.selinux,
                base.partitions + ("vendor_boot" to BootPartitionSnapshot("vendor_boot",
                    "/dev/block/by-name/vendor_boot_b", "/dev/block/vendor_boot", 4096, vendorHash)))
        }
        assertNull(InstallerPending.reconciledInstallState(pending, vivo(candidate, beforeVendor), "new-boot"))
        assertNull(InstallerPending.reconciledInstallState(pending, vivo(boot, afterVendor), "new-boot"))
        assertEquals("BOOT_IMAGE_VERIFIED", InstallerPending.reconciledInstallState(pending, vivo(candidate, afterVendor), "new-boot"))
        assertEquals("RESTORED", InstallerPending.reconciledInstallState(pending, vivo(boot, beforeVendor), "new-boot"))
        assertNull(InstallerPending.reconciledInstallState(pending, snapshot(candidate), "new-boot"))
    }
}
