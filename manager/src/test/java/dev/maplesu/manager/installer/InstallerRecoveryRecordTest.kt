package dev.maplesu.manager.installer

import dev.maplesu.manager.workmode.switch.DeviceBootFacts
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InstallerRecoveryRecordTest {
    private val device = DeviceBootFacts("_a", "normal-firmware", "6.6.115-android15-8-normal")
    private val boot = InstallerRecoveryPartition("/dev/block/by-name/boot_a", 4096, "a".repeat(64))
    private val record = InstallerRecoveryRecord(
        schema = 1,
        taskId = "3f2b0c9e-6a1d-4c47-9c2e-1b7d5a0f8e33",
        state = "RESTORED",
        kernelRelease = "6.6.101-android15-8-ultra",
        firmware = "ultra-firmware",
        slotSuffix = "_a",
        partitions = mapOf("boot" to boot),
    )

    @Test
    fun originalStockRecordRemainsEligibleAcrossWorkModeKernelChange() {
        assertTrue(record.matches(device, setOf("boot")))
    }

    @Test
    fun slotAndPartitionEvidenceStillMustMatch() {
        assertFalse(record.matches(device.copy(slot = "_b"), setOf("boot")))
        assertFalse(record.matches(device, setOf("boot", "init_boot")))
        assertFalse(record.copy(partitions = mapOf("boot" to boot.copy(size = 0))).matches(device, setOf("boot")))
        assertFalse(record.copy(partitions = mapOf("boot" to boot.copy(sha256 = "changed"))).matches(device, setOf("boot")))
        assertFalse(record.copy(state = "PREPARED").matches(device, setOf("boot")))
    }
}
