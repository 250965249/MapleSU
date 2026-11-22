package dev.maplesu.manager.installer

import org.junit.Assert.*
import org.junit.Test

class InstallerSnapshotParserTest {
    private val hash = "a".repeat(64)

    private fun partition(name: String = "boot", slot: String = "_a", target: String = "/dev/block/sde12",
                          size: String = "100663296", digest: String = "$hash  /dev/block/by-name/boot_a") =
        InstallerSnapshotParser.partition(name, slot, target, size, digest)

    private fun rejects(block: () -> Unit) {
        try { block(); fail("Invalid installation observation was accepted") }
        catch (_: IllegalArgumentException) { }
    }

    @Test fun requiresActualRootUid() {
        InstallerSnapshotParser.requireRoot("0\n")
        for (uid in listOf("2000", "10000", "", "uid=0(root)", "00")) {
            try { InstallerSnapshotParser.requireRoot(uid); fail("Non-root UID accepted") }
            catch (_: IllegalStateException) { }
        }
    }

    @Test fun acceptsOnlyKnownSlotSuffixes() {
        for (slot in listOf("", "_a", "_b")) assertEquals(slot, InstallerSnapshotParser.slot("$slot\n"))
        for (slot in listOf("a", "_c", "_a\n_b", "_a; id")) rejects { InstallerSnapshotParser.slot(slot) }
    }

    @Test fun partitionAllowlistRejectsArbitraryTargets() {
        assertEquals("/dev/block/by-name/boot_b", InstallerSnapshotParser.partitionPath("boot", "_b"))
        for (name in listOf("system", "userdata", "boot_a", "../boot", "boot; id")) {
            rejects { InstallerSnapshotParser.partitionPath(name, "_a") }
        }
        rejects { InstallerSnapshotParser.partitionPath("boot", "_a\n") }
    }

    @Test fun acceptsACompleteDeviceIdentity() {
        val value = partition(digest = "${hash.uppercase()}  /dev/block/by-name/boot_a")
        assertEquals(100663296L, value.size)
        assertEquals(hash, value.sha256)
        assertEquals("/dev/block/sde12", value.resolvedPath)
        assertNull(value.identity)
    }

    @Test fun preservesDeviceIdentityWithoutConflatingItWithPartitionContents() {
        val identity = BootPartitionIdentity(179L, 45L, 23L)
        val observed = InstallerSnapshotParser.partition("boot", "_a", "/dev/block/sde12", "100663296",
            "$hash  /dev/block/by-name/boot_a", identity)
        assertEquals(identity, observed.identity)
        assertNotEquals(partition(), observed)
        for (changed in listOf(identity.copy(deviceNumber = 180L), identity.copy(inode = 46L),
            identity.copy(filesystem = 24L))) {
            assertNotEquals(observed, observed.copy(identity = changed))
        }
        assertEquals(partition(), observed.copy(identity = null))
    }

    @Test fun rejectsInvalidDeviceIdentitiesAndAcceptsAnObservedZeroFilesystem() {
        assertEquals(0L, BootPartitionIdentity(1L, 1L, 0L).filesystem)
        for (identity in listOf(Triple(0L, 1L, 1L), Triple(-1L, 1L, 1L),
            Triple(1L, 0L, 1L), Triple(1L, -1L, 1L), Triple(1L, 1L, -1L))) {
            rejects { BootPartitionIdentity(identity.first, identity.second, identity.third) }
        }
    }

    @Test fun rejectsResolvedPathsOutsideBlockDevices() {
        for (target in listOf("/data/boot.img", "/dev/block/../data/x", "/dev/block//sde12",
            "/dev/block/./sde12", "/dev/block/", "/dev/block/sde12;id", "/dev/block/\u00e9")) {
            rejects { partition(target = target) }
        }
    }

    @Test fun rejectsMissingNegativeAndOverflowSizes() {
        partition(size = InstallerSnapshotParser.maxPartitionBytes.toString())
        for (size in listOf("", "0", "-1", (InstallerSnapshotParser.maxPartitionBytes + 1).toString(),
            "9223372036854775808", "12 bytes")) {
            rejects { partition(size = size) }
        }
    }

    @Test fun bindsHashOutputToTheExactLogicalPartition() {
        for (digest in listOf(hash, "$hash  /dev/block/by-name/boot_b", "$hash  /data/boot.img",
            "$hash  /dev/block/by-name/boot_a\n$hash  /dev/block/by-name/boot_a", "z".repeat(64) + "  /dev/block/by-name/boot_a")) {
            rejects { partition(digest = digest) }
        }
    }

    @Test fun preservesASnapshotWhenTheInputMapChanges() {
        val entries = linkedMapOf("boot" to partition())
        val value = InstallerSnapshot("release", "firmware", "_a", "Enforcing", entries)
        entries.clear()
        assertEquals(setOf("boot"), value.partitions.keys)
        try { (value.partitions as MutableMap).clear(); fail("Snapshot was mutable") }
        catch (_: UnsupportedOperationException) { }
    }
}
