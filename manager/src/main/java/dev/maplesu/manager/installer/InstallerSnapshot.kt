package dev.maplesu.manager.installer

import java.util.Collections

internal data class BootPartitionIdentity(
    val deviceNumber: Long,
    val inode: Long,
    val filesystem: Long,
) {
    init {
        require(deviceNumber > 0 && inode > 0 && filesystem >= 0) { "INSTALLER_DEVICE_IDENTITY_INVALID" }
    }
}

internal data class BootPartitionSnapshot(
    val name: String,
    val path: String,
    val resolvedPath: String,
    val size: Long,
    val sha256: String,
    val identity: BootPartitionIdentity? = null,
)

internal class InstallerSnapshot(
    val kernelRelease: String,
    val firmware: String,
    val slotSuffix: String,
    val selinux: String,
    partitions: Map<String, BootPartitionSnapshot>,
    val signingPartitions: Set<String> = emptySet(),
) {
    val partitions: Map<String, BootPartitionSnapshot> =
        Collections.unmodifiableMap(LinkedHashMap(partitions))
}

/** Validate observations; these values alone never authorize a partition write. */
internal object InstallerSnapshotParser {
    val partitionNames = listOf("boot", "init_boot", "vendor_boot", "vbmeta", "recovery", "vbmeta_system")
    const val maxPartitionBytes = 512L * 1024 * 1024

    fun requireRoot(uid: String) {
        check(uid.trim() == "0") { "INSTALLER_ROOT_REQUIRED" }
    }

    fun slot(value: String): String = value.trim().also {
        require(it == "" || it == "_a" || it == "_b") { "INSTALLER_SLOT_INVALID" }
    }

    fun partitionPath(name: String, slot: String): String {
        require(name in partitionNames) { "INSTALLER_PARTITION_INVALID" }
        require(slot == this.slot(slot)) { "INSTALLER_SLOT_INVALID" }
        return "/dev/block/by-name/$name$slot"
    }

    fun partition(name: String, slot: String, resolved: String, size: String, digest: String,
                  identity: BootPartitionIdentity? = null): BootPartitionSnapshot {
        val path = partitionPath(name, slot)
        val target = resolved.trim()
        require(target.startsWith("/dev/block/") && target != "/dev/block/" &&
            target.all { it.isLetterOrDigit() && it.code < 128 || it in "/_.-" } &&
            target.split('/').drop(1).all { it.isNotEmpty() && it != "." && it != ".." }) {
            "INSTALLER_DEVICE_PATH_INVALID"
        }
        val bytes = size.trim().toLongOrNull()
        require(bytes != null && bytes in 1..maxPartitionBytes) { "INSTALLER_DEVICE_SIZE_INVALID" }
        val match = Regex("([0-9a-fA-F]{64})[ \\t]+\\*?" + Regex.escape(path)).matchEntire(digest.trim())
        require(match != null) { "INSTALLER_DEVICE_HASH_INVALID" }
        return BootPartitionSnapshot(name, path, target, bytes, match.groupValues[1].lowercase(), identity)
    }
}
