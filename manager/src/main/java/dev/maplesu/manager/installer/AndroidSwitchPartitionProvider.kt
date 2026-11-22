package dev.maplesu.manager.installer

import dev.maplesu.installer.SwitchPartitionProvider
import dev.maplesu.installer.WorkMode
import dev.maplesu.installer.WritablePartition
import java.io.IOException

/**
 * Pure partition-layout policy for a mode switch (02-switch-contract §1.3 / S0-17).
 *
 * <p>`boot` is always required; `init_boot` is optional for LITE targets but mandatory when the
 * target mode owns it (KSU/LKM). `vbmeta` is observation-only and is never returned as writable.
 */
internal object SwitchPartitionLayoutPolicy {
    /**
     * 稳定声明顺序：`boot` 恒在首位（S0-17 必需分区），其余按名字排序。
     * `WritablePartition.ALLOWED` 是 Java `Set.of`，迭代顺序未定义，不能作为展示/断言顺序。
     */
    private val WRITABLE_ORDER: List<String> =
        WritablePartition.ALLOWED.sortedWith(compareBy({ if (it == "boot") 0 else 1 }, { it }))

    fun writableNames(snapshot: InstallerSnapshot): LinkedHashSet<String> {
        check("boot" in snapshot.partitions) { "INSTALLER_BLOCK_DEVICE_REQUIRED" }
        val names = linkedSetOf<String>()
        for (name in WRITABLE_ORDER) {
            if (name in snapshot.partitions) names.add(name)
        }
        return names
    }

    /** Validates the target layout before any candidate write is prepared. */
    fun requireTargetLayout(snapshot: InstallerSnapshot, toMode: WorkMode) {
        check("boot" in snapshot.partitions) { "INSTALLER_BLOCK_DEVICE_REQUIRED" }
        check(WritablePartition.FORBIDDEN !in WritablePartition.ALLOWED) { "SWITCH_PARTITION_FORBIDDEN" }
        // A mode alone does not require init_boot. The resolved plan validates its actual
        // selected carrier through SwitchPartitionLayout and the provider's get(name).
    }

    /** Real `/dev/block/by-name/<name><slot>` path, validated by the existing parser. */
    fun partitionPath(slotSuffix: String, name: String): String =
        InstallerSnapshotParser.partitionPath(name, slotSuffix)
}

/**
 * Resolves real partitions from one authenticated snapshot. The provider owns the allowlist and
 * the target-layout rule; it never resolves a caller-supplied path.
 */
internal class AndroidSwitchPartitionProvider(
    private val snapshot: InstallerSnapshot,
) : SwitchPartitionProvider {
    init {
        // `snapshot.selinux` is carried as evidence only (2026-11-01): a non-Enforcing device still
        // resolves the same allowlisted block devices, so it must not refuse the switch.
        check(snapshot.partitions.values.all { it.identity != null }) {
            "INSTALLER_DEVICE_IDENTITY_REQUIRED"
        }
    }

    override fun get(name: String): WritablePartition {
        check(name in WritablePartition.ALLOWED) { "SWITCH_PARTITION_FORBIDDEN" }
        if (name !in snapshot.partitions) throw IOException("SWITCH_PARTITION_LAYOUT_UNSUPPORTED")
        return AndroidWritablePartition(snapshot, name)
    }

    override fun available(): MutableSet<String> =
        SwitchPartitionLayoutPolicy.writableNames(snapshot)
}
