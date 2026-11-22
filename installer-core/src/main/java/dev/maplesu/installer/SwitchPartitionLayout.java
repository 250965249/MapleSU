package dev.maplesu.installer;

import java.util.List;

/**
 * Partition carriers and write order (02-switch-contract §1.3).
 *
 * <p>Write init_boot before boot in both directions. Normal is installed before Ultra's
 * kernel is removed; Normal's ramdisk is restored before Ultra's kernel is installed.</p>
 */
public final class SwitchPartitionLayout {
    private SwitchPartitionLayout() {}

    /** Legacy default: LITE uses {@code boot}; KSU(LKM) uses {@code init_boot}. */
    public static String ownedPartition(WorkMode mode) {
        if (mode == null) throw new IllegalArgumentException("SWITCH_PLAN_INVALID");
        return mode == WorkMode.LITE ? "boot" : "init_boot";
    }

    /** The immutable plan selects the actual carrier within the mode's supported partitions. */
    public static boolean allowsPartition(WorkMode mode, String partition) {
        return mode != null && ("boot".equals(partition) || "init_boot".equals(partition));
    }

    /**
     * A→B(LKM): {@code [init_boot, boot]};
     * B→A: {@code [init_boot, boot]}. A future GKI mode that owns {@code boot} too collapses to one.
     */
    public static List<String> writeOrder(WorkMode to) {
        String target = ownedPartition(to);
        String source = ownedPartition(to == WorkMode.LITE ? WorkMode.KSU : WorkMode.LITE);
        if (source.equals(target)) return List.of(target);
        return List.of("init_boot", "boot");
    }
}
