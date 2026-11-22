package dev.maplesu.manager.workmode.ui

import dev.maplesu.manager.workmode.ModeCapabilities

/**
 * W15 六项 KSU 设置行的**唯一可见性裁决**（04 §3.4 / T6）。
 *
 * 纯函数、无 Android 依赖 → 主机单测：
 * - `visibleKsuRows(ModeCapabilities.forMode(LITE))` 必须为空（A 一行都不组合）；
 * - `visibleKsuRows(ModeCapabilities.forMode(KSU))` = 6 项全量（顺序固定）；
 * - `visibleKsuRows(ModeCapabilities.NONE)` 为空（未判定态不出行）。
 *
 * ⚠️ **不得**用现有 `KsuIsValid` 当门控：它的判据是 `isManager && version != null`，
 * 而 LITE 下 `isManager` 也为 true（04 §3.4）。
 */
enum class KsuRowId {
    KERNEL_UMOUNT,
    SELINUX_HIDE,
    SULOG,
    ADB_ROOT,
    SHELL_SU_ADB_ONLY,
    UMOUNT_MODULES_DEFAULT,
}

fun visibleKsuRows(capabilities: ModeCapabilities): List<KsuRowId> = buildList {
    if (capabilities.supportsKernelUmount) add(KsuRowId.KERNEL_UMOUNT)
    if (capabilities.supportsSelinuxHide) add(KsuRowId.SELINUX_HIDE)
    if (capabilities.supportsSulog) add(KsuRowId.SULOG)
    if (capabilities.supportsAdbRoot) {
        add(KsuRowId.ADB_ROOT)
        // 行 4/5 同属 adb_root 能力族，但两条独立开关（04 §3.4 绑定表）。
        if (capabilities.supportsShellSuAdbOnly) add(KsuRowId.SHELL_SU_ADB_ONLY)
    }
    if (capabilities.supportsKernelUmount) add(KsuRowId.UMOUNT_MODULES_DEFAULT)
}
