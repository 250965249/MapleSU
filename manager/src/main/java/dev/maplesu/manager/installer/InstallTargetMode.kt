// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.installer

import dev.maplesu.manager.workmode.WorkMode

/**
 * 安装/修补页「目标工作模式」的唯一枚举（**纯 Kotlin**，无 Android / Compose 依赖，主机可测）。
 *
 * 与内部 [WorkMode] 的对应（内部标识不变，只决定**这一次修补**的走向）：
 * - [ULTRA]  → [WorkMode.LITE]：Ultra 内核 release 资产/门禁
 *   （`dev.maplesu.manager.ultrakernel.{UltraKernelFlow,UltraKernelBuilder,UltraKernelReleaseCatalog}`）；
 * - [NORMAL] → [WorkMode.KSU]：KSU LKM 链路
 *   （`dev.maplesu.manager.installer.{InstallCommitCoordinator,KsuModeInstallContract,KsuKmiMatrix}`
 *   + `dev.maplesu.manager.ksu.{KsuKmiDetector,KsuKmiSelector,KsuInstallProducer}`），
 *   即 `init_boot` 补丁 + 该 KMI 的 `kernelsu.ko`。
 *
 * **选择与"当前已激活模式"无关**：用户可以在这台 Ultra 设备上修补一枚 Normal 目标的镜像。
 * 分派本身收敛在 [InstallTargetDispatch]（纯函数），UI 只消费结果。
 *
 * [productName] 只用于日志/事务记录与纯 JVM 契约测试；界面文案仍然走
 * `R.string.work_mode_lite` / `R.string.work_mode_ksu`（产品名只在
 * `res/values/strings_workmode.xml` 里出现一次）。
 */
enum class InstallTargetMode(
    /** 持久化 wire 值（一经发布不得修改；未知值按默认处理，不做猜测）。 */
    val wire: String,
    /** 该目标对应的内部工作模式。 */
    val workMode: WorkMode,
    /** 产品显示名（与 `strings_workmode.xml` 的同名键逐字一致）。 */
    val productName: String,
) {
    ULTRA("ultra", WorkMode.LITE, "MapleSU_Ultra"),

    /** MapleSU_Normal（KernelSU 分支 / LKM，`init_boot` 补丁）。 */
    NORMAL("normal", WorkMode.KSU, "MapleSU_Normal");

    companion object {
        /** 默认目标 = Ultra（全新安装 / 升级后无持久化值 / 坏值都落在这里）。 */
        val DEFAULT: InstallTargetMode = ULTRA

        /** 持久化键（中性 prefs：选择与激活模式无关，不能落 `settings`/`settings_B`）。 */
        const val PREFS_KEY: String = "install_target_mode"

        /**
         * wire → 枚举；`null` / 空 / 未知值一律返回 `null`（**禁止**在这里悄悄兜底成 Ultra，
         * 兜底只允许发生在 [InstallTargetModeStore.load]）。
         */
        fun fromWire(value: String?): InstallTargetMode? {
            val normalized = value?.trim()?.lowercase().orEmpty()
            if (normalized.isEmpty()) return null
            return entries.firstOrNull { it.wire == normalized }
        }

        /** wire → 枚举，带默认值（持久化读取/升级迁移用）。 */
        fun fromWireOrDefault(value: String?): InstallTargetMode = fromWire(value) ?: DEFAULT

        /**
         * 已激活模式 → 目标模式（兼容旧调用点：下拉传 null = 沿用原语义）。
         *
         * - `LITE` → Ultra（原实现逐字保留）；
         * - `KSU` → Normal；
         * - 未判定（`null`）→ Ultra：这是用户**显式**点安装的动作，D15 只禁止"默认执行 Lite"，
         *   不禁止用户自装，故保留原显式放行语义。
         */
        fun fromWorkMode(mode: WorkMode?): InstallTargetMode = when (mode) {
            WorkMode.KSU -> NORMAL
            WorkMode.LITE, null -> ULTRA
        }
    }
}

/**
 * 平台无关的键值端口：Android 侧 = `SharedPreferences`（见 `InstallTargetModePrefs`），
 * 主机测试 = 内存 map。存在的唯一目的是让"持久化"能在纯 JVM 里被验证。
 */
interface InstallTargetPrefsPort {
    fun getString(key: String): String?

    fun putString(key: String, value: String)
}

/**
 * 选择的持久化：默认 Ultra；进程重启/升级后从 prefs 恢复。
 *
 * 读失败（端口抛异常）也按 [InstallTargetMode.DEFAULT] 处理：UI 不能因为一个坏 prefs 就打不开。
 */
class InstallTargetModeStore(private val prefs: InstallTargetPrefsPort) {

    fun load(): InstallTargetMode {
        val raw = runCatching { prefs.getString(InstallTargetMode.PREFS_KEY) }.getOrNull()
        return InstallTargetMode.fromWireOrDefault(raw)
    }

    /** @return 是否成功落盘（失败不抛，选择仍然在本进程内生效）。 */
    fun save(mode: InstallTargetMode): Boolean = runCatching {
        prefs.putString(InstallTargetMode.PREFS_KEY, mode.wire)
    }.isSuccess
}

/**
 * 一次安装事务的目标模式**快照**。
 *
 * 事务一旦开始（= 点「下一步」那一刻捕获），之后用户再改选择也不会影响它：
 * 快照只承载不可变枚举值，不引用任何可变的页面状态。
 */
@JvmInline
value class InstallTargetSnapshot(val mode: InstallTargetMode)

/**
 * 页面级选择状态（纯 Kotlin，可 JVM 测）。
 *
 * - [selected] 只由用户点击（[select]）改变；
 * - 安装/切换事务进行中时 [lock]，此后 [select] **不生效**（返回原值），
 *   即使 UI 层的禁用态漏画也不会让已开始的事务换目标；
 * - [snapshot] 在事务开始那一刻取值，作为传给执行侧的唯一目标。
 */
class InstallTargetSelection(initial: InstallTargetMode = InstallTargetMode.DEFAULT) {

    var selected: InstallTargetMode = initial
        private set

    var locked: Boolean = false
        private set

    /** @return 生效后的选择（[locked] 时保持原值，不产生任何修改）。 */
    fun select(mode: InstallTargetMode): InstallTargetMode {
        if (!locked) selected = mode
        return selected
    }

    fun lock() {
        locked = true
    }

    fun unlock() {
        locked = false
    }

    fun snapshot(): InstallTargetSnapshot = InstallTargetSnapshot(selected)
}

/** 选择器可用性策略（安装/切换事务进行中禁用，但**仍然可见**）。 */
object InstallTargetModePolicy {
    fun selectable(installRunning: Boolean, switchRunning: Boolean): Boolean =
        !installRunning && !switchRunning
}
