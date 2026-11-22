// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

/**
 * 设置页的 KSU feature 开关（与 7K/上游 `uapi/feature.h` 对齐）。
 *
 * feature name ↔ id 固定（`uapi/feature.h:4-14`）：5 号已废弃，**不得复用**。
 * 全部操作落在 ksud 的 `feature` 子命令上；未接线时返回 unknown/null/false 并记录。
 */
object KsuFeature {
    const val SU_COMPAT = "su_compat"
    const val KERNEL_UMOUNT = "kernel_umount"
    const val SULOG = "sulog"
    const val ADB_ROOT = "adb_root"
    const val SELINUX_HIDE = "selinux_hide"
    const val SHELL_SU_ADB_ONLY = "shell_su_adb_only"

    /** 状态返回值：`supported|managed|unsupported|unknown`（现有四值语义）。 */
    const val STATUS_SUPPORTED = "supported"
    const val STATUS_MANAGED = "managed"
    const val STATUS_UNSUPPORTED = "unsupported"
    const val STATUS_UNKNOWN = "unknown"

    const val DEPRECATED_ID_5 = 5

    val idByName: Map<String, Int> = linkedMapOf(
        SU_COMPAT to 0,
        KERNEL_UMOUNT to 1,
        SULOG to 2,
        ADB_ROOT to 3,
        SELINUX_HIDE to 4,
        SHELL_SU_ADB_ONLY to 6,
    )

    fun isValid(name: String): Boolean = name in idByName
}

data class KsuSettingsFeatureRead(
    val suCompatStatus: String,
    val values: Map<String, Long?>,
    val receipts: Map<String, KsuShellResult> = emptyMap(),
) {
    companion object {
        fun features(includeExtras: Boolean): List<String> = listOf(KsuFeature.SU_COMPAT) +
            if (includeExtras) listOf(KsuFeature.SULOG, KsuFeature.ADB_ROOT,
                KsuFeature.SHELL_SU_ADB_ONLY, KsuFeature.KERNEL_UMOUNT, KsuFeature.SELINUX_HIDE)
            else emptyList()
    }
}

interface KsuSettingsFeature {
    /** supported|managed|unsupported|unknown */
    fun status(feature: String): String
    /** 内核当前生效值；不可得 → null */
    fun value(feature: String): Long?
    /** `--config` 持久值；不可得 → null */
    fun persistValue(feature: String): Long?
    fun set(feature: String, enabled: Boolean): Boolean
    fun save(): Boolean

    fun readSettings(includeExtras: Boolean): KsuSettingsFeatureRead = KsuSettingsFeatureRead(
        status(KsuFeature.SU_COMPAT), KsuSettingsFeatureRead.features(includeExtras).associateWith(::value),
    )
}

/**
 * 生产实现：全部走 ksud 的 feature 子命令。
 *
 * `status` 直接透传 ksud 的四值输出（语言无关）；`value/persistValue` 解析
 * `feature get <name>` 与 `feature get <name> --config` 的 `Value:` 行，兼容纯数字输出。
 */
class KsuSettingsFeatureImpl(
    private val backend: KsuCommandBackend,
    private val timeoutMs: Long = KsuTimeouts.COMMAND_MS,
) : KsuSettingsFeature {

    private fun available(): Boolean = backend.daemonExists()

    override fun readSettings(includeExtras: Boolean): KsuSettingsFeatureRead {
        val features = KsuSettingsFeatureRead.features(includeExtras)
        val daemon = backend.daemonPath()
        val commands = listOf(KsuCommands.feature(daemon, "check", KsuFeature.SU_COMPAT)) +
            features.map { KsuCommands.feature(daemon, "get", it) }
        val results = backend.readFeatureBatch(commands, timeoutMs)
        val names = listOf("check:${KsuFeature.SU_COMPAT}") + features.map { "get:$it" }
        return KsuSettingsFeatureRead(
            parseStatus(results.first().takeIf { it.code == 0 }?.outText.orEmpty()),
            features.mapIndexed { index, feature ->
                feature to results[index + 1].takeIf { it.code == 0 }?.outText?.let(::parseValue)
            }.toMap(),
            names.zip(results).toMap(),
        )
    }

    override fun status(feature: String): String {
        if (!KsuFeature.isValid(feature) || !available()) {
            if (!available()) KsuLog.unavailable("KsuSettingsFeature", "ksud missing")
            return KsuFeature.STATUS_UNKNOWN
        }
        val out = backend.capture("feature check $feature", timeoutMs)
        return parseStatus(out)
    }

    private fun parseStatus(output: String): String = when (val out = output.trim().lowercase()) {
        KsuFeature.STATUS_SUPPORTED, KsuFeature.STATUS_MANAGED,
        KsuFeature.STATUS_UNSUPPORTED, KsuFeature.STATUS_UNKNOWN -> out
        else -> KsuFeature.STATUS_UNKNOWN
    }

    override fun value(feature: String): Long? = readLong(feature, "-")

    override fun persistValue(feature: String): Long? = readLong(feature, "--config")

    override fun set(feature: String, enabled: Boolean): Boolean {
        if (!KsuFeature.isValid(feature) || !available()) {
            if (!available()) KsuLog.unavailable("KsuSettingsFeature", "ksud missing")
            return false
        }
        val cmd = try {
            KsuCommands.feature(backend.daemonPath(), "set", feature, if (enabled) 1L else 0L)
        } catch (e: KsuCommandRejectedException) {
            KsuLog.rejected("KsuSettingsFeature", e.token)
            return false
        }
        return backend.runCommand(cmd, timeoutMs).code == 0
    }

    override fun save(): Boolean {
        if (!available()) {
            KsuLog.unavailable("KsuSettingsFeature", "ksud missing")
            return false
        }
        // `feature save` 不带 feature 参数（ksud CLI：feature save）
        val bare = listOf(KsuCommands.assertDaemon(backend.daemonPath()), "feature", "save")
        KsuCommands.rejectForbidden(bare.drop(1))
        return backend.runCommand(bare, timeoutMs).code == 0
    }

    private fun readLong(feature: String, mode: String): Long? {
        if (!KsuFeature.isValid(feature) || !available()) {
            if (!available()) KsuLog.unavailable("KsuSettingsFeature", "ksud missing")
            return null
        }
        val args = "feature get $feature" + (if (mode == "-") "" else " $mode")
        return parseValue(backend.capture(args, timeoutMs))
    }

    private fun parseValue(output: String): Long? {
        val lines = output.lineSequence().map { it.trim() }
            .filter { it.isNotEmpty() }.toList()
        return lines.firstOrNull()?.toLongOrNull()
            ?: lines.firstOrNull { it.startsWith("Value:") }?.substringAfter(':')?.trim()?.toLongOrNull()
    }

    companion object {
        fun unavailable(reason: String): KsuSettingsFeature {
            KsuLog.unavailable("KsuSettingsFeature", reason)
            return object : KsuSettingsFeature {
                override fun status(feature: String): String = KsuFeature.STATUS_UNKNOWN
                override fun value(feature: String): Long? = null
                override fun persistValue(feature: String): Long? = null
                override fun set(feature: String, enabled: Boolean): Boolean = false
                override fun save(): Boolean = false
            }
        }
    }
}
