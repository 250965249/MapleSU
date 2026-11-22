package dev.maplesu.manager.workmode

/**
 * 双工作模式的唯一枚举。
 *
 * [suffix] 同时是：prefs 后缀、离线仓目录名、控制面 wire 值。
 * 一经发布不得修改（磁盘目录名与 prefs 后缀，改了等于数据丢失）。
 *
 * 核心枚举保持纯 Kotlin，便于主机检查。UI 层负责 `WorkMode -> string res` 映射，
 * 对应 `R.string.work_mode_lite` / `R.string.work_mode_ksu`。
 */
enum class WorkMode(
    /** "A" | "B"，用于 settings_A / modes/A / modes.json.current。 */
    val suffix: String,
) {
    /** MapleSU_Ultra（原 Lite，现状实现）。 */
    LITE("A"),

    /** MapleSU_Normal（原玩机兼容，KSU 分支）。 */
    KSU("B");

    val isLite: Boolean get() = this == LITE

    val isKsu: Boolean get() = this == KSU

    companion object {
        /** 只接受 "A"/"B"/"LITE"/"KSU"；其它（含 null、空串）返回 null，**禁止** fallback 到 LITE。 */
        fun fromWire(value: String?): WorkMode? = when (value?.trim()?.uppercase()) {
            "A", "LITE" -> LITE
            "B", "KSU" -> KSU
            else -> null
        }

        fun fromSuffix(suffix: String?): WorkMode? =
            if (suffix == null) null else entries.firstOrNull { it.suffix == suffix }
    }
}
