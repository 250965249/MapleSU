package dev.maplesu.manager.workmode.ui

import com.maplesu.core.R

/**
 * 三态状态行 → 文案资源（只依赖 R 常量，不触碰 Android 运行时 → 可主机测试）。
 *
 * 约束（用户反馈修复）：UNKNOWN 只能映射到「状态未知（读取失败）」，**禁止**映射到「已开启」；
 * 只有 [SettingsStatus.ON]（明确读到开启）才允许「已开启」。
 *
 * 与 [LiteHiddenStatusPolicy] 同一套语义，但键位独立：`lite_hidden_status_*` 属于
 * litehidden 文档，这里用 `settings_status_*`，避免设置页文案被隐藏页文案绑死。
 */
object SettingsStatusCopy {

    fun statusRes(status: SettingsStatus): Int = when (status) {
        SettingsStatus.ON -> R.string.settings_status_on
        SettingsStatus.OFF -> R.string.settings_status_off
        SettingsStatus.UNKNOWN -> R.string.settings_status_unknown
    }
}
