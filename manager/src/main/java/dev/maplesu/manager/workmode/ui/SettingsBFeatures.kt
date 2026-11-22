package dev.maplesu.manager.workmode.ui

import androidx.compose.runtime.Immutable
import dev.maplesu.manager.workmode.ModeCapabilities

/**
 * W18 三张 B 专属设置卡的能力门控/可用性（纯函数 → 主机可测）。
 *
 * 规则（04 §4 / 主文档 §4.6）：
 * - 隐身：`caps.supportsStealth` 才显示；内核读数 `< 0`（未实现/读失败）→ 显示但禁用 + 原因；
 * - 应用锁：`caps.supportsAppLock` 才显示；v1 内核为**弃用桩**（`app_lock.c` 恒 false/-EPERM）→
 *   一律不可操作，明确显示"当前内核未启用"，**绝不假装可用**；
 * - 网页管理器：`caps.supportsWebAdmin`（仅 B）才显示；能力存在即可操作（失败由调用侧报原因）。
 * LITE（caps 全 false）→ 三张卡都 `show=false`（A 完全隐藏，不改变现有设置页）。
 */
@Immutable
data class BFeatureCard(
    val show: Boolean = false,
    val operable: Boolean = false,
    val enabled: Boolean = false,
    val reasonCode: String = "",
)

@Immutable
data class BFeatureCards(
    val stealth: BFeatureCard = BFeatureCard(),
    val appLock: BFeatureCard = BFeatureCard(),
    val webAdmin: BFeatureCard = BFeatureCard(),
) {
    companion object {
        val NONE = BFeatureCards()
    }
}

object BFeatureReasons {
    const val KERNEL_UNSUPPORTED = "KERNEL_UNSUPPORTED"
    const val KERNEL_UNREADABLE = "KERNEL_UNREADABLE"
    const val KERNEL_DEPRECATED = "KERNEL_DEPRECATED"
}

object BFeaturePolicy {

    fun evaluate(
        capabilities: ModeCapabilities,
        /** `Stealth.kernelState()`：1/0/-1。 */
        stealthRaw: Int,
        /** `Natives.appLockState()`：>0 已配置 / 0 未配置 / <0 不可用。 */
        appLockRaw: Int,
        webAdminEnabledPref: Boolean,
    ): BFeatureCards {
        val stealth = when {
            !capabilities.supportsStealth -> BFeatureCard(show = false)
            stealthRaw == 1 || stealthRaw == 0 -> BFeatureCard(
                show = true,
                operable = true,
                enabled = stealthRaw == 1,
            )

            else -> BFeatureCard(
                show = true,
                operable = false,
                enabled = false,
                reasonCode = BFeatureReasons.KERNEL_UNREADABLE,
            )
        }

        val appLock = if (!capabilities.supportsAppLock) {
            BFeatureCard(show = false)
        } else {
            BFeatureCard(
                show = true,
                operable = false,
                enabled = false,
                reasonCode = BFeatureReasons.KERNEL_DEPRECATED,
            )
        }

        val webAdmin = if (!capabilities.supportsWebAdmin) {
            BFeatureCard(show = false)
        } else {
            BFeatureCard(show = true, operable = true, enabled = webAdminEnabledPref)
        }

        return BFeatureCards(stealth = stealth, appLock = appLock, webAdmin = webAdmin)
    }
}
