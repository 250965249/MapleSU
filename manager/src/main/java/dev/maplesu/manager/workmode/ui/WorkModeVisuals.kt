package dev.maplesu.manager.workmode.ui

import dev.maplesu.manager.workmode.detect.ModeState

/**
 * 状态卡的语义色调（04 §2.5）：两皮肤共用同一套 token，颜色映射各皮肤各自实现一处。
 * 纯函数 → 主机可测；新增 `ModeState` 时编译器强制补分支。
 */
enum class ModeCardTone { OK, WARN, NEUTRAL }

fun toneOf(state: ModeState): ModeCardTone = when (state) {
    ModeState.MODE_A_ACTIVE,
    ModeState.MODE_B_ACTIVE -> ModeCardTone.OK

    ModeState.MODE_B_KERNEL_ONLY,
    ModeState.MODE_A_INSTALLED_UNBOUND -> ModeCardTone.WARN

    ModeState.FOREIGN_SU,
    ModeState.NOT_INSTALLED,
    ModeState.INDETERMINATE -> ModeCardTone.NEUTRAL
}
