package com.maplesu.core.ui.screen.settings

import dev.maplesu.manager.workmode.ui.SettingsModePolicy

/**
 * 设置页上一次的完整状态（进程内）。
 *
 * 设置页「刚打开时卡一下才显示全」的原因是所有行都等后台读取结束才出现：`modePolicy` 默认
 * 未判定，隐藏行要等 root 读取返回，工作模式行要等首帧之后的 effect。本快照减少重复创建时
 * 的数值闪烁，但不证明隐藏状态。ViewModel 创建时仍先遮蔽模式入口、后台确认后才放行。
 * 冷启动的完整结构预热尚未完成，不能把此缓存视为首开不卡问题已解决。
 *
 * 模式变了（只会发生在判定完成前后）就不复用：不同模式的可见项不同，不能串。
 */
internal object SettingsSnapshotCache {

    @Volatile
    private var last: SettingsUiState? = null

    fun store(state: SettingsUiState) {
        last = state
    }

    fun initial(policy: SettingsModePolicy, seed: () -> SettingsUiState): SettingsUiState =
        last?.takeIf { it.modePolicy.mode == policy.mode } ?: seed()
}
