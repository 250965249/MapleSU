package com.maplesu.core.ui.navigation3

/**
 * 「切换工作模式」的**唯一**落点。
 *
 * 首页、设置等入口只打开选择框（`WorkModeSwitchSheet`），不再有独立的工作模式页。
 * 进度页、恢复页只能从选择框内部进入：switchId 为本地请求或已有服务记录，不接受外部注入，
 * 入口层永远不直接跳进度页。
 *
 * 保留成一个对象，是为了让「所有入口落到同一个地方」这件事能在主机测试里断言，
 * 而不是靠几处各写一遍的巧合。
 */
object WorkModeNavigation {

    enum class Destination { SWITCH_SHEET }

    /** 唯一落点：选择框。 */
    val destination: Destination = Destination.SWITCH_SHEET

    /** 打开切换进度页。 */
    fun openProgress(navigator: Navigator, switchId: String, initialTarget: dev.maplesu.manager.workmode.WorkMode? = null) {
        navigator.push(Route.ModeSwitch(switchId, initialTarget))
    }

    /** 打开恢复页。 */
    fun openRecovery(navigator: Navigator, switchId: String) {
        navigator.push(Route.Recovery(switchId))
    }
}
