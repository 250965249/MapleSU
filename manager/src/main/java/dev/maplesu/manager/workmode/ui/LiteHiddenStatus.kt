package dev.maplesu.manager.workmode.ui

import com.maplesu.core.R
import dev.maplesu.manager.litehidden.LiteHiddenState

/**
 * Lite 隐藏状态在 UI 上的**三态**（缺陷修复：UNKNOWN 不得渲染成"已开启"）。
 *
 * 用户实测反馈（2026-10-30 第二轮）：状态读取失败（UNKNOWN）时，旧代码用
 * `state.isEffectivelyOn`（UNKNOWN 保守为 true）直接选"已开启"文案 —— 实际隐身没开，
 * 界面却说开着。安全方向（"隐藏中"）和**事实陈述**（"已开启"）是两件事，不能混用：
 *  - 入口是否消失 → 用 [masks]（UNKNOWN 按隐藏处理，宁可少露）；
 *  - 状态行文案 → 用 [status] / [statusRes]（UNKNOWN 必须说"状态未知（读取失败）"）。
 */
enum class LiteHiddenStatus {
    ON,
    OFF,
    UNKNOWN,
    ;

    /** 是否按"隐藏生效"处理入口（UNKNOWN 保守为 true）。 */
    val masks: Boolean get() = this != OFF

    companion object {
        fun of(state: LiteHiddenState): LiteHiddenStatus = when (state) {
            LiteHiddenState.ON -> ON
            LiteHiddenState.OFF -> OFF
            LiteHiddenState.UNKNOWN -> UNKNOWN
        }
    }
}

/**
 * 隐藏状态 → 状态行文案（纯映射，主机可测）：
 * 只有**明确读到 ON** 才说"已开启"；OFF 说"未开启"；UNKNOWN 说"状态未知（读取失败）"。
 */
object LiteHiddenStatusPolicy {

    fun status(state: LiteHiddenState): LiteHiddenStatus = LiteHiddenStatus.of(state)

    /** 状态行文案资源键（三态一一对应，禁止把 UNKNOWN 映射到"已开启"）。 */
    fun statusRes(state: LiteHiddenState): Int = statusRes(status(state))

    /** 同上一份映射的 [LiteHiddenStatus] 重载（设置页已持有三态时直接取文案）。 */
    fun statusRes(status: LiteHiddenStatus): Int = when (status) {
        LiteHiddenStatus.ON -> R.string.lite_hidden_status_on
        LiteHiddenStatus.OFF -> R.string.lite_hidden_status_off
        LiteHiddenStatus.UNKNOWN -> R.string.lite_hidden_status_unknown
    }

    /** 隐藏/隐藏入口是否按"生效"处理（UNKNOWN 保守按 ON）。 */
    fun masks(state: LiteHiddenState): Boolean = LiteHiddenStatus.of(state).masks
}
