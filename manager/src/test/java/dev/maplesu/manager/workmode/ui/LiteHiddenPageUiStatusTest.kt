package dev.maplesu.manager.workmode.ui

import dev.maplesu.manager.litehidden.HiddenCardPhase
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 隐藏设置页 UI 状态的三态行为（纯 JVM）：
 *  - 只有**明确 ON** 才让整页消失（[LiteHiddenPageUi.hidden]）；
 *  - UNKNOWN 留页显示"状态未知（读取失败）"，且不允许再点"开启隐藏模式"（避免重复开启）；
 *  - OFF 才允许开启。
 */
class LiteHiddenPageUiStatusTest {

    @Test
    fun offAllowsEnable() {
        val ui = LiteHiddenPageUi(status = LiteHiddenStatus.OFF)
        assertTrue("明确 OFF 才允许开启", ui.enableButtonEnabled)
        assertFalse("OFF 不触发整页消失", ui.hidden)
    }

    @Test
    fun stateRefreshDisablesEnableUntilTheReadCompletes() {
        val ui = LiteHiddenPageUi(status = LiteHiddenStatus.OFF, checkingState = true)
        assertFalse(ui.enableButtonEnabled)
        assertTrue(ui.copy(checkingState = false).enableButtonEnabled)
    }

    @Test
    fun unknownKeepsPageOpenAndDisablesEnable() {
        val ui = LiteHiddenPageUi(status = LiteHiddenStatus.UNKNOWN)
        assertFalse("UNKNOWN 不得让整页消失（否则用户看不到读取失败原因）", ui.hidden)
        assertFalse("UNKNOWN 不允许重复开启", ui.enableButtonEnabled)
    }

    @Test
    fun onClosesPageAndDisablesEnable() {
        val ui = LiteHiddenPageUi(status = LiteHiddenStatus.ON, hidden = true)
        assertTrue("明确 ON 才让整页消失", ui.hidden)
        assertFalse(ui.enableButtonEnabled)
    }

    @Test
    fun enablingPhaseDisablesButtonEvenWhenOff() {
        val ui = LiteHiddenPageUi(status = LiteHiddenStatus.OFF, phase = HiddenCardPhase.ENABLING)
        assertFalse("执行中按钮必须禁用", ui.enableButtonEnabled)
    }

    @Test
    fun deactivateEntryOnlyWhenClearlyNotHidden() {
        assertTrue(
            LiteHiddenPageUi(status = LiteHiddenStatus.OFF, activeHost = "com.example.host").showDeactivate,
        )
        assertFalse(
            "UNKNOWN 下不给解除入口（保守按隐藏中）",
            LiteHiddenPageUi(status = LiteHiddenStatus.UNKNOWN, activeHost = "com.example.host").showDeactivate,
        )
        assertFalse(
            LiteHiddenPageUi(status = LiteHiddenStatus.ON, activeHost = "com.example.host").showDeactivate,
        )
    }
}
