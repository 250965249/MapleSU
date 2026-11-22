package dev.maplesu.manager.workmode.ui

import com.maplesu.core.R
import dev.maplesu.manager.litehidden.LiteHiddenState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Lite 隐藏状态 **文案** 与 **行为** 的三态判据（纯 JVM）。
 *
 * 用户实测反馈（2026-10-30 第二轮）：状态读取失败（UNKNOWN）时，UI 显示"隐藏模式下已启用"
 * —— 把 UNKNOWN 当 ON 渲染在状态文案里，隐身没开却说开着。要求：
 *  - 只有**明确 ON** 才显示"已开启"；OFF 显示"未开启"；
 *  - UNKNOWN 显示"状态未知（读取失败）"，**不得**出现"已启用/已开启"；
 *  - 行为方向（入口/整页消失）仍按 UNKNOWN 保守为"隐藏中"，两者分开。
 */
class LiteHiddenStatusPolicyTest {

    @Test
    fun offIsTheOnlyNotMaskingState() {
        assertEquals(LiteHiddenStatus.OFF, LiteHiddenStatusPolicy.status(LiteHiddenState.OFF))
        assertFalse("明确 OFF 才是未隐藏", LiteHiddenStatusPolicy.masks(LiteHiddenState.OFF))
    }

    @Test
    fun onIsMaskingAndSaysOn() {
        assertEquals(LiteHiddenStatus.ON, LiteHiddenStatusPolicy.status(LiteHiddenState.ON))
        assertTrue(LiteHiddenStatusPolicy.masks(LiteHiddenState.ON))
        assertEquals(R.string.lite_hidden_status_on, LiteHiddenStatusPolicy.statusRes(LiteHiddenState.ON))
    }

    @Test
    fun unknownIsNotRenderedAsOn() {
        val status = LiteHiddenStatusPolicy.status(LiteHiddenState.UNKNOWN)
        assertEquals("UNKNOWN 必须保持独立的第三态", LiteHiddenStatus.UNKNOWN, status)
        assertNotEquals("UNKNOWN 绝不能渲染成已开启", LiteHiddenStatus.ON, status)
        assertEquals(
            "UNKNOWN 的状态文案必须是「状态未知」那一句",
            R.string.lite_hidden_status_unknown,
            LiteHiddenStatusPolicy.statusRes(LiteHiddenState.UNKNOWN),
        )
        assertNotEquals(
            "UNKNOWN 不得复用「已开启」文案",
            R.string.lite_hidden_status_on,
            LiteHiddenStatusPolicy.statusRes(LiteHiddenState.UNKNOWN),
        )
    }

    @Test
    fun unknownStillMasksEntriesConservatively() {
        // 行为 vs 事实：入口按"隐藏中"处理（少露），文案说"未知"（不撒谎）。
        assertTrue(LiteHiddenStatusPolicy.masks(LiteHiddenState.UNKNOWN))
    }

    @Test
    fun statusIsInjectiveForAllStates() {
        val mapped = LiteHiddenState.entries.map { LiteHiddenStatusPolicy.status(it) }
        assertEquals("三态必须一一对应，不能把两个输入压成同一个输出", LiteHiddenState.entries.size, mapped.toSet().size)
        assertEquals(LiteHiddenStatus.entries.toSet(), mapped.toSet())
    }

    @Test
    fun zhUnknownCopyIsShortAndHonest() {
        val file = File("src/main/res/values-zh-rCN/maplesu_litehidden.xml")
        assumeTrue("${file.path} 不存在（工作目录不是 :manager？）", file.isFile)
        val text = file.readText()
        val unknown = Regex("""<string name="lite_hidden_status_unknown">([^<]*)</string>""")
            .find(text)?.groupValues?.get(1)
        assertEquals("状态未知（读取失败）", unknown)
        assertFalse("未知文案不得出现「已启用/已开启」", unknown!!.contains("已开启") || unknown.contains("已启用"))
        assertFalse("禁止「演练/自检」等词", unknown.contains("演练") || unknown.contains("自检"))
        assertTrue("状态文案要短：$unknown", unknown.length <= 15)
    }
}
