package com.maplesu.core.ui.security

import dev.maplesu.manager.litehidden.LiteHiddenState
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Lite 隐藏状态文件的**读取结果解析**（纯 JVM）。
 *
 * 真机 root 包装脚本可能先打印警告/回显，只有最后一行才是状态；旧实现用 `contains`/`fromWire`
 * 读首字符，容易把"1"读成 UNKNOWN（失败的概率被人为抬高）。这里锁定：
 *  - 最后一行 `1`/`0` 才算明确状态；
 *  - 文件不存在（LITE_MISSING）→ OFF；
 *  - 空 / 坏写 / 命令失败 → UNKNOWN（保守按 ON，但文案会说"未知"）。
 */
class LiteHiddenStateParseTest {

    @Test
    fun missingFileMeansOff() {
        assertEquals(LiteHiddenState.OFF, parseLiteHiddenStateOutput("LITE_MISSING"))
        assertEquals(LiteHiddenState.OFF, parseLiteHiddenStateOutput("LITE_MISSING\n"))
    }

    @Test
    fun explicitOneAndZeroAreParsed() {
        assertEquals(LiteHiddenState.ON, parseLiteHiddenStateOutput("1\n"))
        assertEquals(LiteHiddenState.OFF, parseLiteHiddenStateOutput("0\n"))
    }

    @Test
    fun lastLineWinsOverNoise() {
        // root 包装脚本/旧 shell 可能先打印无关输出，末行才是 `cat` 的结果。
        assertEquals(LiteHiddenState.ON, parseLiteHiddenStateOutput("warning: deprecated\n1\n"))
        assertEquals(LiteHiddenState.OFF, parseLiteHiddenStateOutput("echo: cannot chmod\n0\n"))
    }

    @Test
    fun rootFailureMeansUnknown() {
        assertEquals(
            "拿不到 root 输出 → 不知道（不是'未开启'）",
            LiteHiddenState.UNKNOWN,
            parseLiteHiddenStateOutput(null),
        )
    }

    @Test
    fun emptyOrGarbageMeansUnknown() {
        assertEquals(LiteHiddenState.UNKNOWN, parseLiteHiddenStateOutput(""))
        assertEquals(LiteHiddenState.UNKNOWN, parseLiteHiddenStateOutput("\n  \n"))
        assertEquals(LiteHiddenState.UNKNOWN, parseLiteHiddenStateOutput("garbage"))
        assertEquals("半截写入（1 后面还有字符）也不算明确 ON", LiteHiddenState.UNKNOWN, parseLiteHiddenStateOutput("1x"))
    }
}
