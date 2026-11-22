package dev.maplesu.manager.workmode.detect.probes

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Lite 凭据探针三态：NOT_ATTEMPTED / SUCCEEDED / FAILED / UNKNOWN 的端口映射。 */
class LiteProbeRulesTest {
    @Test
    fun absentCredentialIsNotAttempted() {
        assertEquals(false to null, LiteProbeRules.evaluate(false, HandshakeOutcome.NOT_ATTEMPTED))
    }

    @Test
    fun absentCredentialIgnoresHandshakeOutcome() {
        // 没凭据就不该有握手结论；即便上游给了 SUCCEEDED 也不得伪造 present=true。
        assertEquals(false to null, LiteProbeRules.evaluate(false, HandshakeOutcome.SUCCEEDED))
        assertEquals(false to null, LiteProbeRules.evaluate(false, HandshakeOutcome.FAILED))
    }

    @Test
    fun presentButNotAttemptedIsUnknown() {
        assertEquals(true to null, LiteProbeRules.evaluate(true, HandshakeOutcome.NOT_ATTEMPTED))
    }

    @Test
    fun presentAndSucceededIsTrue() {
        val result = LiteProbeRules.evaluate(true, HandshakeOutcome.SUCCEEDED)
        assertEquals(true, result.first)
        assertEquals(true, result.second)
    }

    @Test
    fun presentAndFailedIsFalseNotUnknown() {
        // 已尝试但失败必须可区分（false），否则 A 设备会被误判成 UNBOUND 之外的态。
        val result = LiteProbeRules.evaluate(true, HandshakeOutcome.FAILED)
        assertEquals(true, result.first)
        assertEquals(false, result.second)
    }

    @Test
    fun presentButUnknownStaysNull() {
        assertEquals(true to null, LiteProbeRules.evaluate(true, HandshakeOutcome.UNKNOWN))
    }

    @Test
    fun failedAndNotAttemptedAreDistinguished() {
        val failed = LiteProbeRules.evaluate(true, HandshakeOutcome.FAILED).second
        val notAttempted = LiteProbeRules.evaluate(true, HandshakeOutcome.NOT_ATTEMPTED).second
        assertEquals(false, failed)
        assertNull(notAttempted)
    }
}
