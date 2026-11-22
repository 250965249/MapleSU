package dev.maplesu.manager.workmode.gating

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** `mode.gating` 行格式与脱敏。纯 JVM。 */
class ModeGateFormatTest {

    private fun event(
        component: String = "main.install",
        action: ModeGateFormat.Action = ModeGateFormat.Action.DENY,
        mode: String = "none",
        state: String = "UNKNOWN",
        boot: String = "0a1b2c3d",
        pid: Int = 1234,
        uid: Int = 10123,
        reason: ModeGateFormat.Reason = ModeGateFormat.Reason.UNDETERMINED,
        extras: Map<String, String> = emptyMap(),
    ) = ModeGateFormat.Event(component, action, mode, state, boot, pid, uid, reason, extras)

    @Test
    fun fieldOrderIsStable() {
        val line = ModeGateFormat.format(event())
        val expected = "mode.gating v=1 component=main.install action=deny mode=none " +
            "state=UNKNOWN boot=0a1b2c3d pid=1234 uid=10123 reason=UNDETERMINED"
        assertEquals(expected, line)
    }

    @Test
    fun extrasAreAppendedAndSanitized() {
        val line = ModeGateFormat.format(
            event(extras = mapOf("count" to "3", "bad key" to "x", "path" to "/data/adb/maplesu"))
        )
        assertTrue(line.contains("count=3"))
        // 非法键名（空格）被丢弃
        assertFalse(line.contains("bad key"))
        // 值里的空格被换成下划线，行内不出现原始空格分隔歧义
        assertTrue(line.contains("path=/data/adb/maplesu"))
    }

    @Test
    fun sanitizesControlCharactersAndQuote() {
        val line = ModeGateFormat.format(event(component = "a\nb\"c"))
        assertFalse(line.contains("\n"))
        assertTrue(line.contains("component=a_b_c"))
    }

    @Test
    fun longEventsAreTruncatedWithEllipsis() {
        val longValue = "x".repeat(200)
        val extras = (1..20).associate { "k$it" to longValue }
        val line = ModeGateFormat.format(event(extras = extras))
        assertTrue(line.length <= ModeGateFormat.MAX_LENGTH)
        assertTrue(line.endsWith("\u2026"))
    }

    @Test
    fun wireValuesAreLowercase() {
        assertEquals("allow", ModeGateFormat.Action.ALLOW.wire)
        assertEquals("skip", ModeGateFormat.Action.SKIP.wire)
        assertEquals("deny", ModeGateFormat.Action.DENY.wire)
        assertEquals("STEALTH_MASKED", ModeGateFormat.Reason.STEALTH_MASKED.wire)
    }
}
