package dev.maplesu.manager.workmode.control

import dev.maplesu.manager.workmode.control.schema.SwitchHeadViewCodec
import dev.maplesu.manager.workmode.switch.SwitchStateNames
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 01 §8.1 `SwitchHeadViewTest`：wire 投影 + 未知 state 保守 + pending 集合与 02 一致。 */
class SwitchHeadViewTest {

    private fun rawSwitch(
        state: String,
        switchId: String = "sw-1",
        withError: Boolean = true,
    ): String = buildString {
        append("{")
        append("\"schema\":1,")
        append("\"switchId\":\"").append(switchId).append("\",")
        append("\"planSha256\":\"").append("a".repeat(64)).append("\",")
        append("\"state\":\"").append(state).append("\",")
        append("\"stage\":\"S4\",\"step\":\"4d\",")
        append("\"fromMode\":\"LITE\",\"toMode\":\"KSU\",")
        append("\"startBootId\":\"boot-1\",")
        append("\"attempts\":{\"bootVerifyFailures\":1,\"rebootRequests\":2},")
        if (withError) append("\"error\":{\"code\":\"VERIFY_PARTITION_MISMATCH\",\"stage\":\"S6\"},")
        append("\"updatedAtUptimeMs\":12345")
        append("}")
    }

    @Test
    fun currentParsesAllStates() {
        for (state in SwitchStateNames.ALL) {
            val head = SwitchHeadViewCodec.parse(rawSwitch(state))
            assertTrue("state=$state must parse", head != null)
            assertEquals(state, head!!.state)
            assertEquals(state in SwitchStateNames.PENDING, head.pending)
        }
    }

    @Test
    fun unknownStateIsPending() {
        val head = SwitchHeadViewCodec.parse(rawSwitch("FUTURE_STATE"))
        assertTrue(head != null)
        assertTrue(head!!.pending)
        assertFalse(SwitchStateNames.isKnown(head.state))
    }

    @Test
    fun wireFieldsAreMappedFromSwitchJsonSchema() {
        val head = SwitchHeadViewCodec.parse(rawSwitch(SwitchStateNames.COMMIT))
        assertEquals(1, head!!.schema)
        assertEquals("sw-1", head.switchId)
        assertEquals(SwitchStateNames.COMMIT, head.state)
        assertEquals("LITE", head.from)
        assertEquals("KSU", head.to)
        assertEquals("boot-1", head.bootIdAtBegin)
        assertEquals(2, head.attempts)
        assertEquals("VERIFY_PARTITION_MISMATCH", head.errorCode)
        assertEquals("S6", head.errorStage)
        assertEquals(12_345L, head.updatedAt)
    }

    @Test
    fun corruptJsonReturnsNull() {
        assertNull(SwitchHeadViewCodec.parse("{"))
        assertNull(SwitchHeadViewCodec.parse("[]"))
        assertNull(SwitchHeadViewCodec.parse("{\"state\":\"COMMIT\"}"))
        assertNull(SwitchHeadViewCodec.parse("{\"switchId\":\"sw-1\"}"))
        assertNull(SwitchHeadViewCodec.parse(""))
    }

    @Test
    fun pendingAndTerminalPartitionAllStates() {
        assertEquals(12, SwitchStateNames.ALL.size)
        assertEquals(8, SwitchStateNames.PENDING.size)
        assertEquals(4, SwitchStateNames.TERMINAL.size)
        assertTrue((SwitchStateNames.PENDING + SwitchStateNames.TERMINAL).containsAll(SwitchStateNames.ALL))
        assertTrue(SwitchStateNames.PENDING.intersect(SwitchStateNames.TERMINAL).isEmpty())
        assertTrue(SwitchStateNames.isPending(null))
        assertTrue(SwitchStateNames.isPending("SOMETHING_NEW"))
        for (terminal in SwitchStateNames.TERMINAL) assertFalse(SwitchStateNames.isPending(terminal))
    }
}
