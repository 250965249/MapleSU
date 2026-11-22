package dev.maplesu.manager.runtime

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Host regression for the L3 su gate's parsing and binding (ABI v1).
 *
 * <p>The gate decides whether *anything* is allowed to run as root, so every test
 * below is a refusal test except the first: a record that is malformed, unbound,
 * stale or merely not `ARMED` must not produce an armed gate, and there is no
 * default that could. The helper's file itself cannot be produced here (that needs a
 * device), so the parser is driven directly with the exact document shape the
 * helper writes - `attempt`, `bootId`, `suToken`, `suGate`.
 */
class SuGateTest {

    private val attempt = "a1b2c3d4e5f60718"
    private val boot = "0011223344556677"
    private val token = "0123456789abcdef"

    private fun document(
        suToken: String? = token,
        suGate: String? = "ARMED",
        attemptId: String? = attempt,
        bootId: String? = boot,
    ): String = buildString {
        append("{\"schema\":\"maplesu.hook.attest.v1\",\"pid\":4242,\"uid\":0")
        append(",\"domain\":\"u:r:kernel:s0\"")
        if (attemptId != null) append(",\"attempt\":\"").append(attemptId).append('"')
        if (bootId != null) append(",\"bootId\":\"").append(bootId).append('"')
        if (suToken != null) append(",\"suToken\":\"").append(suToken).append('"')
        if (suGate != null) append(",\"suGate\":\"").append(suGate).append('"')
        append(",\"enforcingFinal\":1}")
    }

    // --- token format (ABI: 16 lowercase hex digits, "%016llx") ---------------

    @Test
    fun `a well formed token parses and keeps its 64 bit value`() {
        val parsed = SuGate.parseToken(token)
        assertEquals(token, parsed!!.hex)
        assertEquals(0x0123456789abcdefL, parsed.value)
    }

    @Test
    fun `a token with the high bit set keeps the kernel's bit pattern`() {
        val parsed = SuGate.parseToken("ffffffffffffffff")
        assertEquals("ffffffffffffffff", parsed!!.hex)
        // Unsigned 2^64-1: the same 64 bits the kernel compares, not an error.
        assertEquals(-1L, parsed.value)
    }

    @Test
    fun `a zero token is well formed`() {
        assertEquals(0L, SuGate.parseToken("0000000000000000")!!.value)
    }

    @Test
    fun `a zero token cannot arm the gate`() {
        // The module's ARM branch refuses token == 0, so "ARMED + zeros" is a
        // half-written record: the App must answer the same way the kernel would.
        val gate = SuGate.parse(document(suToken = "0000000000000000"), attempt, boot)
        assertEquals("0000000000000000", gate.suToken!!.hex)
        assertFalse(gate.armed)
        assertEquals(SuGate.UNAVAILABLE, gate.state)
    }

    @Test
    fun `every malformed token is refused rather than repaired`() {
        val malformed = listOf(
            null,
            "",
            "0123456789ABCDEF",     // uppercase is not %016llx
            "0123456789abcde",      // 15 digits
            "0123456789abcdef0",    // 17 digits
            "0x123456789abcd",      // prefix
            "0123456789abcdeg",     // non-hex
            " 123456789abcdef",     // leading space
            "0123456789abcdef ",    // trailing space
        )
        for (candidate in malformed) {
            assertNull("accepted " + candidate, SuGate.parseToken(candidate))
        }
    }

    // --- gate state ----------------------------------------------------------

    @Test
    fun `an armed record bound to this attempt and boot is armed`() {
        val gate = SuGate.parse(document(), attempt, boot)
        assertTrue(gate.armed)
        assertEquals(SuGate.ARMED, gate.state)
        assertEquals(token, gate.suToken!!.hex)
        assertEquals(attempt, gate.attempt)
        assertEquals(boot, gate.bootId)
    }

    @Test
    fun `an UNAVAILABLE record is not armed even with a token beside it`() {
        val gate = SuGate.parse(document(suGate = SuGate.UNAVAILABLE), attempt, boot)
        assertFalse(gate.armed)
        assertEquals(SuGate.UNAVAILABLE, gate.state)
    }

    @Test
    fun `a missing or unknown suGate is not armed`() {
        for (value in listOf(null, "", "ARMEDD", "armed")) {
            val gate = SuGate.parse(document(suGate = value), attempt, boot)
            assertFalse("accepted suGate=" + value, gate.armed)
            assertEquals(SuGate.UNAVAILABLE, gate.state)
        }
    }

    @Test
    fun `a missing or malformed token is not armed`() {
        for (value in listOf(null, "", "0123456789ABCDEF", "0")) {
            val gate = SuGate.parse(document(suToken = value), attempt, boot)
            assertFalse("accepted suToken=" + value, gate.armed)
            assertEquals(SuGate.UNAVAILABLE, gate.state)
        }
    }

    // --- binding -------------------------------------------------------------

    @Test
    fun `a record from another attempt is unbound and unarmed`() {
        val gate = SuGate.parse(document(attemptId = "ffffffffffffffff"), attempt, boot)
        assertFalse(gate.bound)
        assertFalse(gate.armed)
        // The raw value is kept for diagnostics; the token itself is withheld so no
        // caller can accidentally use it.
        assertEquals("ARMED", gate.suGate)
        assertNull(gate.suToken)
        assertEquals(SuGate.UNAVAILABLE, gate.state)
    }

    @Test
    fun `a record from another boot is unbound and unarmed`() {
        val gate = SuGate.parse(document(bootId = "ffffffffffffffff"), attempt, boot)
        assertFalse(gate.bound)
        assertNull(gate.suToken)
        assertEquals(SuGate.UNAVAILABLE, gate.state)
    }

    @Test
    fun `a caller without an attempt or boot binding cannot arm anything`() {
        for ((missingAttempt, missingBoot) in listOf(attempt to null, null to boot,
            null to null, "" to boot, attempt to "")) {
            val gate = SuGate.parse(document(), missingAttempt, missingBoot)
            assertFalse(gate.bound)
            assertFalse(gate.armed)
            assertEquals(SuGate.UNAVAILABLE, gate.state)
        }
    }

    @Test
    fun `a record with no attempt or boot field is unbound`() {
        val gate = SuGate.parse(document(attemptId = null, bootId = null), attempt, boot)
        assertFalse(gate.bound)
        assertNull(gate.suToken)
        assertFalse(gate.armed)
    }

    // --- malformed documents -------------------------------------------------

    @Test
    fun `a malformed document yields the unavailable gate`() {
        for (text in listOf("", "{", "not json", "[]", "{\"attempt\":}")) {
            val gate = SuGate.parse(text, attempt, boot)
            assertEquals(SuGate.Gate.UNAVAILABLE_GATE, gate)
            assertFalse(gate.armed)
            assertEquals(SuGate.UNAVAILABLE, gate.state)
        }
    }

    @Test
    fun `the refusal code is the stable token the su path returns`() {
        assertEquals("SU_GATE_NOT_ARMED", SuGate.ERROR_NOT_ARMED)
        assertEquals("ARMED", SuGate.ARMED)
        assertEquals("UNAVAILABLE", SuGate.UNAVAILABLE)
        assertEquals("maplesu-hook-daemon.json", SuGate.DAEMON_FILE)
    }
}
