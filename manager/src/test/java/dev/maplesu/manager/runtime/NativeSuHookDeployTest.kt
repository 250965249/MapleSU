package dev.maplesu.manager.runtime

import java.io.File
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Host regression for the two hook-route call sites that replaced
 * `HOOK_MANAGEMENT_UNAVAILABLE`: `NativeSuDirectoryProvider.deploySu` (through
 * [NativeSu.executeScript]) and `NativeSuDaemon.run` (through [NativeSu.execute]).
 *
 * <p>The real JNI library is never loaded here: [NativeSu.inject] installs a fake
 * runner, so these tests assert exactly what the provider would do - the token that
 * reaches the native call, the argv, the retry rule and the bundle contents - without
 * a device and without `libmaplesu_l3_su.so`.
 *
 * <p>The one property that matters most is the negative one: a gate that is not armed
 * must never reach the runner, so no fork, no prctl and no root process can happen.
 */
class NativeSuHookDeployTest {

    private data class Call(val token: Long, val argv: List<String>, val timeoutMillis: Int)

    private val calls = mutableListOf<Call>()

    /** Stand-in for `<filesDir>/maplesu-su` (ABI v1's reserved second attempt). */
    private val fallback = File("/data/user/0/dev.maplesu.manager/files/maplesu-su")

    @After
    fun clearRunner() {
        NativeSu.inject(null)
        calls.clear()
    }

    private fun gate(
        suToken: String? = "0123456789abcdef",
        suGate: String = SuGate.ARMED,
        bound: Boolean = true,
    ): SuGate.Gate = SuGate.Gate(SuGate.parseToken(suToken), suGate, bound,
        "a1b2c3d4e5f60718", "0011223344556677")

    /** Installs a fake runner that records every dispatch and answers through [answer]. */
    private fun fake(answer: (Call) -> NativeSu.SuResult) {
        NativeSu.inject { token, argv, timeoutMillis ->
            val call = Call(token, argv.toList(), timeoutMillis)
            calls += call
            answer(call)
        }
    }

    // --- success path --------------------------------------------------------

    @Test
    fun `an armed gate runs the script through sh -c and returns its streams`() {
        fake { NativeSu.SuResult(0, "uid=0(root) gid=0(root)\n", "") }

        val result = NativeSu.executeScript(gate(), "id", fallback)

        assertEquals(0, result.code)
        assertEquals("uid=0(root) gid=0(root)\n", result.out)
        assertEquals("", result.err)
        assertEquals(1, calls.size)
        // su -c semantics, byte for byte: the script is one argv element of sh -c.
        assertEquals(listOf("/system/bin/sh", "-c", "id"), calls[0].argv)
        assertEquals(0x0123456789abcdefL, calls[0].token)
        assertEquals(NativeSu.DEFAULT_TIMEOUT_MILLIS, calls[0].timeoutMillis)
    }

    @Test
    fun `the token reaches the native call with the ABI's 64 bit value`() {
        fake { NativeSu.SuResult(0, "", "") }

        NativeSu.executeScript(gate(suToken = "ffffffffffffffff"), "id")

        assertEquals(-1L, calls.single().token)
    }

    @Test
    fun `a failing command keeps its own code and streams`() {
        fake { NativeSu.SuResult(1, "partial\n", "sh: no such file\n") }

        val result = NativeSu.executeScript(gate(), "false", fallback)

        assertEquals(1, result.code)
        assertEquals("partial\n", result.out)
        assertEquals("sh: no such file\n", result.err)
        assertEquals(1, calls.size)
    }

    // --- refusal path: the gate -------------------------------------------------

    @Test
    fun `a gate that is not ARMED returns SU_GATE_NOT_ARMED and never dispatches`() {
        fake { NativeSu.SuResult(0, "should not run", "") }

        val result = NativeSu.executeScript(gate(suGate = SuGate.UNAVAILABLE), "id", fallback)

        assertEquals(NativeSu.EXIT_GATE_DENIED, result.code)
        assertEquals("", result.out)
        assertEquals(SuGate.ERROR_NOT_ARMED, result.err)
        assertTrue("no process may be started for an unarmed gate", calls.isEmpty())
    }

    @Test
    fun `a missing token is refused even when suGate says ARMED`() {
        fake { NativeSu.SuResult(0, "should not run", "") }

        val result = NativeSu.executeScript(gate(suToken = null), "id", fallback)

        assertEquals(SuGate.ERROR_NOT_ARMED, result.err)
        assertTrue(calls.isEmpty())
    }

    @Test
    fun `a malformed token is refused`() {
        fake { NativeSu.SuResult(0, "should not run", "") }

        val result = NativeSu.executeScript(gate(suToken = "0123456789ABCDEF"), "id", fallback)

        assertEquals(SuGate.ERROR_NOT_ARMED, result.err)
        assertTrue(calls.isEmpty())
    }

    @Test
    fun `a record from another attempt or boot is refused`() {
        fake { NativeSu.SuResult(0, "should not run", "") }

        val result = NativeSu.executeScript(gate(bound = false), "id", fallback)

        assertEquals(SuGate.ERROR_NOT_ARMED, result.err)
        assertTrue(calls.isEmpty())
    }

    @Test
    fun `an empty argv is refused without dispatching`() {
        fake { NativeSu.SuResult(0, "should not run", "") }

        val result = NativeSu.execute(gate(), emptyArray(), 1_000)

        assertEquals(NativeSu.EXIT_GATE_DENIED, result.code)
        assertEquals("SU_ARGV_EMPTY", result.err)
        assertTrue(calls.isEmpty())
    }

    // --- the reserved second attempt -------------------------------------------

    @Test
    fun `an exec failure retries the reserved in-app client`() {
        fake { call ->
            if (call.argv[0] == NativeSu.SHELL) {
                NativeSu.SuResult(NativeSu.EXIT_EXEC_FAILED, "", "maplesu_su: exec /system/bin/sh errno=2")
            } else {
                NativeSu.SuResult(0, "uid=0(root)", "")
            }
        }

        val result = NativeSu.executeScript(gate(), "id", fallback)

        assertEquals(0, result.code)
        assertEquals("uid=0(root)", result.out)
        assertEquals(2, calls.size)
        assertEquals(listOf(fallback.path, "-c", "id"), calls[1].argv)
        // The retry re-uses the same token: it is a second attempt at the same gate,
        // not a new authorisation.
        assertEquals(calls[0].token, calls[1].token)
    }

    @Test
    fun `a denied gate is never retried on the fallback`() {
        fake { NativeSu.SuResult(NativeSu.EXIT_GATE_DENIED, "", "maplesu_su: SU denied") }

        val result = NativeSu.executeScript(gate(), "id", fallback)

        assertEquals(NativeSu.EXIT_GATE_DENIED, result.code)
        assertEquals(1, calls.size)
    }

    @Test
    fun `a fallback that cannot exec either reports the primary failure`() {
        // Both programs missing: the shell was the primary cause and must not be
        // replaced by its workaround in the error the caller sees.
        fake { NativeSu.SuResult(NativeSu.EXIT_EXEC_FAILED, "",
            "maplesu_su: exec " + it.argv[0] + " errno=2") }

        val result = NativeSu.executeScript(gate(), "id", fallback)

        assertEquals(2, calls.size)
        assertEquals(NativeSu.EXIT_EXEC_FAILED, result.code)
        assertEquals("maplesu_su: exec /system/bin/sh errno=2", result.err)
    }

    @Test
    fun `a fallback that fails specifically is the answer`() {
        fake { call ->
            if (call.argv[0] == NativeSu.SHELL) {
                NativeSu.SuResult(NativeSu.EXIT_EXEC_FAILED, "", "shell missing")
            } else {
                NativeSu.SuResult(1, "", "maplesu-su: bad script")
            }
        }

        val result = NativeSu.executeScript(gate(), "id", fallback)

        assertEquals(1, result.code)
        assertEquals("maplesu-su: bad script", result.err)
    }

    @Test
    fun `without a fallback an exec failure is final`() {
        fake { NativeSu.SuResult(NativeSu.EXIT_EXEC_FAILED, "", "exec failed") }

        val result = NativeSu.executeScript(gate(), "id", null)

        assertEquals(NativeSu.EXIT_EXEC_FAILED, result.code)
        assertEquals(1, calls.size)
    }

    @Test
    fun `the daemon path runs an arbitrary argv through the same gate`() {
        fake { NativeSu.SuResult(0, "ok", "") }

        val result = NativeSu.execute(gate(), arrayOf("/system/bin/id", "-u"), 5_000, fallback)

        assertEquals(0, result.code)
        assertEquals(listOf("/system/bin/id", "-u"), calls.single().argv)
        assertEquals(5_000, calls.single().timeoutMillis)
    }

    @Test
    fun `the library name cannot be mistaken for the runtime su executable`() {
        // build.gradle.kts publishes the runtime's maplesu-su *executable* as
        // libmaplesu_su.so; loading that name would always fail.
        assertEquals("maplesu_l3_su", NativeSu.LIBRARY)
        assertEquals("/system/bin/sh", NativeSu.SHELL)
        assertEquals("maplesu-su", NativeSu.FALLBACK_NAME)
    }
}
