package dev.maplesu.manager.runtime

import dev.maplesu.manager.jailbreak.JailbreakRequest
import dev.maplesu.manager.jailbreak.JailbreakStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * M5/M3 (report `maplesu-ultra-attestation-stability-2026-10-31.md` §5): the prepare has
 * a wall clock, and its failure is a named token that is written before the caller sees it.
 *
 * <p>`NativeSuDaemon.prepareHook` used to await `contentResolver.call` with no timeout at
 * all (P1/P6: the instrumentation thread sat in `am instrument` until the host's 600 s
 * kill). M5 gives the call a bounded budget and the token [HOOK_PREPARE_TIMEOUT]; M3 makes
 * the token land in the status record first. Both pieces are pure enough to test here;
 * the timer test asserts the *caller* is released, not that the abandoned provider thread
 * stopped (a binder call is not interruptible, and pretending otherwise would be a lie in
 * the evidence).
 */
class HookPrepareBudgetTest {

    private val request = JailbreakRequest(
        method = "dirtyfrag",
        attemptId = ATTEMPT,
        bootId = BOOT,
        softReboot = false,
        rootBackend = JailbreakRequest.BACKEND_HOOK,
    )

    @Test
    fun `a prepare that overruns its budget returns the named timeout token`() {
        var token = ""
        val started = System.nanoTime()
        try {
            withWallClockBudget(200L, HOOK_PREPARE_TIMEOUT) {
                Thread.sleep(60_000)
                "never"
            }
            fail("a prepare over its budget must not return a value")
        } catch (timeout: IllegalStateException) {
            token = hookPrepareFailureToken(timeout)
        }
        val elapsedMillis = (System.nanoTime() - started) / 1_000_000
        assertEquals("HOOK_PREPARE_TIMEOUT", token)
        assertEquals(HOOK_PREPARE_TIMEOUT, token)
        assertTrue("the caller must be released at the budget, was " + elapsedMillis + "ms",
            elapsedMillis <= 2_000)
    }

    @Test
    fun `a prepare inside its budget returns the provider's answer`() {
        assertEquals("answered",
            withWallClockBudget(5_000L, HOOK_PREPARE_TIMEOUT) { "answered" })
    }

    @Test
    fun `the provider's own token survives the budget wrapper`() {
        var token = ""
        try {
            withWallClockBudget(5_000L, HOOK_PREPARE_TIMEOUT) {
                throw IllegalStateException("SU_DIRECTORY_BUSY")
            }
            fail("the provider's refusal must propagate")
        } catch (refused: IllegalStateException) {
            token = hookPrepareFailureToken(refused)
        }
        assertEquals("SU_DIRECTORY_BUSY", token)
    }

    @Test
    fun `ghostlock restore failure survives the budget wrapper and binder cause`() {
        val expected = "GHOSTLOCK_RESTORE_UNVERIFIED:FAILED"
        assertEquals(expected, hookPrepareFailureToken(java.io.IOException(expected)))
        try {
            withWallClockBudget(5_000L, HOOK_PREPARE_TIMEOUT) {
                throw IllegalStateException("provider call failed", java.io.IOException(expected))
            }
            fail("the restore failure must propagate")
        } catch (error: IllegalStateException) {
            assertEquals(expected, hookPrepareFailureToken(error))
        }
    }

    @Test
    fun `ghostlock handover can finish after the ordinary prepare budget`() {
        val ghostlock = request.copy(method = "ghostlock")
        // Scale wall time by 1000; the production caller's selected budget is used.
        val result = withWallClockBudget(hookPrepareBudgetMillis(ghostlock) / 1_000,
            HOOK_PREPARE_TIMEOUT) {
            Thread.sleep(150)
            "restored"
        }
        assertEquals("restored", result)
        assertTrue(hookPrepareBudgetMillis(ghostlock) > 240_000L)
        assertEquals(90_000L, hookPrepareBudgetMillis(request))
    }

    @Test
    fun `ghostlock attempt can finish inside the upstream app timeout`() {
        val ghostlock = request.copy(method = "ghostlock")
        val executor = java.util.concurrent.Executors.newSingleThreadExecutor()
        try {
            // Scale seconds to milliseconds while keeping both production budgets.
            val pending = executor.submit<String> {
                Thread.sleep(250)
                "restored"
            }
            val result = withWallClockBudget(hookPrepareBudgetMillis(ghostlock) / 1_000,
                HOOK_PREPARE_TIMEOUT) {
                pending.get(JailbreakRequest.GHOSTLOCK_HANDOVER_TIMEOUT_SECONDS,
                    java.util.concurrent.TimeUnit.MILLISECONDS)
            }
            assertEquals("restored", result)
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `timeout preserves a bound provider restore failure`() {
        val ghostlock = request.copy(method = "ghostlock")
        val failed = observed().copy(method = "ghostlock",
            failure = "GHOSTLOCK_RESTORE_UNVERIFIED:FAILED", restoreState = "FAILED")
        val reply = hookPreparationFailure(failed, ghostlock, HOOK_PREPARE_TIMEOUT,
            "late timeout", 9_000L, 4242)
        assertEquals(failed, reply)
        val foreign = failed.copy(attemptId = "00000000-0000-0000-0000-000000000000")
        assertEquals(HOOK_PREPARE_TIMEOUT, hookPreparationFailure(foreign, ghostlock,
            HOOK_PREPARE_TIMEOUT, "timeout", 9_000L, 4242)!!.failure)
        for (mismatch in listOf(failed.copy(bootId = "other-boot"),
            failed.copy(method = "dirtyfrag"), failed.copy(rootBackend = "ksu"))) {
            assertEquals(HOOK_PREPARE_TIMEOUT, hookPreparationFailure(mismatch, ghostlock,
                HOOK_PREPARE_TIMEOUT, "timeout", 9_000L, 4242)!!.failure)
        }
    }

    @Test
    fun `a nested timeout keeps its named token`() {
        assertEquals(HOOK_PREPARE_TIMEOUT, hookPrepareFailureToken(
            IllegalStateException("provider call failed", java.util.concurrent.TimeoutException())))
    }

    @Test
    fun `an anonymous failure becomes one named bucket, never a sentence`() {
        // A dead binder, a SecurityException or an OOM has no token of its own; the record
        // must still carry a name the acceptance script can match, not a stack-trace text.
        assertEquals("HOOK_BACKEND_NOT_READY:prepare_call_failed",
            hookPrepareFailureToken(RuntimeException("binder died: 0xdeadbeef")))
        assertEquals("HOOK_BACKEND_NOT_READY:prepare_call_failed",
            hookPrepareFailureToken(SecurityException("Permission Denial")))
        assertEquals("HOOK_BACKEND_NOT_READY:worker_unreachable",
            hookPrepareFailureToken(IllegalStateException(
                "HOOK_BACKEND_NOT_READY:worker_unreachable")))
    }

    @Test
    fun `the timeout token is what lands in the record`() {
        // The order prepareHook uses: map the exception to a token, then write it.
        val thrown = IllegalStateException(HOOK_PREPARE_TIMEOUT)
        val token = hookPrepareFailureToken(thrown)
        val message = hookPrepareFailureMessage(token, thrown)
        assertTrue("the record must carry the token: " + message,
            message.contains("HOOK_PREPARE_TIMEOUT"))
        assertTrue("the report's reason form must also be greppable: " + message,
            message.contains("HOOK_BACKEND_NOT_READY:prepare_timeout"))
        val written = hookFailureStatus(
            current = observed(),
            request = request,
            token = token,
            message = message,
            nowMillis = 9_000L,
            ownerPid = 4242,
        )
        assertNotNull(written)
        assertEquals("HOOK_PREPARE_TIMEOUT", written!!.failure)
        assertTrue(written.message.contains("HOOK_BACKEND_NOT_READY:prepare_timeout"))
        assertEquals("the stage must stay honest, not become DAEMON_READY",
            JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED, written.stage)
        assertEquals(9_000L, written.updatedAtMillis)
    }

    @Test
    fun `a prepare with no record at all leaves a failed one`() {
        val written = hookFailureStatus(
            current = null,
            request = request,
            token = "HOOK_BACKEND_NOT_READY:status_missing",
            message = "no status",
            nowMillis = 9_000L,
            ownerPid = 4242,
        )
        assertNotNull(written)
        assertEquals(JailbreakStatus.STAGE_FAILED, written!!.stage)
        assertEquals("HOOK_BACKEND_NOT_READY:status_missing", written.failure)
        assertEquals(ATTEMPT, written.attemptId)
        assertEquals(BOOT, written.bootId)
        assertEquals(4242, written.ownerPid)
    }

    @Test
    fun `a success of this attempt is never overwritten by a later failure`() {
        val ready = observed().copy(stage = JailbreakStatus.STAGE_DAEMON_READY)
        assertNull("a DAEMON_READY record of this attempt stands",
            hookFailureStatus(ready, request, "HOOK_PREPARE_TIMEOUT", "late", 9_000L, 4242))
        // A record of another attempt is not a success of this one.
        val foreign = ready.copy(attemptId = "00000000-0000-0000-0000-000000000000")
        assertNotNull(hookFailureStatus(foreign, request, "HOOK_PREPARE_TIMEOUT", "late",
            9_000L, 4242))
    }

    private fun observed() = JailbreakStatus(
        method = "dirtyfrag",
        stage = JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED,
        message = "hook evidence observed",
        startedAtMillis = 1_000L,
        updatedAtMillis = 1_000L,
        bootId = BOOT,
        attemptId = ATTEMPT,
        ownerPid = 4242,
        restoreState = "RESTORED_BASELINE",
        restoreOrigin = "jailbreak:dirtyfrag:" + ATTEMPT,
        restoreEnforcing = 1,
        restoreFailures = 0,
        rootBackend = JailbreakRequest.BACKEND_HOOK,
    )

    private companion object {
        const val ATTEMPT = "611efa15-0a4d-4c1f-9b7e-3f2f9c1d2e3f"
        const val BOOT = "a666f35b-2fd2-4f6e-9c2d-1a3b5c7d9e0f"
    }
}
