package dev.maplesu.manager.runtime.authorization

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Host regression for the seccomp-safe privileged path (P0, 2026-10-31).
 *
 * <p>The root tool is a fork of the App, so it inherits the App's seccomp filter. The
 * observed failure is `SIGSYS`, `syscall 144` (`setgid`), from the `setgid` that
 * `createIdmap`'s `ExecuteBinary` child performs. No user-space code can lift that
 * filter; what the App can control is (a) not calling a filtered syscall and (b)
 * reporting a filtered death by name instead of inventing a transport failure.
 *
 * <p>These tests pin both halves of (b): the protocol line is the only success signal,
 * an explicit `ERR` is a refusal, and a signal death without a line is
 * `SU_PRIVILEGED_PATH_SECCOMP_BLOCKED` - never a generic unavailable and never success.
 */
class SuperuserSeccompPathTest {

    private fun failed(code: String): RootToolOutcome.Failed =
        RootToolOutcome.Failed(code)

    private fun failureOf(outcome: RootToolOutcome): String =
        (outcome as? RootToolOutcome.Failed)?.code ?: error("expected a failure, got $outcome")

    // --- the named seccomp failure ------------------------------------------

    @Test
    fun `a SIGSYS death without a protocol line is the named seccomp code`() {
        assertEquals(
            SuCodes.SU_PRIVILEGED_PATH_SECCOMP_BLOCKED,
            failureOf(RootToolOutcome.parse(RootToolOutcome.EXIT_SIGSYS, "")),
        )
    }

    @Test
    fun `the seccomp exit spelling is 128 plus SIGSYS and nothing else`() {
        assertEquals(31, RootToolOutcome.SIGSYS)
        assertEquals(159, RootToolOutcome.EXIT_SIGSYS)
        assertTrue(RootToolOutcome.isSeccompDeath(159))
        for (other in listOf(-159, -31, 0, 1, 126, 127, 128, 129, 137, 143, 158, 160, 255)) {
            assertFalse("$other is not a SIGSYS death", RootToolOutcome.isSeccompDeath(other))
        }
    }

    @Test
    fun `shell diagnostics around a killed tool do not hide the seccomp classification`() {
        // A real killed child can leave this kind of text on stdout before dying; none
        // of it is the tool's protocol line, so it must not become a result.
        val output = "Killed\n" +
            "Abort message: 'Fatal signal 31 (SIGSYS), code 1 (SYS_SECCOMP), syscall 144'\n"
        assertEquals(
            SuCodes.SU_PRIVILEGED_PATH_SECCOMP_BLOCKED,
            failureOf(RootToolOutcome.parse(RootToolOutcome.EXIT_SIGSYS, output)),
        )
    }

    @Test
    fun `ordinary child failures stay generic and are never called seccomp`() {
        for (exit in listOf(0, 1, 126, 127, 128, 137, 143, 158, 160, 255)) {
            assertEquals(
                "exit=$exit must stay a generic transport failure",
                SuCodes.SU_TRANSPORT_UNAVAILABLE,
                failureOf(RootToolOutcome.parse(exit, "")),
            )
        }
    }

    // --- the protocol line is the only success signal -----------------------

    @Test
    fun `OK carries the payload and is accepted even when the process exits by SIGSYS afterwards`() {
        val outcome = RootToolOutcome.parse(
            RootToolOutcome.EXIT_SIGSYS,
            "noise\nOK rev=7 pending=0 detail=- code=OK\n",
        )
        assertTrue("an explicit OK is the tool's completed answer", outcome is RootToolOutcome.Ok)
        assertEquals("rev=7 pending=0 detail=- code=OK", (outcome as RootToolOutcome.Ok).payload)
    }

    @Test
    fun `an ERR line is a refusal even when the process exit status is zero`() {
        val outcome = RootToolOutcome.parse(
            0,
            "ERR java.lang.IllegalStateException:AUTH_STORE_ROOT_REQUIRED\n",
        )
        assertEquals(SuCodes.SU_TRANSPORT_UNAVAILABLE, failureOf(outcome))
    }

    @Test
    fun `the last protocol line wins so a trailing ERR cannot be hidden by an earlier OK`() {
        val outcome = RootToolOutcome.parse(0, "OK stale=true\nERR AUTH_DENIED\n")
        assertEquals(SuCodes.SU_TRANSPORT_UNAVAILABLE, failureOf(outcome))
    }

    @Test
    fun `a line that merely contains OK is not the protocol line`() {
        for (output in listOf("this is OK but not a line", " OK leading-space", "OK", "OK\n")) {
            assertEquals(
                "output=[$output] must not be accepted",
                SuCodes.SU_TRANSPORT_UNAVAILABLE,
                failureOf(RootToolOutcome.parse(0, output)),
            )
        }
    }

    @Test
    fun `an empty stdout with zero exit is still a transport failure, not success`() {
        assertEquals(
            SuCodes.SU_TRANSPORT_UNAVAILABLE,
            failureOf(RootToolOutcome.parse(0, "")),
        )
    }

    // --- the package-service user is derived, not read from a Context -------

    @Test
    fun `the root reader derives the Android user from the manager uid`() {
        assertEquals(0, SystemPackageSnapshotSource.userIdOf(10481))
        assertEquals(0, SystemPackageSnapshotSource.userIdOf(19999))
        assertEquals(1, SystemPackageSnapshotSource.userIdOf(110481))
        assertEquals(2, SystemPackageSnapshotSource.userIdOf(20481 + 200_000))
        assertEquals(0, SystemPackageSnapshotSource.userIdOf(0))
    }

    @Test
    fun `the fallback failure constructor is the generic transport code`() {
        assertEquals(SuCodes.SU_TRANSPORT_UNAVAILABLE, failed(SuCodes.SU_TRANSPORT_UNAVAILABLE).code)
    }
}
