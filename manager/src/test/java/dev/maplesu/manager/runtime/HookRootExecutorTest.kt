package dev.maplesu.manager.runtime

import dev.maplesu.manager.jailbreak.JailbreakRequest
import dev.maplesu.manager.jailbreak.JailbreakStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlinx.coroutines.runBlocking

class HookRootExecutorTest {
    private class Fixture {
        var status: JailbreakStatus? = JailbreakStatus(
            method = "dirtyfrag", stage = JailbreakStatus.STAGE_DAEMON_READY, message = "",
            startedAtMillis = 1, updatedAtMillis = 1, bootId = "boot", attemptId = "attempt",
            rootBackend = JailbreakRequest.BACKEND_HOOK,
        )
        var boot: String? = "boot"
        var gate = SuGate.Gate(SuGate.Token("0123456789abcdef"), "ARMED", true, "attempt", "boot")
        var gateReads = 0
        var commands = 0
        var code = 0
        var timeout = 0
        val executor = HookRootExecutor(
            status = { status }, bootId = { boot },
            readGate = { attempt, boot ->
                assertEquals("attempt", attempt)
                assertEquals("boot", boot)
                gateReads++
                gate
            },
            runScript = { gate, script, timeout ->
                assertTrue(gate.armed)
                this.timeout = timeout
                commands++
                NativeSu.SuResult(code, script, if (code == 0) "" else "native-failure")
            },
        )
    }

    @Test fun aCurrentReadyHookCanExecuteWithoutAUltraKey() {
        val fixture = Fixture()
        assertTrue(fixture.executor.available())
        val result = fixture.executor.run("id -u")
        assertTrue(result.ok)
        assertEquals(RootBackend.HOOK, result.backend)
        assertEquals("id -u", result.output)
        assertEquals(1, fixture.commands)
    }

    @Test fun incompleteFailedForeignAndExpiredAttemptsNeverReadATokenOrExecute() {
        val valid = Fixture().status!!
        val invalid = listOf(
            null,
            valid.copy(stage = JailbreakStatus.STAGE_PROVIDER_RUNNING),
            valid.copy(stage = JailbreakStatus.STAGE_EXPIRED),
            valid.copy(failure = "failed"),
            valid.copy(rootBackend = JailbreakRequest.BACKEND_KSU),
            valid.copy(rootBackend = null),
            valid.copy(bootId = "previous-boot"),
            valid.copy(bootId = null),
            valid.copy(attemptId = null),
            valid.copy(attemptId = ""),
        )
        for (status in invalid) {
            val fixture = Fixture().apply { this.status = status }
            assertFalse(fixture.executor.available())
            assertFalse(fixture.executor.run("must-not-run").ok)
            assertEquals(0, fixture.gateReads)
            assertEquals(0, fixture.commands)
        }
    }

    @Test fun anUnreadableCurrentBootNeverExecutes() {
        for (boot in listOf(null, "", "new-boot")) {
            val fixture = Fixture().apply { this.boot = boot }
            assertFalse(fixture.executor.available())
            assertFalse(fixture.executor.run("must-not-run").ok)
            assertEquals(0, fixture.commands)
        }
    }

    @Test fun aDeniedUnboundOrMismatchedGateNeverExecutes() {
        val armed = Fixture().gate
        for (gate in listOf(
            SuGate.Gate.UNAVAILABLE_GATE,
            armed.copy(bound = false),
            armed.copy(suGate = "UNAVAILABLE"),
            armed.copy(suToken = SuGate.Token("0000000000000000")),
            armed.copy(attempt = "other-attempt"),
            armed.copy(bootId = "other-boot"),
        )) {
            val fixture = Fixture().apply { this.gate = gate }
            assertFalse(fixture.executor.available())
            assertFalse(fixture.executor.run("must-not-run").ok)
            assertEquals(0, fixture.commands)
        }
    }

    @Test fun aGateThatExpiresAfterPrepareIsReadAgainBeforeExecution() {
        val fixture = Fixture()
        assertTrue(fixture.executor.prepareForExecution())
        fixture.gate = SuGate.Gate.UNAVAILABLE_GATE
        assertFalse(fixture.executor.run("must-not-run").ok)
        assertEquals(2, fixture.gateReads)
        assertEquals(0, fixture.commands)
    }

    @Test fun aPageDeadlineBoundsTheNativeChildLifetime() {
        val fixture = Fixture()
        runBlocking(PageReadDeadline.context(500)) {
            assertTrue(fixture.executor.run("inventory").ok)
        }
        assertTrue("Native child ignored page deadline: ${fixture.timeout}", fixture.timeout in 1..500)
        assertTrue(fixture.executor.run("install").ok)
        assertEquals(NativeSu.DEFAULT_TIMEOUT_MILLIS, fixture.timeout)
    }

    @Test fun anExpiredPageNeverForks() {
        val fixture = Fixture()
        val result = runBlocking(PageReadDeadline.context(0)) { fixture.executor.run("inventory") }
        assertFalse(result.ok)
        assertEquals("ROOT_EXECUTION_BUSY", result.detail)
        assertEquals(0, fixture.commands)
    }

    @Test fun nativeFailureIsReturnedWithoutReportingSuccess() {
        val fixture = Fixture().apply { code = 126 }
        val result = fixture.executor.run("one-attempt")
        assertFalse(result.ok)
        assertEquals(126, result.code)
        assertEquals("native-failure", result.detail)
        assertEquals(1, fixture.commands)
    }
}
