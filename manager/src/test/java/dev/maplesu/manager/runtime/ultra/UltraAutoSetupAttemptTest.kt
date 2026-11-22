package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.*
import org.junit.Test

class UltraAutoSetupAttemptTest {
    @Test fun verifiedNeverStartedUnknownUsesRecoveryWithoutBootReinstallation() {
        val port = Port().apply { observed = UltraEnvironmentProbe.State.Unknown }
        var starts = 0
        val result = UltraAutoSetupAttempt.run(port) {
            starts++
            UltraEnvironmentAutoSetup.Result(true, true, "IDLE_RECOVERED")
        }
        assertTrue("verified idle boot must leave STATE_Unknown", result.installed)
        assertEquals(1, starts)
        assertEquals(0, port.installs)
    }

    @Test fun unknownWithoutIdleEvidenceAndProtectedStatesStayBlocked() {
        for (state in listOf(UltraEnvironmentProbe.State.Unknown, UltraEnvironmentProbe.State.Fault,
                             UltraEnvironmentProbe.State.NoKey)) {
            val port = Port().apply { observed = state }
            var checks = 0
            val result = UltraAutoSetupAttempt.run(port) { checks++; null }
            assertFalse(result.attempted)
            assertEquals(if (state == UltraEnvironmentProbe.State.Unknown) 1 else 0, checks)
            assertEquals(0, port.installs)
        }
    }

    private class Port : UltraAutoSetupAttempt.Port {
        var observed = UltraEnvironmentProbe.State.Running
        var blocked: String? = null
        var afterProbe: (() -> Unit)? = null
        var afterRecord: (() -> Unit)? = null
        var records = 0
        var diagnosticCrash = false
        var installs = 0
        var outcome = UltraEnvironmentInstaller.Outcome(true, "OK")
        var crash = false
        override fun blockedReason() = blocked
        override fun state() = observed.also { afterProbe?.invoke() }
        override fun recordAttempt() {
            records++
            afterRecord?.invoke()
            if (diagnosticCrash) error("diagnostic storage unavailable")
        }
        override fun install(): UltraEnvironmentInstaller.Outcome {
            installs++
            if (crash) error("install transport lost")
            if (outcome.ok && outcome.verified) observed = UltraEnvironmentProbe.State.Running
            return outcome
        }
        override fun refresh() = Unit
        fun run() = UltraAutoSetupAttempt.run(this)
    }

    @Test fun healthyObservationDoesNotConsumeTheLaterRecoveryAttempt() {
        val port = Port()
        assertEquals("ALREADY_RUNNING", port.run().reason)
        assertEquals(0, port.records)
        port.observed = UltraEnvironmentProbe.State.NotInstalled
        assertTrue(port.run().installed)
        assertEquals("ALREADY_RUNNING", port.run().reason)
        assertEquals(1, port.installs)
        assertEquals(1, port.records)
    }

    @Test fun faultUnknownAndNoKeyNeverInstallOrRecordAnAttempt() {
        for (state in listOf(UltraEnvironmentProbe.State.Fault, UltraEnvironmentProbe.State.Unknown,
                             UltraEnvironmentProbe.State.NoKey)) {
            val port = Port().apply { observed = state }
            assertFalse(port.run().attempted)
            assertEquals(0, port.records)
            assertEquals(0, port.installs)
        }
    }

    @Test fun changesDuringProbeAbortBeforeDiagnosticsOrAnyWrite() {
        for (reason in listOf("KEY_CHANGED", "BOOT_CHANGED", "SUSPENDED", "SWITCH_PENDING", "MODE_KSU")) {
            val port = Port().apply {
                observed = UltraEnvironmentProbe.State.NotInstalled
                afterProbe = { blocked = reason }
            }
            assertEquals(reason, port.run().reason)
            assertEquals(0, port.records)
            assertEquals(0, port.installs)
        }
    }

    @Test fun diagnosticStorageFailureDoesNotBlockAConfirmedMissingEnvironment() {
        val port = Port().apply { observed = UltraEnvironmentProbe.State.NotInstalled; diagnosticCrash = true }
        assertTrue(port.run().installed)
        assertEquals(1, port.installs)
    }

    @Test fun changesWhileWritingDiagnosticsStillAbortBeforeInstallation() {
        val port = Port().apply {
            observed = UltraEnvironmentProbe.State.NotInstalled
            afterRecord = { blocked = "KEY_CHANGED" }
        }
        assertEquals("KEY_CHANGED", port.run().reason)
        assertEquals(1, port.records)
        assertEquals(0, port.installs)
    }

    @Test fun failedUnverifiedAndInterruptedWritesAllowOneRetryPerFreshRequest() {
        for (scenario in 0..2) {
            val port = Port().apply {
                observed = UltraEnvironmentProbe.State.NotInstalled
                when (scenario) {
                    0 -> outcome = UltraEnvironmentInstaller.Outcome(false, "ERR_MODULE_NO_BOOT")
                    1 -> outcome = UltraEnvironmentInstaller.Outcome(true, "OK", verified = false)
                    2 -> crash = true
                }
            }
            val failed = port.run()
            assertTrue(failed.attempted)
            assertFalse(failed.installed)
            assertEquals("one request never loops internally", 1, port.installs)
            port.outcome = UltraEnvironmentInstaller.Outcome(true, "OK")
            port.crash = false
            assertTrue(port.run().installed)
            assertEquals(2, port.installs)
            assertEquals("ALREADY_RUNNING", port.run().reason)
            assertEquals(2, port.installs)
        }
    }

    @Test fun aLostInstallReplyIsReconciledBeforeAnyLaterSubmission() {
        for (later in listOf(UltraEnvironmentProbe.State.Running, UltraEnvironmentProbe.State.Unknown,
                             UltraEnvironmentProbe.State.Fault, UltraEnvironmentProbe.State.NoKey)) {
            val port = Port().apply {
                observed = UltraEnvironmentProbe.State.NotInstalled
                crash = true
            }
            assertFalse(port.run().installed)
            port.observed = later
            assertFalse(port.run().attempted)
            assertEquals("only a later NotInstalled observation permits a new submission", 1, port.installs)
        }
    }
}
