package dev.maplesu.manager.runtime.ultra

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class UltraIdleRecoveryAttemptTest {
    private class Port : UltraIdleRecoveryAttempt.Port {
        var blocked: String? = null
        var persistedGuard = false
        var guardStored = true
        var idle = true
        var helper = true
        var channel = true
        var preparationFailure: String? = null
        var submitOk = true
        var runningState = true
        var functional = true
        var crashAt: String? = null
        var failure: Exception = IllegalStateException("fixture failure")
        val after = mutableMapOf<String, () -> Unit>()
        val calls = mutableListOf<String>()
        var idleChecks = 0
            private set

        private fun <T> step(name: String, read: () -> T): T {
            calls += name
            if (crashAt == name) throw failure
            val result = read()
            after[name]?.invoke()
            return result
        }

        override fun blockedReason() = blocked
        override fun alreadySubmitted() = step("guard") { persistedGuard }
        override fun idleVerified() = step("idle${++idleChecks}") { idle }
        override fun helperVerified() = step("helper") { helper }
        override fun channelVerified() = step("channel") { channel }
        override fun markSubmitted() = step("mark") {
            if (guardStored) persistedGuard = true
            guardStored
        }
        override fun prepare() = step("prepare") { preparationFailure }
        override fun submit() = step("submit") { submitOk }
        override fun running() = step("running") { runningState }
        override fun functionalityVerified() = step("functionality") { functional }
        fun count(name: String) = calls.count { it == name }
        fun run() = UltraIdleRecoveryAttempt.run(this)
    }

    private val scopeChanges = listOf("KEY_CHANGED", "BOOT_CHANGED", "SUSPENDED", "SWITCH_PENDING", "MODE_KSU")

    private fun failed(reason: String, attempted: Boolean = true) =
        UltraEnvironmentAutoSetup.Result(attempted, false, reason)

    private fun assertNoSubmission(port: Port) {
        assertEquals(0, port.count("submit"))
        assertEquals(0, port.count("running"))
        assertEquals(0, port.count("functionality"))
    }

    private fun assertGuardPreventsReplay(port: Port) {
        assertTrue(port.persistedGuard)
        val fresh = Port().apply { persistedGuard = port.persistedGuard }
        assertEquals(failed("IDLE_RECOVERY_ALREADY_SUBMITTED", attempted = false), fresh.run())
        assertEquals(listOf("guard"), fresh.calls)
        val submissions = port.count("submit")
        port.blocked = null
        port.crashAt = null
        assertEquals(failed("IDLE_RECOVERY_ALREADY_SUBMITTED", attempted = false), port.run())
        assertEquals(submissions, port.count("submit"))
    }

    private fun assertRetrySubmits(port: Port) {
        assertFalse(port.persistedGuard)
        val submissions = port.count("submit")
        port.blocked = null
        port.crashAt = null
        port.preparationFailure = null
        port.idle = true
        port.guardStored = true
        port.after.clear()
        assertEquals(UltraEnvironmentAutoSetup.Result(true, true, "IDLE_RECOVERED"), port.run())
        assertEquals(submissions + 1, port.count("submit"))
        assertGuardPreventsReplay(port)
    }

    @Test fun strictlyVerifiedIdleRecoversOnceAfterDurableGuardAndFreshIdleChecks() {
        val port = Port()
        assertEquals(UltraEnvironmentAutoSetup.Result(true, true, "IDLE_RECOVERED"), port.run())
        assertTrue(port.persistedGuard)
        assertEquals(3, port.idleChecks)
        for (call in listOf("helper", "channel", "mark", "prepare", "submit", "running", "functionality")) {
            assertEquals(call, 1, port.count(call))
        }
        assertTrue(port.calls.indexOf("prepare") < port.calls.indexOf("idle3"))
        assertTrue(port.calls.indexOf("idle3") < port.calls.indexOf("mark"))
        assertTrue(port.calls.indexOf("mark") < port.calls.indexOf("submit"))
        assertGuardPreventsReplay(port)
    }

    @Test fun absentIdleOrInitialProtectionNeverConsumesGuard() {
        val missing = Port().apply { idle = false }
        assertNull(missing.run())
        assertEquals(listOf("guard", "idle1"), missing.calls)
        for (reason in scopeChanges) {
            val port = Port().apply { blocked = reason }
            assertNull(reason, port.run())
            assertTrue(reason, port.calls.isEmpty())
            assertFalse(port.persistedGuard)
        }
    }

    @Test fun eligibilityScopeChangesAbortBeforeDurableGuard() {
        val boundaries = mapOf(
            "guard" to null,
            "idle1" to null,
            "helper" to "IDLE_HELPER_UNVERIFIED",
            "channel" to "IDLE_CHANNEL_UNVERIFIED",
            "idle2" to null,
        )
        for ((boundary, expectedReason) in boundaries) {
            for (reason in scopeChanges) {
                val port = Port().apply { after[boundary] = { blocked = reason } }
                val result = port.run()
                assertEquals("$boundary/$reason", expectedReason?.let { failed(it, attempted = false) }, result)
                assertFalse(port.persistedGuard)
                assertEquals(0, port.count("mark"))
                assertEquals(0, port.count("prepare"))
                assertNoSubmission(port)
            }
        }
    }

    @Test fun helperOrChannelFailureNeverWritesGuardOrPrepares() {
        for (boundary in listOf("helper", "channel")) {
            val port = Port().apply { if (boundary == "helper") helper = false else channel = false }
            val reason = if (boundary == "helper") "IDLE_HELPER_UNVERIFIED" else "IDLE_CHANNEL_UNVERIFIED"
            assertEquals(failed(reason, attempted = false), port.run())
            assertFalse(port.persistedGuard)
            assertEquals(0, port.count("mark"))
            assertEquals(0, port.count("prepare"))
            assertNoSubmission(port)
        }
    }

    @Test fun idleLostDuringHelperAndChannelChecksNeverConsumesGuard() {
        val port = Port().apply { after["channel"] = { idle = false } }
        assertNull(port.run())
        assertEquals(2, port.idleChecks)
        assertEquals(0, port.count("mark"))
        assertNoSubmission(port)
    }

    @Test fun guardStorageFailureOrExceptionAfterPreparationNeverSubmits() {
        for (throws in listOf(false, true)) {
            val port = Port().apply { if (throws) crashAt = "mark" else guardStored = false }
            val reason = if (throws) "IDLE_EXCEPTION:IllegalStateException" else "IDLE_GUARD_STORE_FAILED"
            assertEquals(failed(reason, attempted = false), port.run())
            assertFalse(port.persistedGuard)
            assertEquals(1, port.count("mark"))
            assertEquals(1, port.count("prepare"))
            assertNoSubmission(port)
            assertRetrySubmits(port)
        }
    }

    @Test fun preparationFailureOrExceptionNeverConsumesGuardOrSubmits() {
        for (throws in listOf(false, true)) {
            val port = Port().apply {
                if (throws) crashAt = "prepare" else preparationFailure = "POLICY_BACKEND_FAILED"
            }
            val reason = if (throws) "IDLE_EXCEPTION:IllegalStateException"
                else "IDLE_PREPARATION_FAILED:POLICY_BACKEND_FAILED"
            assertEquals(failed(reason, attempted = false), port.run())
            assertEquals(1, port.count("prepare"))
            assertEquals(0, port.count("mark"))
            assertNoSubmission(port)
            assertRetrySubmits(port)
        }
    }

    @Test fun preSubmissionScopeChangesConsumeGuardOnlyAfterMark() {
        for (boundary in listOf("mark", "prepare", "idle3")) {
            for (reason in scopeChanges) {
                val port = Port().apply { after[boundary] = { blocked = reason } }
                val marked = boundary == "mark"
                assertEquals("$boundary/$reason", failed("IDLE_SCOPE_CHANGED", attempted = marked), port.run())
                assertEquals(if (marked) 1 else 0, port.count("mark"))
                assertNoSubmission(port)
                if (marked) assertGuardPreventsReplay(port) else assertRetrySubmits(port)
            }
        }
    }

    @Test fun idleLostOrReadThrowsAfterPreparationNeverConsumesGuardOrSubmits() {
        for (throws in listOf(false, true)) {
            val port = Port().apply {
                if (throws) crashAt = "idle3" else after["prepare"] = { idle = false }
            }
            val reason = if (throws) "IDLE_EXCEPTION:IllegalStateException" else "IDLE_SCOPE_CHANGED"
            assertEquals(failed(reason, attempted = false), port.run())
            assertEquals(0, port.count("mark"))
            assertNoSubmission(port)
            assertRetrySubmits(port)
        }
    }

    @Test fun failedOrThrownSubmissionIsNeverReplayed() {
        for (throws in listOf(false, true)) {
            val port = Port().apply { if (throws) crashAt = "submit" else submitOk = false }
            val reason = if (throws) "IDLE_EXCEPTION:IllegalStateException" else "IDLE_START_FAILED"
            assertEquals(failed(reason), port.run())
            assertEquals(1, port.count("submit"))
            assertEquals(0, port.count("running"))
            assertEquals(0, port.count("functionality"))
            assertGuardPreventsReplay(port)
        }
    }

    @Test fun scopeLostDuringSubmissionPreventsRunningAndFunctionalChecks() {
        for (reason in scopeChanges) {
            val port = Port().apply { after["submit"] = { blocked = reason } }
            assertEquals(reason, failed("IDLE_START_UNCONFIRMED"), port.run())
            assertEquals(1, port.count("submit"))
            assertEquals(0, port.count("running"))
            assertEquals(0, port.count("functionality"))
            assertGuardPreventsReplay(port)
        }
    }

    @Test fun runningFailureOrExceptionPreventsFunctionalityAndKeepsGuard() {
        for (throws in listOf(false, true)) {
            val port = Port().apply { if (throws) crashAt = "running" else runningState = false }
            val reason = if (throws) "IDLE_EXCEPTION:IllegalStateException" else "IDLE_START_UNCONFIRMED"
            assertEquals(failed(reason), port.run())
            assertEquals(0, port.count("functionality"))
            assertGuardPreventsReplay(port)
        }
    }

    @Test fun scopeLostDuringRunningPreventsFunctionalChecks() {
        for (reason in scopeChanges) {
            val port = Port().apply { after["running"] = { blocked = reason } }
            assertEquals(reason, failed("IDLE_FUNCTIONALITY_UNCONFIRMED"), port.run())
            assertEquals(0, port.count("functionality"))
            assertGuardPreventsReplay(port)
        }
    }

    @Test fun functionalityFailureOrExceptionKeepsGuardWithoutReportingReady() {
        for (throws in listOf(false, true)) {
            val port = Port().apply { if (throws) crashAt = "functionality" else functional = false }
            val reason = if (throws) "IDLE_EXCEPTION:IllegalStateException" else "IDLE_FUNCTIONALITY_UNCONFIRMED"
            assertEquals(failed(reason), port.run())
            assertGuardPreventsReplay(port)
        }
    }

    @Test fun scopeLostDuringFunctionalityRejectsSuccessfulProbe() {
        for (reason in scopeChanges) {
            val port = Port().apply { after["functionality"] = { blocked = reason } }
            assertEquals(reason, failed("IDLE_FUNCTIONALITY_UNCONFIRMED"), port.run())
            assertGuardPreventsReplay(port)
        }
    }

    @Test fun persistedGuardBlocksFreshInstanceBeforeEligibilityOrSubmission() {
        val port = Port().apply { persistedGuard = true }
        assertEquals(failed("IDLE_RECOVERY_ALREADY_SUBMITTED", attempted = false), port.run())
        assertEquals(listOf("guard"), port.calls)
    }

    @Test fun eligibilityExceptionsNeverConsumeGuardOrSubmit() {
        for (boundary in listOf("guard", "idle1", "helper", "channel", "idle2")) {
            val port = Port().apply { crashAt = boundary }
            assertEquals(boundary, failed("IDLE_EXCEPTION:IllegalStateException", attempted = false), port.run())
            assertFalse(port.persistedGuard)
            assertEquals(0, port.count("mark"))
            assertNoSubmission(port)
        }
    }

    @Test fun interruptedPreparationRestoresInterruptWithoutConsumingGuard() {
        assertFalse(Thread.currentThread().isInterrupted)
        val port = Port().apply { crashAt = "prepare"; failure = InterruptedException("interrupted") }
        try {
            assertEquals(failed("IDLE_EXCEPTION:InterruptedException", attempted = false), port.run())
            assertTrue(Thread.currentThread().isInterrupted)
            assertFalse(port.persistedGuard)
            assertEquals(0, port.count("mark"))
            assertNoSubmission(port)
        } finally {
            Thread.interrupted()
        }
        assertRetrySubmits(port)
    }

    @Test fun supportedNumericPolicyModesRemainValidThroughJsonGetAndOpt() {
        for (mode in listOf<Number>(0, 1, 3, 0L, 1L, 3L)) {
            val policy = JSONObject().put("effective", mode)
            assertTrue("get $mode/${mode.javaClass.simpleName}",
                UltraIdleRecoveryAttempt.effectivePolicyVerified(policy.get("effective")))
            assertTrue("opt $mode/${mode.javaClass.simpleName}",
                UltraIdleRecoveryAttempt.effectivePolicyVerified(policy.opt("effective")))
        }
    }

    @Test fun jsonNullMissingStringsAndBooleansNeverBecomeEffectivePolicyZero() {
        val policy = JSONObject("""{"absent":null,"zero":"0","one":"1","false":false}""")
        for (key in listOf("absent", "zero", "one", "false")) {
            assertFalse("get $key", UltraIdleRecoveryAttempt.effectivePolicyVerified(policy.get(key)))
            assertFalse("opt $key", UltraIdleRecoveryAttempt.effectivePolicyVerified(policy.opt(key)))
        }
        assertSame(JSONObject.NULL, policy.get("absent"))
        assertNull(policy.opt("missing"))
        assertFalse(UltraIdleRecoveryAttempt.effectivePolicyVerified(policy.opt("missing")))
        assertFalse(UltraIdleRecoveryAttempt.effectivePolicyVerified(JSONObject.NULL))
        assertFalse(UltraIdleRecoveryAttempt.effectivePolicyVerified(null))
    }

    @Test fun unsupportedAndFractionalJsonNumbersNeverVerifyEffectivePolicy() {
        for (mode in listOf<Number>(2, 4, -1, 1.5)) {
            val policy = JSONObject().put("effective", mode)
            assertFalse("get $mode", UltraIdleRecoveryAttempt.effectivePolicyVerified(policy.get("effective")))
            assertFalse("opt $mode", UltraIdleRecoveryAttempt.effectivePolicyVerified(policy.opt("effective")))
        }
    }

    @Test fun nonFiniteNumbersNeverVerifyEffectivePolicy() {
        for (mode in listOf(Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY,
                            Float.NaN, Float.POSITIVE_INFINITY, Float.NEGATIVE_INFINITY)) {
            assertFalse(mode.toString(), UltraIdleRecoveryAttempt.effectivePolicyVerified(mode))
        }
    }
}
