package dev.maplesu.manager.runtime

import dev.maplesu.manager.jailbreak.HookWorker
import dev.maplesu.manager.jailbreak.JailbreakRequest
import dev.maplesu.manager.jailbreak.JailbreakStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * M3/M4 (report `maplesu-ultra-attestation-stability-2026-10-31.md` §5): a claim answers
 * with a named token, and it writes that token before it answers.
 *
 * <p>Before this, every refusal was an `IllegalStateException` raised inside the
 * provider's binder thread (`NativeSuDirectoryProvider.kt:403-419`). The reason existed
 * only in the caller's stack: `L3SuGateAndroidTest` copied it into `run.failure`, and as
 * soon as the test process died so did the reason (report Q2). These tests drive the pure
 * claim with an in-memory record and assert both halves of the fix - the token's name and
 * the fact that the sink already holds it when the result comes back.
 *
 * <p>M4 adds the second half of the honesty rule: the claim records *where* its evidence
 * came from, and the WEAK source is never described as a kernel-credentialed answer
 * (report R3).
 */
class HookClaimResultTest {

    private val request = JailbreakRequest(
        method = "dirtyfrag",
        attemptId = ATTEMPT,
        bootId = BOOT,
        softReboot = false,
        rootBackend = JailbreakRequest.BACKEND_HOOK,
    )

    /** The record the claim reads and writes; keeps every write for the assertions. */
    private class Sink(private var status: JailbreakStatus?) : ClaimSink {
        val writes = mutableListOf<JailbreakStatus>()
        override fun read(): JailbreakStatus? = status
        override fun write(status: JailbreakStatus) {
            this.status = status
            writes += status
        }

        fun last(): JailbreakStatus = writes.last()
    }

    private fun observed(
        stage: String = JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED,
        failure: String? = null,
        enforcing: Int? = 1,
        state: String? = "RESTORED_BASELINE",
    ) = JailbreakStatus(
        method = "dirtyfrag",
        stage = stage,
        message = "hook evidence observed",
        startedAtMillis = 1_000L,
        updatedAtMillis = 1_000L,
        bootId = BOOT,
        attemptId = ATTEMPT,
        ownerPid = 4242,
        restoreState = state,
        restoreOrigin = "jailbreak:dirtyfrag:" + ATTEMPT,
        restoreEnforcing = enforcing,
        restoreFailures = 0,
        rootBackend = JailbreakRequest.BACKEND_HOOK,
        failure = failure,
    )

    private fun gate() = SuGate.Gate(
        suToken = SuGate.Token(TOKEN),
        suGate = SuGate.ARMED,
        bound = true,
        attempt = ATTEMPT,
        bootId = BOOT,
    )

    private fun proven(status: JailbreakStatus) = CarrierProver.Result.Proven(
        dev.maplesu.manager.jailbreak.CarrierProof(
            kind = CarrierProver.KIND_L3,
            attemptId = status.attemptId!!,
            bootId = status.bootId!!,
            provenAtMillis = 2_000L,
            probe = dev.maplesu.manager.jailbreak.ProbeResult("id -u", 0, "0", 0),
        ),
    )

    private fun attestation(
        source: String = HookWorker.SOURCE_UCRED,
        peerUid: Int = 0,
        enforcing: Int? = 1,
    ) = HookWorker.Attestation(
        peerUid = peerUid,
        peerPid = 18001,
        replyPid = 18001,
        replyNonce = "",
        replyBootId = BOOT,
        replyAttempt = ATTEMPT,
        domain = "u:r:kernel:s0",
        enforcing = enforcing,
        starttime = 12345L,
        nonce = "",
        bootId = BOOT,
        attempt = ATTEMPT,
        source = source,
    )

    @Test
    fun `a claim that is not in the observed stage returns its token and writes it`() {
        val sink = Sink(observed(stage = JailbreakStatus.STAGE_PROVIDER_RUNNING))
        val result = decideHookClaim(request, sink, { error("must not attest") }, { gate() },
            proveCarrier = { proven(it) }, ownerPid = 4242)
        assertEquals("SU_DIRECTORY_ATTEMPT_NOT_CONFIRMED:PROVIDER_RUNNING", result.failure)
        assertEquals(JailbreakStatus.STAGE_PROVIDER_RUNNING, result.stage)
        assertFalse(result.ok)
        assertNull(result.attestationSource)
        assertEquals("the refusal must already be on disk", 1, sink.writes.size)
        assertEquals(result.failure, sink.last().failure)
    }

    @Test
    fun `a claim whose record is missing returns a named token without inventing a claim`() {
        val sink = Sink(null)
        val result = decideHookClaim(request, sink, { null }, { gate() }, proveCarrier = { proven(it) }, ownerPid = 4242)
        assertEquals("SU_DIRECTORY_ATTEMPT_NOT_CONFIRMED:missing", result.failure)
        assertTrue("nothing to write: there is no attempt record to attach it to",
            sink.writes.isEmpty())
    }

    @Test
    fun `a restore that is not a restored enforcing baseline is refused by name`() {
        for ((enforcing, state, expected) in listOf(
            Triple(0, "RESTORED_BASELINE", "HOOK_BACKEND_NOT_READY:restore_not_enforcing"),
            Triple(1, "OK", "HOOK_BACKEND_NOT_READY:restore_not_enforcing"),
            Triple(null, "RESTORED_BASELINE", "HOOK_BACKEND_NOT_READY:restore_not_enforcing"),
        )) {
            val sink = Sink(observed(enforcing = enforcing, state = state))
            val result = decideHookClaim(request, sink, { error("must not attest") },
                { gate() }, proveCarrier = { proven(it) }, ownerPid = 4242)
            assertEquals(expected, result.failure)
            assertEquals("the record must not claim anything", 1, sink.writes.size)
            assertEquals(expected, sink.last().failure)
            assertEquals("the stage never moves backwards or forwards",
                JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED, sink.last().stage)
        }
    }

    @Test
    fun `an absent worker is worker_unreachable and the status says so`() {
        val sink = Sink(observed())
        val result = decideHookClaim(request, sink, { null }, { gate() }, proveCarrier = { proven(it) }, ownerPid = 4242)
        assertEquals("HOOK_BACKEND_NOT_READY:worker_unreachable", result.failure)
        assertEquals(result.failure, sink.last().failure)
        assertTrue("the message names the reason: " + sink.last().message,
            sink.last().message.contains("no attestation worker"))
    }

    @Test
    fun `a refused attestation keeps its own reason`() {
        val sink = Sink(observed())
        val result = decideHookClaim(request, sink, { attestation(peerUid = 10213) },
            { gate() }, proveCarrier = { proven(it) }, ownerPid = 4242)
        assertEquals("HOOK_BACKEND_NOT_READY:worker_identity", result.failure)
        // M4: the claim still says which evidence it looked at.
        assertEquals(HookWorker.SOURCE_UCRED, result.attestationSource)
        assertEquals(result.failure, sink.last().failure)
        assertTrue(sink.last().message.contains("attestationSource=ucred"))
    }

    @Test
    fun `an unavailable gate keeps the claim unsuccessful and prevents automatic reboot`() {
        val sink = Sink(observed())
        val result = decideHookClaim(request, sink, { attestation() },
            { SuGate.Gate.UNAVAILABLE_GATE }, proveCarrier = { proven(it) }, ownerPid = 4242)
        assertFalse(result.ok)
        assertEquals("HOOK_BACKEND_NOT_READY:su_gate_not_armed", result.failure)
        assertEquals(JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED, sink.last().stage)
        assertEquals(result.failure, sink.last().failure)
        var dispatched = false
        dev.maplesu.manager.jailbreak.JailbreakAutomaticReboot({ null }, { true }).onSuccess(
            true, JailbreakRequest.BACKEND_HOOK,
            dev.maplesu.manager.jailbreak.JailbreakController.Outcome(
                result.stage, "test", result.failure, ATTEMPT),
        ) { dispatched = true; false }
        assertFalse(dispatched)
    }

    @Test
    fun `an unreadable gate is not a successful worker claim`() {
        val sink = Sink(observed())
        val result = decideHookClaim(request, sink, { attestation() },
            { throw java.io.IOException("unreadable") }, proveCarrier = { proven(it) }, ownerPid = 4242)
        assertFalse(result.ok)
        assertEquals("HOOK_BACKEND_NOT_READY:su_gate_not_armed", result.failure)
        assertEquals(result.failure, sink.last().failure)
    }

    @Test
    fun `an unavailable gate records the helper reason without publishing its token`() {
        val sink = Sink(observed())
        val result = decideHookClaim(request, sink, { attestation() },
            { SuGate.Gate(null, SuGate.UNAVAILABLE, true, ATTEMPT, BOOT,
                reason = "STAGE2_LOAD_FAILED") }, proveCarrier = { error("must not prove") }, ownerPid = 4242)
        assertEquals("HOOK_BACKEND_NOT_READY:su_gate_not_armed", result.failure)
        assertTrue(sink.last().message.contains("reason=STAGE2_LOAD_FAILED"))
        assertTrue(sink.last().message.contains("bound=true"))
        assertNull(sink.last().suToken)
    }

    @Test
    fun `an armed gate whose real child fails never becomes ready`() {
        val sink = Sink(observed())
        val result = decideHookClaim(request, sink, { attestation() }, { gate() },
            proveCarrier = { CarrierProver.Result.Rejected("probe_exit:126") }, ownerPid = 4242)
        assertFalse(result.ok)
        assertEquals("HOOK_BACKEND_NOT_READY:carrier:probe_exit:126", result.failure)
        assertEquals(result.failure, sink.last().failure)
        assertEquals(JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED, sink.last().stage)
    }

    @Test
    fun `a carrier probe exception returns a named unsuccessful claim`() {
        val sink = Sink(observed())
        val result = decideHookClaim(request, sink, { attestation() }, { gate() },
            proveCarrier = { throw java.io.IOException("probe") }, ownerPid = 4242)
        assertFalse(result.ok)
        assertEquals("HOOK_BACKEND_NOT_READY:carrier:probe_failed:IOException", result.failure)
    }

    @Test
    fun `a recovery whose real child fails preserves historical evidence but reports failure`() {
        val status = observed(stage = JailbreakStatus.STAGE_DAEMON_READY).copy(
            carrier = proven(observed()).proof,
        )
        val sink = Sink(status)
        val result = confirmHookCarrier(status, sink,
            { CarrierProver.Result.Rejected("probe_exit:126") }, ownerPid = 4242)
        assertFalse(result.ok)
        assertEquals("HOOK_BACKEND_NOT_READY:carrier:probe_exit:126", result.failure)
        assertTrue(sink.writes.isEmpty())
    }

    @Test
    fun `a ready recovery refreshes its proof without moving backwards`() {
        val status = observed(stage = JailbreakStatus.STAGE_DAEMON_READY)
        val sink = Sink(status)
        val result = confirmHookCarrier(status, sink, { proven(it) }, ownerPid = 4242)
        assertTrue(result.ok)
        assertEquals(listOf(JailbreakStatus.STAGE_DAEMON_READY), sink.writes.map { it.stage })
        assertEquals(0, sink.last().carrier?.probe?.uid)
    }

    @Test
    fun `normal failed su proof persists failure without publishing ready`() {
        val status = observed().copy(rootBackend = JailbreakRequest.BACKEND_KSU)
        val sink = Sink(status)
        val result = confirmHookCarrier(status, sink,
            { CarrierProver.Result.Rejected("probe_exit:126") }, ownerPid = 4242)
        assertFalse(result.ok)
        assertEquals("KSU_BACKEND_NOT_READY:carrier:probe_exit:126", result.failure)
        assertEquals(result.failure, sink.last().failure)
        assertEquals(listOf(JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED),
            sink.writes.map { it.stage })
    }

    @Test
    fun `normal publishes ready only after its real carrier proof`() {
        val status = observed().copy(rootBackend = JailbreakRequest.BACKEND_KSU)
        val sink = Sink(status)
        val result = confirmHookCarrier(status, sink, {
            assertTrue(sink.writes.isEmpty())
            proven(it).let { proof -> CarrierProver.Result.Proven(
                proof.proof.copy(kind = CarrierProver.KIND_KSU)) }
        }, ownerPid = 4242)
        assertTrue(result.ok)
        assertEquals(listOf(JailbreakStatus.STAGE_CARRIER_PROVEN,
            JailbreakStatus.STAGE_DAEMON_READY), sink.writes.map { it.stage })
        assertEquals(CarrierProver.KIND_KSU, sink.last().carrier?.kind)
    }

    @Test
    fun `a process interrupted after carrier proof can finish ready`() {
        val status = observed(stage = JailbreakStatus.STAGE_CARRIER_PROVEN).copy(
            carrier = proven(observed()).proof,
        )
        val sink = Sink(status)
        val result = confirmHookCarrier(status, sink, { proven(it) }, ownerPid = 4242)
        assertTrue(result.ok)
        assertEquals(listOf(JailbreakStatus.STAGE_DAEMON_READY), sink.writes.map { it.stage })
    }

    @Test
    fun `a successful claim writes daemon ready with its evidence source`() {
        val sink = Sink(observed())
        val result = decideHookClaim(request, sink, { attestation() }, { gate() },
            proveCarrier = { proven(it) }, ownerPid = 4242)
        assertNull(result.failure)
        assertTrue(result.ok)
        assertEquals(JailbreakStatus.STAGE_DAEMON_READY, result.stage)
        assertEquals(HookWorker.SOURCE_UCRED, result.attestationSource)

        assertEquals(listOf(JailbreakStatus.STAGE_CARRIER_PROVEN,
            JailbreakStatus.STAGE_DAEMON_READY), sink.writes.map { it.stage })
        assertEquals(0, sink.last().carrier?.probe?.uid)

        val written = sink.last()
        assertEquals(JailbreakStatus.STAGE_DAEMON_READY, written.stage)
        assertEquals(18001, written.workerPid)
        assertEquals(SuGate.ARMED, written.suGate)
        assertEquals(TOKEN, written.suToken)
        assertEquals(4242, written.ownerPid)
        assertTrue("the message must carry the source: " + written.message,
            written.message.contains("attestationSource=ucred"))
        assertTrue("the socket path may say the worker answered: " + written.message,
            written.message.contains("kernel-credentialed worker"))
    }

    @Test
    fun `a daemon record is accepted but never described as a kernel answer`() {
        val sink = Sink(observed())
        val result = decideHookClaim(request, sink,
            { attestation(source = HookWorker.SOURCE_DAEMON_RECORD) }, { gate() },
            proveCarrier = { proven(it) }, ownerPid = 4242)
        assertTrue("the record is still the only evidence some devices have", result.ok)
        assertEquals(HookWorker.SOURCE_DAEMON_RECORD, result.attestationSource)

        val message = sink.last().message
        assertTrue("the weak path must say so: " + message,
            message.contains("attestationSource=daemon-record"))
        assertTrue("the weak path must say WEAK: " + message, message.contains("WEAK"))
        assertFalse("R3: the record file has no ucred, so this word is forbidden: " + message,
            message.contains("kernel-credentialed"))
        assertFalse("R3: nothing answered on a socket here: " + message,
            message.contains(" answered"))
    }

    @Test
    fun `a weak attestation is refused when the caller demands the kernel ucred`() {
        // The claim itself keeps M4's default (record as evidence); this is the gate a
        // future acceptance caller uses, and it must fail closed rather than upgrade.
        assertEquals("worker_evidence_weak",
            HookWorker.refusal(attestation(source = HookWorker.SOURCE_DAEMON_RECORD),
                requireUcred = true))
    }

    @Test
    fun `the listener outcome travels into the record, refusals included`() {
        // Q1/U4: "the listener never came up" and "it came up and nobody connected" must
        // stop looking identical in the evidence, and the refusal is where it matters.
        val refused = Sink(observed())
        decideHookClaim(request, refused, { null }, { gate() }, proveCarrier = { proven(it) }, ownerPid = 4242,
            attestServer = "bind_failed")
        assertTrue("a refusal must say what the listener did: " + refused.last().message,
            refused.last().message.contains("attestServer=bind_failed"))

        val accepted = Sink(observed())
        decideHookClaim(request, accepted, { attestation() }, { gate() }, proveCarrier = { proven(it) }, ownerPid = 4242,
            attestServer = "accepted")
        assertTrue("a pass must say what the listener did: " + accepted.last().message,
            accepted.last().message.contains("attestServer=accepted"))
    }

    @Test
    fun `a status write failure is itself a named token`() {
        val failing = object : ClaimSink {
            override fun read(): JailbreakStatus? = observed()
            override fun write(status: JailbreakStatus) = throw java.io.IOException("ENOSPC")
        }
        val result = decideHookClaim(request, failing, { attestation() }, { gate() },
            proveCarrier = { proven(it) }, ownerPid = 4242)
        assertEquals("SU_DIRECTORY_STATUS_WRITE_FAILED", result.failure)
        assertFalse(result.ok)
    }

    private companion object {
        const val ATTEMPT = "611efa15-0a4d-4c1f-9b7e-3f2f9c1d2e3f"
        const val BOOT = "a666f35b-2fd2-4f6e-9c2d-1a3b5c7d9e0f"
        const val TOKEN = "0123456789abcdef"
    }
}
