package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Host regression for the attestation gate (step-4 D4, design §3.1/§3.5 item 10).
 *
 * <p>The whole value of this proof rests on **where** the identity comes from: the
 * kernel's `SO_PEERCRED` ucred, not the worker's own JSON. A worker that says
 * `{"uid":0}` proves nothing - the App could bind that socket itself - so every test
 * below varies one field of the *kernel* side or of the *binding* and asserts that the
 * gate refuses with the right named reason. None of them may pass by accident.
 *
 * <p>**M4 (report `maplesu-ultra-attestation-stability-2026-10-31.md` §5).** The fourth
 * source of error is now named: an identity taken from the worker's own root-owned
 * record instead of the kernel's ucred is real evidence, but weaker, and it says so
 * ([HookWorker.SOURCE_DAEMON_RECORD]). A caller that needs the transport proof uses
 * `requireUcred`, which refuses it by name instead of quietly accepting it - that is the
 * R3 defect this test pins down.
 */
class HookWorkerAttestationTest {

    private fun attestation(
        peerUid: Int = 0,
        peerPid: Int = 18001,
        replyPid: Int = 18001,
        replyNonce: String? = NONCE,
        replyBootId: String? = BOOT,
        replyAttempt: String? = ATTEMPT,
        enforcing: Int? = 1,
        domain: String? = "u:r:kernel:s0",
        source: String = HookWorker.SOURCE_UCRED,
    ) = HookWorker.Attestation(
        peerUid = peerUid, peerPid = peerPid, replyPid = replyPid,
        replyNonce = replyNonce, replyBootId = replyBootId, replyAttempt = replyAttempt,
        domain = domain, enforcing = enforcing, starttime = 12345,
        nonce = NONCE, bootId = BOOT, attempt = ATTEMPT, source = source,
    )

    @Test
    fun `a uid0 worker that answers for this attempt passes`() {
        assertNull(HookWorker.refusal(attestation()))
    }

    @Test
    fun `a non-root peer is refused no matter what the reply claims`() {
        // The reply is perfect; only the kernel's ucred says otherwise. This is the
        // exact forgery the App could mount on itself in rev 1 (self-reported uid).
        assertEquals("worker_identity", HookWorker.refusal(attestation(peerUid = 10213)))
    }

    @Test
    fun `the reply pid must be the kernel pid of this connection`() {
        assertEquals("worker_identity", HookWorker.refusal(attestation(replyPid = 18002)))
        assertEquals("worker_identity", HookWorker.refusal(attestation(peerPid = 0)))
    }

    @Test
    fun `the nonce must be the one this connection sent`() {
        assertEquals("worker_identity",
            HookWorker.refusal(attestation(replyNonce = "other")))
        assertEquals("worker_identity", HookWorker.refusal(attestation(replyNonce = null)))
    }

    @Test
    fun `the reply must name this boot and this attempt`() {
        assertEquals("worker_identity",
            HookWorker.refusal(attestation(replyBootId = "b0000000-0000-0000-0000-000000000000")))
        assertEquals("worker_identity",
            HookWorker.refusal(attestation(replyAttempt = "00000000-0000-0000-0000-000000000000")))
        // Asking for nothing means nothing to bind against; the caller always passes both.
        assertNull(HookWorker.refusal(attestation(replyBootId = null, replyAttempt = null)
            .copy(bootId = null, attempt = null)))
    }

    @Test
    fun `an unobserved enforcing readback is its own refusal`() {
        // R-D2: the worker's pre-opened descriptor pool ran out and the fallback open
        // failed. "Unknown" must never be read as "enforcing".
        assertEquals("worker_enforcing_unobserved",
            HookWorker.refusal(attestation(enforcing = null)))
    }

    @Test
    fun `a worker that reads permissive is refused`() {
        assertEquals("restore_not_enforcing", HookWorker.refusal(attestation(enforcing = 0)))
    }

    @Test
    fun `the evidence source names are the ones the evidence scripts read`() {
        // report §S2/§S6: the acceptance script reads `attestationSource`, so these two
        // spellings are part of the protocol, not an implementation detail.
        assertEquals("ucred", HookWorker.SOURCE_UCRED)
        assertEquals("daemon-record", HookWorker.SOURCE_DAEMON_RECORD)
        assertEquals(HookWorker.SOURCE_UCRED, attestation().source)
        assertFalse(attestation().weak)
    }

    @Test
    fun `a daemon record is accepted by default but reported as weak`() {
        // The unsocketed path is still evidence: a root-owned file, matching attempt and
        // boot, uid 0, kernel domain, enforcingFinal == 1. It is not a transport proof,
        // and `weak` is how everything downstream knows the difference (report R3).
        val record = attestation(source = HookWorker.SOURCE_DAEMON_RECORD)
        assertNull(HookWorker.refusal(record))
        assertTrue(record.weak)
    }

    @Test
    fun `a daemon record is refused when the caller requires the kernel ucred`() {
        assertEquals("worker_evidence_weak",
            HookWorker.refusal(attestation(source = HookWorker.SOURCE_DAEMON_RECORD),
                requireUcred = true))
        // The same fields over the socket path pass: only the source differs.
        assertNull(HookWorker.refusal(attestation(), requireUcred = true))
    }

    @Test
    fun `the socket name is attempt prefixed so a survivor cannot collide`() {
        val directory = java.io.File("/data/user_de/0/dev.maplesu.manager")
        assertEquals(java.io.File(directory, "maplesu-hook-611efa15.sock"),
            HookWorker.socketFile(directory, ATTEMPT))
        assertEquals(java.io.File(directory, "maplesu-hook-00000000.sock"),
            HookWorker.socketFile(directory, "00000000-0000-0000-0000-000000000000"))
        // One naming rule for both halves: the listener derives its file from this.
        assertEquals("maplesu-hook-611efa15.sock", HookWorker.socketName(ATTEMPT))
    }

    private companion object {
        const val ATTEMPT = "611efa15-0a4d-4c1f-9b7e-3f2f9c1d2e3f"
        const val BOOT = "a666f35b-2fd2-4f6e-9c2d-1a3b5c7d9e0f"
        const val NONCE = "3f2f9c1d-2e3f-4a4d-8c1f-611efa150a4d"
    }
}
