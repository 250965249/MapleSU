package dev.maplesu.manager.runtime

import dev.maplesu.manager.jailbreak.ProbeResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * T6 host tests (§6.2 / §7 T6): the L3 proof is the conjunction of the gate being
 * ARMED for *this* attempt and boot, the helper's record being root-owned, the hook
 * evidence being OK, and a real child behind that gate printing `0` for `id -u`.
 */
class CarrierProofUltraTest {
    private fun probe(exit: Int = 0, stdout: String = "0", uid: Int = 0) =
        ProbeResult("/system/bin/sh -c 'id -u'", exit, stdout, uid)

    private fun facts(
        gateArmed: Boolean = true,
        gateAttempt: String? = "attempt-1",
        gateBootId: String? = "boot-a",
        tokenHex: String? = "0123456789abcdef",
        recordOwnerUid: Int? = 0,
        evidenceRefusal: String? = null,
        evidenceVerdict: String? = "OK",
        probe: ProbeResult? = probe(),
    ) = CarrierProver.UltraFacts(
        gateArmed = gateArmed,
        gateAttempt = gateAttempt,
        gateBootId = gateBootId,
        tokenHex = tokenHex,
        recordOwnerUid = recordOwnerUid,
        evidenceRefusal = evidenceRefusal,
        evidenceVerdict = evidenceVerdict,
        probe = probe,
    )

    private fun decide(facts: CarrierProver.UltraFacts) =
        CarrierProver.decideUltra("attempt-1", "boot-a", 1_000L, 4242, facts)

    private fun assertRejected(result: CarrierProver.Result, fragment: String) {
        assertTrue("expected rejection, got $result", result is CarrierProver.Result.Rejected)
        val reason = (result as CarrierProver.Result.Rejected).reason
        assertTrue("reason '$reason' must mention '$fragment'", reason.contains(fragment))
    }

    @Test
    fun allFourFactsProduceAL3Proof() {
        val result = decide(facts())

        assertTrue(result is CarrierProver.Result.Proven)
        val proof = (result as CarrierProver.Result.Proven).proof
        assertEquals("l3-gate", proof.kind)
        assertEquals("attempt-1", proof.attemptId)
        assertEquals("boot-a", proof.bootId)
        assertEquals("ARMED", proof.facts["gate"])
        assertEquals("0", proof.facts["recordOwnerUid"])
        assertEquals(64, proof.facts["tokenSha256"]?.length)
        assertNotEquals("the token itself must never be stored",
            "0123456789abcdef", proof.facts["tokenSha256"])
        assertEquals(0, proof.probe?.exitCode)
        assertEquals(0, proof.probe?.uid)
    }

    @Test
    fun anUnarmedGateIsRefused() = assertRejected(decide(facts(gateArmed = false)), "gate_not_armed")

    @Test
    fun aGateForAnotherAttemptIsRefused() =
        assertRejected(decide(facts(gateAttempt = "attempt-2")), "gate_foreign_attempt")

    @Test
    fun aGateForAnotherBootIsRefused() =
        assertRejected(decide(facts(gateBootId = "boot-b")), "gate_foreign_boot")

    @Test
    fun aRecordNotOwnedByRootIsRefused() =
        assertRejected(decide(facts(recordOwnerUid = 10123)), "record_not_root_owned")

    @Test
    fun refusedHookEvidenceIsRefused() =
        assertRejected(decide(facts(evidenceRefusal = "MAPLESU_HOOK_RESTORE_UNVERIFIED")),
            "hook_evidence")

    @Test
    fun nonOkHookVerdictIsRefused() =
        assertRejected(decide(facts(evidenceVerdict = "DEGRADED")), "hook_verdict")

    @Test
    fun aProbeThatDidNotExitZeroIsRefused() =
        assertRejected(decide(facts(probe = probe(exit = 126, stdout = "", uid = 0))), "probe_exit")

    @Test
    fun aProbeThatPrintedANonRootUidIsRefused() =
        assertRejected(decide(facts(probe = probe(stdout = "1000", uid = 1000))), "probe_stdout")

    @Test
    fun aProbeMissingItsUidIsRefused() =
        assertRejected(decide(facts(probe = probe(stdout = "0", uid = -1))), "probe_uid")

    @Test
    fun aMissingProbeIsRefused() = assertRejected(decide(facts(probe = null)), "probe_missing")

    @Test
    fun theTokenIsHashedNotCopied() {
        assertFalse(CarrierProver.sha256Hex("0123456789abcdef").contains("0123456789abcdef"))
    }
}
