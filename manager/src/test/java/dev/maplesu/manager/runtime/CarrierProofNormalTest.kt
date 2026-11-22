package dev.maplesu.manager.runtime

import dev.maplesu.manager.jailbreak.ProbeResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * T7 host tests (§6.2 / §7 T7): the Normal proof requires `kernelsu` in /proc/modules,
 * an executable packaged `ksud`, its version answer, and a real child printing `0`.
 */
class CarrierProofNormalTest {
    private fun probe(exit: Int = 0, stdout: String = "0", uid: Int = 0) =
        ProbeResult("/system/bin/sh -c 'id -u'", exit, stdout, uid)

    private fun facts(
        loaded: Boolean = true,
        ksudPath: String? = "/data/adb/ksud",
        executable: Boolean = true,
        version: String? = "3.1.0-maplesu",
        probe: ProbeResult? = probe(),
    ) = CarrierProver.NormalFacts(loaded, ksudPath, executable, version, probe)

    private fun decide(facts: CarrierProver.NormalFacts) =
        CarrierProver.decideNormal("attempt-1", "boot-a", 1_000L, 4242, facts)

    private fun assertRejected(result: CarrierProver.Result, fragment: String) {
        assertTrue("expected rejection, got $result", result is CarrierProver.Result.Rejected)
        val reason = (result as CarrierProver.Result.Rejected).reason
        assertTrue("reason '$reason' must mention '$fragment'", reason.contains(fragment))
    }

    @Test
    fun loadedKernelsuExecutableKsudAndProbeProduceAKsuProof() {
        val result = decide(facts())

        assertTrue(result is CarrierProver.Result.Proven)
        val proof = (result as CarrierProver.Result.Proven).proof
        assertEquals("ksu-lkm", proof.kind)
        assertEquals("kernelsu", proof.facts["module"])
        assertEquals("true", proof.facts["procModules"])
        assertEquals("/data/adb/ksud", proof.facts["ksud"])
        assertEquals("3.1.0-maplesu", proof.facts["ksudVersion"])
        assertEquals("OK", proof.facts["lateLoad"])
        assertEquals(0, proof.probe?.uid)
    }

    @Test
    fun aBootWithoutKernelsuIsRefused() =
        assertRejected(decide(facts(loaded = false)), "kernelsu_not_loaded")

    @Test
    fun aMissingKsudPathIsRefused() =
        assertRejected(decide(facts(ksudPath = null)), "ksud_path_missing")

    @Test
    fun aNonExecutableKsudIsRefused() =
        assertRejected(decide(facts(executable = false)), "ksud_not_executable")

    @Test
    fun anUnavailableKsudVersionIsRefused() =
        assertRejected(decide(facts(version = " ")), "ksud_version_unavailable")

    @Test
    fun aProbeThatDidNotExitZeroIsRefused() =
        assertRejected(decide(facts(probe = probe(exit = 1, stdout = "", uid = 0))), "probe_exit")

    @Test
    fun aProbeThatPrintedANonRootUidIsRefused() =
        assertRejected(decide(facts(probe = probe(stdout = "2000", uid = 2000))), "probe_stdout")

    @Test
    fun aMissingProbeIsRefused() = assertRejected(decide(facts(probe = null)), "probe_missing")
}
