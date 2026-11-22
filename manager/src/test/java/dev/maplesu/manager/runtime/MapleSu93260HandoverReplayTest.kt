package dev.maplesu.manager.runtime

import dev.maplesu.manager.jailbreak.*
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Replay captured backend records; root ownership and command execution remain fixture inputs. */
class MapleSu93260HandoverReplayTest {
    private val records = JSONObject(javaClass.getResourceAsStream("/maplesu-93260/new-log-records.json")!!
        .bufferedReader().use { it.readText() })
    private val daemon = records.getJSONObject("maplesu-hook-daemon.json")
    private val attempt = daemon.getString("attempt")
    private val boot = daemon.getString("bootId")
    private val request = JailbreakRequest("maplesu_93260", attempt, boot,
        rootBackend = JailbreakRequest.BACKEND_HOOK)

    private fun claim(probe: ProbeResult): Pair<ClaimResult, List<JailbreakStatus>> {
        val merged = HookEvidence.merge(
            HookEvidence.parseMain(records.getJSONObject("maplesu-hook.json").toString()),
            HookEvidence.parseUnload(records.getJSONObject("maplesu-hook-unload.json").toString()))!!
        assertNull(GhostlockHandover.refusal(records.getJSONObject("maplesu-handover.json").toString(), request))
        assertNull(HookEvidence.bindingRefusal(merged, boot, attempt))
        assertNull(HookEvidence.refusalToken(merged))
        var status = JailbreakStatus(method = request.method, stage = JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED,
            message = "captured restore", startedAtMillis = 1000, updatedAtMillis = 2000,
            attemptId = attempt, bootId = boot, rootBackend = request.rootBackend,
            restoreState = merged.restoreState, restoreEnforcing = merged.enforcing,
            restoreFailures = merged.failures)
        val writes = mutableListOf<JailbreakStatus>()
        val sink = object : ClaimSink {
            override fun read() = status
            override fun write(value: JailbreakStatus) { status = value; writes += value }
        }
        val gate = SuGate.parse(daemon.toString(), attempt, boot)
        val worker = HookWorker.Attestation(daemon.getInt("uid"), daemon.getInt("pid"), daemon.getInt("pid"),
            "", boot, attempt, daemon.getString("domain"), daemon.getInt("enforcingFinal"),
            daemon.getLong("starttime"), "", boot, attempt, source = HookWorker.SOURCE_DAEMON_RECORD)
        val result = decideHookClaim(request, sink, { worker }, { gate }, proveCarrier = {
            CarrierProver.decideUltra(attempt, boot, 3000, 4242, CarrierProver.UltraFacts(
                gate.armed, gate.attempt, gate.bootId, gate.suToken?.hex, 0,
                HookEvidence.refusalToken(merged), merged.verdict, probe))
        }, ownerPid = 4242)
        return result to writes
    }

    @Test fun capturedUltraRecordsReachTheSharedPublicationWithAUidZeroProbe() {
        val (claim, writes) = claim(ProbeResult("id -u", 0, "0", 0))
        assertTrue(claim.ok)
        assertEquals(listOf(JailbreakStatus.STAGE_CARRIER_PROVEN, JailbreakStatus.STAGE_DAEMON_READY),
            writes.map { it.stage })
        assertTrue(writes.all { it.method == "maplesu_93260" && it.attemptId == attempt && it.bootId == boot })
        assertEquals(HookWorker.SOURCE_DAEMON_RECORD, claim.attestationSource)
        var publications = 0
        assertTrue(publishConfirmedHook(claim) { publications++ }.ok)
        assertEquals(1, publications)
    }

    @Test fun theSameArmedRecordsWithAShellUidNeverPublishReady() {
        val (claim, writes) = claim(ProbeResult("id -u", 0, "2000", 2000))
        assertFalse(claim.ok)
        assertTrue(claim.failure!!.contains("carrier:probe_stdout:2000"))
        assertTrue(writes.none { it.stage == JailbreakStatus.STAGE_DAEMON_READY })
        var publications = 0
        assertFalse(publishConfirmedHook(claim) { publications++ }.ok)
        assertEquals(0, publications)
    }
}
