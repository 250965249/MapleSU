package dev.maplesu.manager.runtime

import dev.maplesu.manager.jailbreak.JailbreakRequest
import dev.maplesu.manager.jailbreak.JailbreakStatus
import dev.maplesu.manager.jailbreak.ProbeResult
import dev.maplesu.manager.runtime.authorization.SuperuserControl
import org.junit.Assert.*
import org.junit.Test

/** Recovery must publish a status that the authorization transport can actually use. */
class HookRecoveryAuthorityTest {
    private val attempt = "c46446ca-258f-42e0-ac85-1576ae8d92d0"
    private val boot = "e39ad72a-f943-4e3b-a263-1e855da09c34"
    private val gate = SuGate.Gate(SuGate.Token("0123456789abcdef"), SuGate.ARMED, true, attempt, boot)

    private fun status(stage: String, method: String = "ghostlock") = JailbreakStatus(
        method = method, stage = stage, message = "cancel requested",
        startedAtMillis = 1, updatedAtMillis = 2, bootId = boot, attemptId = attempt,
        rootBackend = JailbreakRequest.BACKEND_HOOK,
        failure = if (stage == JailbreakStatus.STAGE_CANCELLED) "JAILBREAK_CANCELLED" else null,
    )

    private fun proof(status: JailbreakStatus) = CarrierProver.decideUltra(
        status.attemptId, status.bootId, 3, 4242,
        CarrierProver.UltraFacts(true, attempt, boot, gate.suToken!!.hex, 0, null, "OK",
            ProbeResult("id -u", 0, "0", 0)),
    )

    @Test fun recoveredSessionReachesTheAuthorizationTransport() {
        for (method in listOf("dirtyfrag", "ghostlock")) {
            for (stage in listOf(JailbreakStatus.STAGE_CANCELLED, JailbreakStatus.STAGE_PROVIDER_RUNNING,
                    JailbreakStatus.STAGE_CARRIER_PROVEN, JailbreakStatus.STAGE_DAEMON_READY)) {
                var persisted = status(stage, method)
                val sink = object : ClaimSink {
                    override fun read() = persisted
                    override fun write(status: JailbreakStatus) { persisted = status }
                }
                val result = confirmHookCarrier(persisted, sink, ::proof, 4242)
                assertTrue(result.ok)
                assertNull(persisted.failure)
                assertTrue("$method/$stage: recovery reported success but HOOK_AUTHORITY_UNAVAILABLE remains",
                    SuperuserControl.hookGate(persisted, gate).armed)
            }
        }
    }

    @Test fun failedRootProbeNeverPublishesAnAuthorizationTransport() {
        for (method in listOf("dirtyfrag", "ghostlock")) {
            val original = status(JailbreakStatus.STAGE_DAEMON_READY, method)
            var persisted = original
            val sink = object : ClaimSink {
                override fun read() = persisted
                override fun write(status: JailbreakStatus) { persisted = status }
            }
            val result = confirmHookCarrier(original, sink, { CarrierProver.Result.Rejected("probe_exit:126") }, 4242)
            assertFalse(result.ok)
            assertFalse(SuperuserControl.hookGate(persisted, gate).armed)
        }
    }
}
