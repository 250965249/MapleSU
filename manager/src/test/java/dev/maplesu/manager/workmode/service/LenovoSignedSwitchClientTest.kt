package dev.maplesu.manager.workmode.service

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class LenovoSignedSwitchClientTest {
    private fun state(id: String, state: String) = ClientStatus(id, state, "", "", "KSU", "LITE", "", "", "",
        state == "REBOOT_REQUIRED", state == "VERIFIED", true, false, 0, emptyList())
    private open class Fake(private val calls: MutableList<String>, private val prefix: String) : ModeSwitchClient {
        var current: ClientStatus? = null
        var failSnapshot = false
        var failAbort = false
        private fun call(name: String) = ClientResult(true, status = current).also { calls += "$prefix:$name" }
        override suspend fun preflight(switchId: String, planFields: Map<String, String>) = call("preflight")
        override suspend fun begin(switchId: String, planFields: Map<String, String>, superuserJson: File, settingsMirrorJson: File): ClientResult {
            current = ClientStatus(switchId, "BEGIN", "", "", "KSU", "LITE", "", "", "", false, false, false, false, 0, emptyList())
            return call("begin")
        }
        override suspend fun snapshot(switchId: String): ClientResult {
            if (!failSnapshot) current = current?.copy(state = "SNAPSHOT")
            return call("snapshot").copy(ok = !failSnapshot)
        }
        override suspend fun exportImage(switchId: String, kind: String, partition: String, destination: File) = true.also { call("export") }
        override suspend fun submitCandidate(switchId: String, partition: String, candidate: File, candidateSha256: String) = call("submit")
        override suspend fun commit(switchId: String) = call("commit")
        override suspend fun rollback(switchId: String) = call("rollback")
        override suspend fun abort(switchId: String): ClientResult {
            if (!failAbort) current = current?.copy(state = "CANCELLED")
            return call("abort").copy(ok = !failAbort)
        }
        override fun status(switchId: String) = current
        override suspend fun verify(switchId: String) = call("verify")
        override suspend fun markRebootRequested(switchId: String) = true
        override suspend fun exportLog(switchId: String, destination: File) = destination
    }
    private class Signed(calls: MutableList<String>) : Fake(calls, "signed"), SignedSwitchClient {
        var task: String? = null
        var vivo = false
        override fun standalone(switchId: String) = owns(switchId) && vivo
        override fun owns(switchId: String) = task == switchId
        override fun latestId() = task
        override suspend fun begin(switchId: String, planFields: Map<String, String>, superuserJson: File, settingsMirrorJson: File): ClientResult {
            task = switchId
            vivo = planFields["vivoCompatibility"] == "1"
            return super.begin(switchId, planFields, superuserJson, settingsMirrorJson)
        }
    }
    private val file = File("unused.img")

    @Test fun vivoUsesOneNativePreparationAndPreservesItsRouteAfterRestart() = runBlocking {
        val calls = mutableListOf<String>()
        val signed = Signed(calls)
        val client = LenovoSignedSwitchClient(Fake(calls, "ordinary"), signed)
        val fields = mapOf("vivoCompatibility" to "1")
        client.preflight("id", fields); client.begin("id", fields, file, file); client.snapshot("id")
        client.exportImage("id", "PRE", "vendor_boot", file)
        client.submitCandidate("id", "vendor_boot", file, "hash")
        client.submitCandidate("id", "init_boot", file, "hash")
        client.submitCandidate("id", "boot", file, "hash"); client.commit("id")
        assertTrue(calls.all { it.startsWith("signed:") })
        assertEquals(1, calls.count { it == "signed:snapshot" })
        calls.clear()
        val restarted = LenovoSignedSwitchClient(Fake(calls, "ordinary"), signed)
        assertTrue(restarted.rollback("id").ok)
        assertEquals(listOf("signed:rollback"), calls)
    }

    @Test fun optInKeepsBaselineCaptureButRoutesAllWritesThroughTheSignedBatch() = runBlocking {
        val calls = mutableListOf<String>()
        val ordinary = Fake(calls, "ordinary")
        val signed = Signed(calls)
        val client = LenovoSignedSwitchClient(ordinary, signed)
        val fields = mapOf("lenovoSigning" to "AOSP")
        client.preflight("id", fields); client.begin("id", fields, file, file); client.snapshot("id")
        client.exportImage("id", "BASE", "boot", file); client.submitCandidate("id", "boot", file, "hash"); client.commit("id")
        assertEquals(listOf("ordinary:preflight", "ordinary:begin", "signed:begin", "ordinary:snapshot", "signed:snapshot", "ordinary:abort",
            "signed:export", "signed:submit", "signed:commit"), calls)
        assertTrue(client.signedActive)
    }
    @Test fun ordinaryRequestsUseTheExistingWriter() = runBlocking {
        val calls = mutableListOf<String>()
        val client = LenovoSignedSwitchClient(Fake(calls, "ordinary"), Signed(calls))
        client.preflight("id", emptyMap()); client.begin("id", emptyMap(), file, file); client.snapshot("id"); client.commit("id")
        assertEquals(listOf("ordinary:preflight", "ordinary:begin", "ordinary:snapshot", "ordinary:commit"), calls)
        assertFalse(client.signedActive)
    }
    @Test fun baselineFailureNeverPreparesTheSignedWriter() = runBlocking {
        val calls = mutableListOf<String>()
        val client = LenovoSignedSwitchClient(Fake(calls, "ordinary").apply { failSnapshot = true }, Signed(calls))
        client.begin("id", mapOf("lenovoSigning" to "CHAINED"), file, file)
        assertFalse(client.snapshot("id").ok)
        assertFalse(calls.contains("signed:snapshot"))
    }
    @Test fun restartFindsSignedPendingTaskWhenOrdinaryBackendChangesAfterReboot() {
        val calls = mutableListOf<String>()
        val signed = Signed(calls).apply { task = "signed-task"; current = state("signed-task", "REBOOT_REQUIRED") }
        val restarted = LenovoSignedSwitchClient(Fake(calls, "ordinary"), signed)
        assertEquals("signed-task", restarted.status("")?.switchId)
        assertEquals("REBOOT_REQUIRED", restarted.statusExact("signed-task")?.state)
        assertTrue(restarted.signedActive)
    }
    @Test fun rollbackAndVerificationRetireTheUnusedOrdinaryTransaction() = runBlocking {
        val calls = mutableListOf<String>()
        val signed = Signed(calls).apply { task = "id"; current = state("id", "ROLLED_BACK") }
        val client = LenovoSignedSwitchClient(Fake(calls, "ordinary").apply { current = state("id", "SNAPSHOT") }, signed)
        assertTrue(client.rollback("id").ok)
        assertEquals(listOf("signed:rollback", "ordinary:abort"), calls)
        calls.clear()
        signed.current = state("id", "VERIFIED")
        assertTrue(client.verify("id").ok)
        assertEquals(listOf("signed:verify"), calls)
    }
    @Test fun nativePrepareFailureCancelsBothUnwrittenPreparations() = runBlocking {
        val calls = mutableListOf<String>()
        val signed = Signed(calls).apply { failSnapshot = true }
        val client = LenovoSignedSwitchClient(Fake(calls, "ordinary"), signed)
        client.begin("id", mapOf("lenovoSigning" to "NON_CHAINED"), file, file)
        assertFalse(client.snapshot("id").ok)
        assertEquals(listOf("ordinary:begin", "signed:begin", "ordinary:snapshot", "signed:snapshot", "signed:abort", "ordinary:abort"), calls)
    }
    @Test fun failedBaselineRetirementDoesNotReportSnapshotSuccess() = runBlocking {
        val calls = mutableListOf<String>()
        val client = LenovoSignedSwitchClient(Fake(calls, "ordinary").apply { failAbort = true }, Signed(calls))
        client.begin("id", mapOf("lenovoSigning" to "CHAINED"), file, file)
        assertFalse(client.snapshot("id").ok)
        assertFalse(calls.contains("signed:commit"))
    }
}
