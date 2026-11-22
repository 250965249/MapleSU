package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class ServiceResumeModeSwitchClientTest {
    private val ultraId = "11111111-1111-1111-1111-111111111111"
    private val serviceId = "22222222-2222-2222-2222-222222222222"
    private val file = File("unused.img")

    private fun state(id: String, state: String) = ClientStatus(id, state, "", "", "KSU", "LITE",
        "", "", "", state == "REBOOT_REQUIRED", state == "VERIFIED", true, false, 0, emptyList())

    private class Fake(private val name: String, val calls: MutableList<String>) : ModeSwitchClient {
        val records = linkedMapOf<String, ClientStatus>()
        var readFailure: Throwable? = null
        var beginFailure: Throwable? = null
        var mutationFailure: ClientResult? = null
        private fun result(id: String, action: String): ClientResult {
            calls += "$name:$action:$id"
            return mutationFailure ?: ClientResult(true, status = records[id])
        }
        override suspend fun preflight(switchId: String, planFields: Map<String, String>) = result(switchId, "preflight")
        override suspend fun begin(switchId: String, planFields: Map<String, String>, superuserJson: File,
                                   settingsMirrorJson: File): ClientResult {
            beginFailure?.let { throw it }
            return result(switchId, "begin")
        }
        override suspend fun snapshot(switchId: String) = result(switchId, "snapshot")
        override suspend fun exportImage(switchId: String, kind: String, partition: String, destination: File) =
            result(switchId, "export").ok
        override suspend fun submitCandidate(switchId: String, partition: String, candidate: File,
                                             candidateSha256: String) = result(switchId, "submit")
        override suspend fun commit(switchId: String) = result(switchId, "commit")
        override suspend fun rollback(switchId: String) = result(switchId, "rollback")
        override suspend fun abort(switchId: String) = result(switchId, "abort")
        override suspend fun verify(switchId: String) = result(switchId, "verify")
        override suspend fun markRebootRequested(switchId: String) = result(switchId, "reboot").ok
        override suspend fun exportLog(switchId: String, destination: File) =
            destination.takeIf { result(switchId, "log").ok }
        override fun status(switchId: String) = statusExact(switchId)
        override fun statusExact(switchId: String): ClientStatus? {
            calls += "$name:read:$switchId"
            readFailure?.let { throw it }
            return if (switchId.isEmpty()) records.values.lastOrNull() else records[switchId]
        }
    }

    @Test fun restartFindsServicePendingAlongsideCompletedUltraAndKeepsAllTaskActionsOnService() = runBlocking {
        val calls = mutableListOf<String>()
        val ultra = Fake("ultra", calls).apply { records[ultraId] = state(ultraId, "VERIFIED") }
        val service = Fake("service", calls).apply { records[serviceId] = state(serviceId, "REBOOT_REQUIRED") }
        val client = ServiceResumeModeSwitchClient(ultra, service) { true }
        assertEquals(serviceId, client.status("")!!.switchId)
        calls.clear()
        client.snapshot(serviceId)
        client.exportImage(serviceId, "PRE", "boot", file)
        client.submitCandidate(serviceId, "boot", file, "hash")
        client.commit(serviceId)
        client.verify(serviceId)
        client.rollback(serviceId)
        client.abort(serviceId)
        client.markRebootRequested(serviceId)
        client.exportLog(serviceId, file)
        assertEquals(listOf("snapshot", "export", "submit", "commit", "verify", "rollback", "abort", "reboot", "log")
            .map { "service:$it:$serviceId" }, calls)
        val restarted = ServiceResumeModeSwitchClient(ultra, service) { true }
        assertEquals(serviceId, restarted.statusExact(serviceId)!!.switchId)
        assertTrue(restarted.verify(serviceId).ok)
    }

    @Test fun newPreflightAndAcceptedBeginStayOnUltraWithoutLookingForHistoricalRecords() = runBlocking {
        val calls = mutableListOf<String>()
        val ultra = Fake("ultra", calls)
        val service = Fake("service", calls).apply { records[ultraId] = state(ultraId, "REBOOT_REQUIRED") }
        val client = ServiceResumeModeSwitchClient(ultra, service) { error("history must not gate a new begin") }
        assertTrue(client.preflight(ultraId, emptyMap()).ok)
        assertTrue(client.begin(ultraId, emptyMap(), file, file).ok)
        assertTrue(client.snapshot(ultraId).ok)
        assertEquals(listOf("ultra:preflight:$ultraId", "ultra:begin:$ultraId", "ultra:snapshot:$ultraId"), calls)
    }

    @Test fun failedOrThrownUltraBeginRechecksPersistentOwnershipAndStillRecoversTheExistingServiceTask() = runBlocking {
        for (throws in listOf(false, true)) {
            val calls = mutableListOf<String>()
            val ultra = Fake("ultra", calls).apply {
                if (throws) beginFailure = IllegalStateException("original-begin-error")
                else mutationFailure = ClientResult(false, "ULTRA_WRITE_UNCERTAIN")
            }
            val service = Fake("service", calls).apply { records[serviceId] = state(serviceId, "REBOOT_REQUIRED") }
            val client = ServiceResumeModeSwitchClient(ultra, service) { true }
            assertEquals(serviceId, client.statusExact(serviceId)!!.switchId)
            runCatching { client.begin(serviceId, emptyMap(), file, file) }
            calls.clear()
            assertTrue(client.rollback(serviceId).ok)
            assertTrue(calls.contains("ultra:read:$serviceId"))
            assertTrue(calls.contains("service:rollback:$serviceId"))
            assertFalse(calls.contains("ultra:rollback:$serviceId"))
        }
    }

    @Test fun uncertainBeginWithARealUltraRecordAndAnExistingServiceRecordReportsConflictBeforeRecovery() = runBlocking {
        val calls = mutableListOf<String>()
        val ultra = Fake("ultra", calls).apply { mutationFailure = ClientResult(false, "ULTRA_WRITE_UNCERTAIN") }
        val service = Fake("service", calls).apply { records[serviceId] = state(serviceId, "REBOOT_REQUIRED") }
        val client = ServiceResumeModeSwitchClient(ultra, service) { true }
        client.statusExact(serviceId)
        assertFalse(client.begin(serviceId, emptyMap(), file, file).ok)
        ultra.records[serviceId] = state(serviceId, "BEGIN")
        calls.clear()
        val failure = runCatching { client.verify(serviceId) }.exceptionOrNull()
        assertTrue(failure?.message.orEmpty().startsWith(ModeSwitchCodes.PLAN_CONFLICT))
        assertTrue(calls.all { ":read:" in it })
    }

    @Test fun oldStoragePresenceWithoutAnAuthorityDoesNotSelectService() {
        val calls = mutableListOf<String>()
        val ultra = Fake("ultra", calls).apply { records[ultraId] = state(ultraId, "VERIFIED") }
        val service = Fake("service", calls)
        val client = ServiceResumeModeSwitchClient(ultra, service) { true }
        assertEquals(ultraId, client.status("")!!.switchId)
        assertNull(client.statusExact(serviceId))
        assertFalse(calls.any { it.startsWith("service:") && !it.startsWith("service:read:") })
    }

    @Test fun noHistoricalStorageUsesUltraAndNeverReadsService() {
        val calls = mutableListOf<String>()
        val ultra = Fake("ultra", calls).apply { records[ultraId] = state(ultraId, "REBOOT_REQUIRED") }
        val client = ServiceResumeModeSwitchClient(ultra, Fake("service", calls)) { false }
        assertEquals(ultraId, client.status("")!!.switchId)
        assertFalse(calls.any { it.startsWith("service:") })
    }

    @Test fun pendingUltraWinsOverCompletedServiceAndTwoCompletedHistoriesDefaultToPro() {
        val calls = mutableListOf<String>()
        val ultra = Fake("ultra", calls).apply { records[ultraId] = state(ultraId, "REBOOT_REQUIRED") }
        val service = Fake("service", calls).apply { records[serviceId] = state(serviceId, "VERIFIED") }
        val client = ServiceResumeModeSwitchClient(ultra, service) { true }
        assertEquals(ultraId, client.status("")!!.switchId)
        ultra.records[ultraId] = state(ultraId, "VERIFIED")
        assertEquals(ultraId, client.status("")!!.switchId)
        assertEquals(serviceId, client.statusExact(serviceId)!!.switchId)
    }

    @Test fun twoPendingTasksOrTheSameIdInBothFormatsReportConflictWithoutMutation() {
        for (sameId in listOf(false, true)) {
            val calls = mutableListOf<String>()
            val otherId = if (sameId) ultraId else serviceId
            val ultra = Fake("ultra", calls).apply { records[ultraId] = state(ultraId, "REBOOT_REQUIRED") }
            val service = Fake("service", calls).apply { records[otherId] = state(otherId, "REBOOT_REQUIRED") }
            val client = ServiceResumeModeSwitchClient(ultra, service) { true }
            val failure = runCatching { if (sameId) client.statusExact(ultraId) else client.status("") }.exceptionOrNull()
            assertTrue(failure?.message.orEmpty().startsWith(ModeSwitchCodes.PLAN_CONFLICT))
            assertTrue(calls.all { ":read:" in it })
        }
    }

    @Test fun observationAndAuthorityReadFailuresPropagateWithoutChoosingOrReplayingAnotherExecutor() = runBlocking {
        for (source in listOf("root", "ultra", "service")) {
            val calls = mutableListOf<String>()
            val failure = IllegalStateException("$source-original-read-error")
            val ultra = Fake("ultra", calls).apply { if (source == "ultra") readFailure = failure }
            val service = Fake("service", calls).apply { if (source == "service") readFailure = failure }
            val client = ServiceResumeModeSwitchClient(ultra, service) {
                if (source == "root") throw failure
                true
            }
            assertSame(failure, runCatching { client.statusExact(serviceId) }.exceptionOrNull())
            assertTrue(calls.all { ":read:" in it })
        }
    }

    @Test fun unknownExactIdNeverUsesAnotherServicesValidHeadOrReplaysAMutation() = runBlocking {
        val calls = mutableListOf<String>()
        val ultra = Fake("ultra", calls)
        val service = Fake("service", calls).apply { records[serviceId] = state(serviceId, "REBOOT_REQUIRED") }
        val client = ServiceResumeModeSwitchClient(ultra, service) { true }
        assertNull(client.statusExact(ultraId))
        assertFalse(client.isServiceTask(ultraId))
        val failure = runCatching { client.rollback(ultraId) }.exceptionOrNull()
        assertTrue(failure?.message.orEmpty().startsWith(ModeSwitchCodes.PLAN_INVALID))
        assertTrue(calls.all { ":read:" in it })
    }

    @Test fun legacyMutationFailureRemainsOnItsOriginalExecutor() = runBlocking {
        val calls = mutableListOf<String>()
        val failure = ClientResult(false, "LEGACY_ROLLBACK_FAILED", "original detail")
        val service = Fake("service", calls).apply {
            records[serviceId] = state(serviceId, "RECOVERY_REQUIRED")
            mutationFailure = failure
        }
        val client = ServiceResumeModeSwitchClient(Fake("ultra", calls), service) { true }
        assertSame(failure, client.rollback(serviceId))
        assertFalse(calls.contains("ultra:rollback:$serviceId"))
    }
}
