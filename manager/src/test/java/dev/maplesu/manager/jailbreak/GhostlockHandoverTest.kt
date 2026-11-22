package dev.maplesu.manager.jailbreak

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.IOException

class GhostlockHandoverTest {
    @Test fun providerExitBeforeDispatchEndsTheWaitWithItsOriginalFailure() {
        val error = assertThrows(IOException::class.java) {
            GhostlockHandover.awaitReceipt(request(JailbreakRequest.BACKEND_HOOK), 0,
                { null }, { false }, readWorker = { "" },
                sourceFailure = { "GHOSTLOCK_PROVIDER_EXIT_BEFORE_HANDOVER:64" })
        }
        assertEquals("GHOSTLOCK_PROVIDER_EXIT_BEFORE_HANDOVER:64", error.message)
    }

    @Test fun dispatchedProviderDoesNotReplaceTheWorkersRestoreResult() {
        val backend = JailbreakRequest.BACKEND_HOOK
        val snapshots = ArrayDeque(listOf("", "{", worker().toString()))
        GhostlockHandover.awaitReceipt(request(backend), 1000,
            { receipt(backend).toString() }, { false },
            readWorker = { snapshots.removeFirst() }, sourceFailure = { null })
        assertEquals(0, snapshots.size)
    }

    private fun request(backend: String) = JailbreakRequest(
        method = "ghostlock", attemptId = "attempt-a", bootId = "boot-a", rootBackend = backend)

    private fun receipt(backend: String): JSONObject = JSONObject().apply {
        put("schema", "maplesu.handover.v1")
        put("attempt", "attempt-a")
        put("bootId", "boot-a")
        put("target", GhostlockHandover.target(backend))
        put("verdict", "OK")
        put("carrier", JSONObject().apply {
            put("kind", if (backend == JailbreakRequest.BACKEND_HOOK) "l3-gate" else "ksu-lkm")
            put("gate", "ARMED")
            put("stage2", "LOADED")
            put("ksu", "LATE_LOAD_OK")
        })
        put("restore", JSONObject().put("enforcingFinal", 1).put("failures", 0))
    }

    private fun worker(code: Int = 0) = JSONObject().apply {
        put("schema", "maplesu.ghostlock.worker.v1")
        put("provider", "ghostlock")
        put("bootId", "boot-a")
        put("attempt", "attempt-a")
        put("exitCode", code)
    }

    @Test fun bothRequestedCarriersAcceptTheirOwnBoundReceipt() {
        for (backend in listOf(JailbreakRequest.BACKEND_HOOK, JailbreakRequest.BACKEND_KSU)) {
            assertNull(GhostlockHandover.refusal(receipt(backend).toString(), request(backend)))
        }
    }

    @Test fun anotherBootAttemptSchemaOrTargetDoesNotProveTheRequest() {
        for (key in listOf("schema", "bootId", "attempt", "target")) {
            val document = receipt(JailbreakRequest.BACKEND_HOOK).put(key, "different")
            assertEquals("GHOSTLOCK_HANDOVER_BINDING_MISMATCH",
                GhostlockHandover.refusal(document.toString(), request(JailbreakRequest.BACKEND_HOOK)))
        }
    }

    @Test fun failedOrDegradedLoadNeverCountsAsReady() {
        for (verdict in listOf("FAILED", "DEGRADED")) {
            val document = receipt(JailbreakRequest.BACKEND_HOOK).put("verdict", verdict)
            assertEquals("GHOSTLOCK_HANDOVER_NOT_READY",
                GhostlockHandover.refusal(document.toString(), request(JailbreakRequest.BACKEND_HOOK)))
            document.put("token", "MAPLESU_HANDOVER_LOAD_FAILED")
            assertEquals("MAPLESU_HANDOVER_LOAD_FAILED",
                GhostlockHandover.refusal(document.toString(), request(JailbreakRequest.BACKEND_HOOK)))
        }
    }

    @Test fun oppositeCarrierAndUnavailableGateNeverProveTheRequest() {
        val document = receipt(JailbreakRequest.BACKEND_HOOK)
        document.getJSONObject("carrier").put("gate", "UNAVAILABLE")
        assertEquals("GHOSTLOCK_HANDOVER_NOT_READY",
            GhostlockHandover.refusal(document.toString(), request(JailbreakRequest.BACKEND_HOOK)))
        val normal = receipt(JailbreakRequest.BACKEND_KSU)
        normal.getJSONObject("carrier").put("kind", "l3-gate")
        assertEquals("GHOSTLOCK_HANDOVER_NOT_READY",
            GhostlockHandover.refusal(normal.toString(), request(JailbreakRequest.BACKEND_KSU)))
    }

    @Test fun incompleteOrMalformedDocumentsAreRejected() {
        for (text in listOf("{", "{}", receipt(JailbreakRequest.BACKEND_HOOK).apply {
            remove("carrier")
        }.toString())) {
            assertEquals("GHOSTLOCK_HANDOVER_EVIDENCE_INVALID",
                GhostlockHandover.refusal(text, request(JailbreakRequest.BACKEND_HOOK)))
        }
    }

    @Test fun ultraRequiresSuccessfulLoadingAndFinalRestore() {
        val backend = JailbreakRequest.BACKEND_HOOK
        val document = receipt(backend)
        document.getJSONObject("carrier").put("stage2", "LOAD_FAILED")
        assertEquals("MAPLESU_HANDOVER_LOAD_FAILED",
            GhostlockHandover.refusal(document.toString(), request(backend)))
        document.getJSONObject("carrier").put("stage2", "LOADED")
        document.getJSONObject("restore").put("enforcingFinal", 0)
        assertEquals("MA_HOOK_RESTORE_FAILED",
            GhostlockHandover.refusal(document.toString(), request(backend)))
        document.getJSONObject("restore").put("enforcingFinal", 1).put("failures", 1)
        assertEquals("MA_HOOK_RESTORE_FAILED",
            GhostlockHandover.refusal(document.toString(), request(backend)))
    }

    @Test fun ultraWaitsThroughEmptyAndPartialReceiptWrites() {
        val backend = JailbreakRequest.BACKEND_HOOK
        val snapshots = ArrayDeque(listOf("", "{", receipt(backend).toString()))
        GhostlockHandover.awaitReceipt(request(backend), 1000, { snapshots.removeFirst() }, { false })
        assertEquals(0, snapshots.size)
    }

    @Test fun completeFailureIsReportedWithoutWaitingForAnyLease() {
        val backend = JailbreakRequest.BACKEND_HOOK
        val text = receipt(backend).put("verdict", "FAILED")
            .put("token", "MAPLESU_HANDOVER_LOAD_FAILED").toString()
        val error = assertThrows(IOException::class.java) {
            GhostlockHandover.awaitReceipt(request(backend), 0, { text }, { false })
        }
        assertEquals("MAPLESU_HANDOVER_LOAD_FAILED", error.message)
    }

    @Test fun failedBackendWaitsForRestoreTailBeforeReportingItsOriginalFailure() {
        val backend = JailbreakRequest.BACKEND_HOOK
        val text = receipt(backend).put("verdict", "FAILED")
            .put("token", "MA_HOOK_NOT_PRIVILEGED").toString()
        val snapshots = ArrayDeque(listOf("", "{", worker(65).toString()))
        val error = assertThrows(IOException::class.java) {
            GhostlockHandover.awaitReceipt(request(backend), 1000, { text }, { false },
                readWorker = { snapshots.removeFirst() })
        }
        assertEquals(0, snapshots.size)
        assertEquals("MA_HOOK_NOT_PRIVILEGED", error.message)
    }

    @Test fun aFailedReceiptStillHonorsDeadlineWhileItsWorkerHasNoTerminalRecord() {
        val backend = JailbreakRequest.BACKEND_HOOK
        val text = receipt(backend).put("verdict", "FAILED")
            .put("token", "MA_HOOK_NOT_PRIVILEGED").toString()
        val error = assertThrows(IOException::class.java) {
            GhostlockHandover.awaitReceipt(request(backend), 0, { text }, { false },
                readWorker = { "" })
        }
        assertEquals("GHOSTLOCK_HANDOVER_TIMEOUT", error.message)
    }

    @Test fun receiptWaitHonorsCancellationAndDeadline() {
        val backend = JailbreakRequest.BACKEND_HOOK
        val cancelled = assertThrows(IOException::class.java) {
            GhostlockHandover.awaitReceipt(request(backend), 1000,
                { error("cancelled attempts must not read a receipt") }, { true })
        }
        assertEquals("JAILBREAK_CANCELLED", cancelled.message)
        val timeout = assertThrows(IOException::class.java) {
            GhostlockHandover.awaitReceipt(request(backend), 0, { null }, { false })
        }
        assertEquals("GHOSTLOCK_HANDOVER_TIMEOUT", timeout.message)
    }
    @Test fun workerFailureBeforeBackendReceiptStopsTheWaitImmediately() {
        val backend = JailbreakRequest.BACKEND_HOOK
        val error = assertThrows(IOException::class.java) {
            GhostlockHandover.awaitReceipt(request(backend), 0, { null }, { false },
                readWorker = { worker(73).toString() })
        }
        assertEquals("GHOSTLOCK_WORKER_FAILED:73", error.message)
    }

    @Test fun workerSuccessWithoutBackendProofNeverPublishesReadiness() {
        val backend = JailbreakRequest.BACKEND_HOOK
        val error = assertThrows(IOException::class.java) {
            GhostlockHandover.awaitReceipt(request(backend), 0, { null }, { false },
                readWorker = { worker().toString() })
        }
        assertEquals("GHOSTLOCK_HANDOVER_EVIDENCE_MISSING", error.message)
    }

    @Test fun backendProofWaitsForTheCurrentSourcesCompleteTerminalWrite() {
        val backend = JailbreakRequest.BACKEND_HOOK
        val snapshots = ArrayDeque(listOf("", "{", worker().toString()))
        val messages = mutableListOf<String>()
        GhostlockHandover.awaitReceipt(request(backend), 1000,
            { receipt(backend).toString() }, { false },
            readWorker = { snapshots.removeFirst() }, progress = messages::add)
        assertEquals(0, snapshots.size)
        assertEquals(2, messages.size)
    }

    @Test fun anotherWorkerOrMalformedTerminalRecordCannotEndTheWaitSuccessfully() {
        val backend = JailbreakRequest.BACKEND_HOOK
        for (key in listOf("schema", "provider", "bootId", "attempt")) {
            assertEquals("GHOSTLOCK_WORKER_BINDING_MISMATCH",
                GhostlockHandover.workerRefusal(worker().put(key, "other").toString(), request(backend)))
        }
        for (text in listOf("{}", worker().apply { remove("exitCode") }.toString())) {
            assertEquals("GHOSTLOCK_WORKER_EVIDENCE_INVALID",
                GhostlockHandover.workerRefusal(text, request(backend)))
        }
        assertNull(GhostlockHandover.workerRefusal(worker().toString(), request(backend)))
    }

    @Test fun aWorkerErrorAfterAnArmedReceiptStillFails() {
        val backend = JailbreakRequest.BACKEND_HOOK
        val error = assertThrows(IOException::class.java) {
            GhostlockHandover.awaitReceipt(request(backend), 0,
                { receipt(backend).toString() }, { false }, readWorker = { worker(76).toString() })
        }
        assertEquals("GHOSTLOCK_WORKER_FAILED:76", error.message)
    }

    @Test fun anInterruptedWaitPreservesCancellationWithoutReadingEvidence() {
        Thread.currentThread().interrupt()
        try {
            val error = assertThrows(IOException::class.java) {
                GhostlockHandover.awaitReceipt(request(JailbreakRequest.BACKEND_HOOK), 1000,
                    { error("interrupted wait must not read evidence") }, { false })
            }
            assertEquals("JAILBREAK_CANCELLED", error.message)
        } finally { Thread.interrupted() }
    }

}
