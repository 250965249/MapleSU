package dev.maplesu.manager.modules.compat

import dev.maplesu.manager.runtime.ultra.NativeReceipt
import dev.maplesu.manager.runtime.ultra.UltraOutcome
import dev.maplesu.manager.runtime.ultra.UltraPhase
import dev.maplesu.manager.runtime.ultra.UltraReceipt
import dev.maplesu.manager.ultra.model.MapleSuModInstalledItem
import java.io.File
import java.io.IOException
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class UltraModuleJournalAdmissionTest {
    private val id = "journal_fixture"
    private fun receipt(operation: String, data: JSONObject? = null) = NativeReceipt(
        1, "fixture", 1, operation, true, "OK", 0, null, data, "{}")

    private inner class Host : UltraModuleHost {
        var installs = 0
        var writes = 0
        var reads = 0
        var enabled = true
        override fun environmentState() = receipt("get_maplesu_environment_state")
        override fun parseModuleDescriptor(zipPath: String) = receipt("parse_module_desc_from_zip_file",
            JSONObject().put("desc", JSONObject().put("id32", id).put("ver", "1")))
        override fun installModule(zipPath: String, devRunOnce: Boolean): NativeReceipt {
            installs++
            return receipt(if (devRunOnce) "install_module_dev_run_once" else "install_module",
                JSONObject().put("installCommitted", true))
        }
        override fun moduleControl(id32: String): NativeReceipt {
            reads++
            return receipt("get_module_control", JSONObject().put("abiVersion", 1).put("id32", id)
                .put("supportsEnableToggle", true).put("enabled", enabled).put("needsReboot", false)
                .put("runtimeState", "NotRunning"))
        }
        override fun setModuleEnabled(id32: String, enabled: Boolean): NativeReceipt {
            writes++
            this.enabled = enabled
            return receipt("set_module_enabled")
        }
        override fun uninstallModule(id32: String): NativeReceipt = error("Unexpected uninstall")
        override fun modules(): List<MapleSuModInstalledItem> = error("Unexpected list")
        override fun openModuleWebUI(id32: String): NativeReceipt = error("Unexpected WebUI")
    }

    private fun install(devRunOnce: Boolean, preparedFails: Boolean, cleanupFails: Boolean = false): Triple<UltraReceipt, Host, Int> {
        val host = Host()
        var discarded = 0
        val transaction = UltraModuleInstallTransaction(host,
            environmentProbe = { UltraModuleEnvironmentObservation(host.environmentState(), "Running") },
            catalog = object : UltraModuleCatalogPort {
                override fun stage(source: File, confirmedArchiveSha256: String) = "token"
                override fun stagedArchive(token: String) = File("fixture.zip")
                override fun commit(token: String) { assertEquals(1, host.installs) }
                override fun discard(token: String) {
                    discarded++
                    if (cleanupFails) throw IOException("CLEANUP_FIRST_ERROR")
                }
            },
            journal = object : UltraModuleJournal {
                override fun append(operationId: String, receipt: UltraReceipt, token: String?) =
                    error("Admission must use the durable result")
                override fun appendDurably(operationId: String, receipt: UltraReceipt, token: String?): Result<Unit> =
                    if ((receipt.phase == UltraPhase.PREPARED) == preparedFails)
                        Result.failure(IOException("JOURNAL_FIRST_ERROR")) else Result.success(Unit)
            },
            evidence = { UltraModuleEvidenceRecordResult.Dropped("fixture") },
            facts = { UltraModuleDeviceFacts.of() }, clockMillis = { 1L },
            buildDigest = { UltraModuleBuildDigest.of("9f".repeat(32)) },
            bootId = { "1f2e3d4c-5b6a-4978-8c9d-0e1f2a3b4c5d" }, processPid = { 42 },
            receiptData = { null })
        val request = UltraModuleInstallRequest(File("source.zip"),
            UltraModulePackageIdentity(id, "1", "ed".repeat(32)), "1", devRunOnce, UltraModuleAction.INSTALL)
        return Triple(transaction.install(request, {}, {}), host, discarded)
    }

    @Test fun aFailedPreparedRecordNeverSubmitsEitherInstallOperation() {
        for (dev in listOf(false, true)) {
            val (result, host, discarded) = install(dev, preparedFails = true)
            assertEquals(0, host.installs)
            assertEquals(1, discarded)
            assertEquals(UltraPhase.PREPARED, result.phase)
            assertEquals(UltraOutcome.FAILED, result.outcome)
            assertEquals("MAPLESU_OPERATION_LOG_WRITE_FAILED", result.sdkError)
            assertEquals("JOURNAL_FIRST_ERROR", result.unknowns["operationLog"])
            assertEquals("staged_discarded", result.cleanupOutcome)
        }
    }

    @Test fun cleanupFailureKeepsTheOriginalJournalErrorAndTheUnsubmittedStageUncertain() {
        val (result, host, discarded) = install(false, preparedFails = true, cleanupFails = true)
        assertEquals(0, host.installs)
        assertEquals(1, discarded)
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, result.outcome)
        assertEquals("JOURNAL_FIRST_ERROR", result.unknowns["operationLog"])
        assertEquals("CLEANUP_FIRST_ERROR", result.unknowns["cleanup"])
        assertEquals("staged_discard_failed", result.cleanupOutcome)
    }

    @Test fun laterJournalFailurePreservesTheActualHostCommitAndDoesNotResubmit() {
        val (result, host, discarded) = install(false, preparedFails = false)
        assertEquals(1, host.installs)
        assertEquals(0, discarded)
        assertEquals(UltraOutcome.COMPLETED, result.outcome)
        assertEquals(UltraPhase.CATALOG_COMMITTED, result.phase)
        assertEquals("JOURNAL_FIRST_ERROR", result.unknowns["operationLog"])
    }

    @Test fun togglePreparationFailureStopsBeforeMutationWithoutAnExtraRead() {
        val host = Host()
        val result = UltraModuleToggleTransaction(host, beforeMutation = { throw IOException("JOURNAL_FIRST_ERROR") })
            .setEnabled(id, false)
        assertEquals(1, host.reads)
        assertEquals(0, host.writes)
        assertEquals(UltraOutcome.FAILED, result.outcome)
        assertEquals(UltraPhase.PREPARED, result.phase)
        assertEquals("JOURNAL_FIRST_ERROR", result.unknowns["operationLog"])
    }

    @Test fun anUnchangedToggleNeedsNoMutationRecord() {
        val host = Host()
        val result = UltraModuleToggleTransaction(host, beforeMutation = { error("No mutation") })
            .setEnabled(id, true)
        assertEquals(UltraOutcome.COMPLETED, result.outcome)
        assertEquals(0, host.writes)
        assertEquals(1, host.reads)
    }

    @Test fun togglePreparationCancellationRemainsCancellation() {
        val host = Host()
        val cancelled = java.util.concurrent.CancellationException("CANCELLED_BEFORE_MUTATION")
        val thrown = assertThrows(java.util.concurrent.CancellationException::class.java) {
            UltraModuleToggleTransaction(host, beforeMutation = { throw cancelled }).setEnabled(id, false)
        }
        assertSame(cancelled, thrown)
        assertEquals(0, host.writes)
        assertEquals(1, host.reads)
    }
}
