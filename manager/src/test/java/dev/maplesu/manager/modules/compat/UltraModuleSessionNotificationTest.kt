package dev.maplesu.manager.modules.compat

import dev.maplesu.manager.modules.webui.ModuleWebUiSessions
import dev.maplesu.manager.runtime.ultra.NativeReceipt
import dev.maplesu.manager.ultra.model.MapleSuModInstalledItem
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/** Real transactions with injected receipts/catalog only; no native host or installation runs. */
class UltraModuleSessionNotificationTest {
    private companion object {
        const val ID = "0123456789abcdef0123456789abcdef"
    }

    @Test fun confirmedInstallRetiresTheMatchingSessionOnce() {
        assertEquals(1, installation(committed = true))
    }

    @Test fun uncommittedInstallDoesNotRetireTheSession() {
        assertEquals(0, installation(committed = false))
    }

    @Test fun anotherOperationsInstallReceiptDoesNotRetireTheSession() {
        assertEquals(0, installation(committed = true, operation = "different_operation"))
    }

    @Test fun catalogFailureAfterHostCommitStillRetiresTheSession() {
        assertEquals(1, installation(committed = true, catalogFails = true))
    }

    @Test fun successfulUninstallRetiresTheMatchingSessionOnce() {
        assertEquals(1, uninstallation(ok = true))
    }

    @Test fun failedUninstallDoesNotRetireTheSession() {
        assertEquals(0, uninstallation(ok = false))
    }

    @Test fun anotherOperationsUninstallReceiptDoesNotRetireTheSession() {
        assertEquals(0, uninstallation(ok = true, operation = "different_operation"))
    }

    @Test fun failedReadbackAfterHostUninstallStillRetiresTheSession() {
        assertEquals(1, uninstallation(ok = true, listOkay = false))
    }

    private fun receipt(operation: String, ok: Boolean = true, data: JSONObject? = null) =
        NativeReceipt(1, "fixture", 1, operation, ok, if (ok) "OK" else "ERROR",
            if (ok) 0 else -1, null, data, "{}")

    private inner class Host(
        private val reply: NativeReceipt,
        private val listOkay: Boolean = true,
    ) : UltraModuleHost {
        override fun environmentState() = receipt("get_maplesu_environment_state")
        override fun parseModuleDescriptor(zipPath: String) = receipt(
            "parse_module_desc_from_zip_file",
            data = JSONObject().put("desc", JSONObject().put("id32", ID).put("ver", "1.0")),
        )
        override fun installModule(zipPath: String, devRunOnce: Boolean) = reply
        override fun uninstallModule(id32: String) = reply
        override fun modules() = emptyList<MapleSuModInstalledItem>()
        override fun moduleList() = receipt("get_all_modules_list", listOkay,
            JSONObject().put("modules", JSONArray()))
        override fun openModuleWebUI(id32: String) = error("Unexpected WebUI start")
    }

    private fun countNotifications(run: ((String) -> Unit) -> Unit): Int {
        var notifications = 0
        val session = "maplesu:$ID"
        val subscription = requireNotNull(ModuleWebUiSessions.subscribe(session,
            ModuleWebUiSessions.revision(session)) { notifications++ })
        try {
            run { ModuleWebUiSessions.committed("maplesu:$it") }
            return notifications
        } finally {
            subscription.close()
        }
    }

    private fun installation(
        committed: Boolean,
        operation: String = "install_module",
        catalogFails: Boolean = false,
    ) = countNotifications { onCommitted ->
        val transaction = UltraModuleInstallTransaction(
            host = Host(receipt(operation, data = JSONObject()
                .put("installCommitted", committed).put("cleanupComplete", !committed))),
            environmentProbe = { UltraModuleEnvironmentObservation(
                receipt("get_maplesu_environment_state"), "Running") },
            catalog = object : UltraModuleCatalogPort {
                override fun stage(source: File, confirmedArchiveSha256: String) = "stage-token"
                override fun stagedArchive(token: String) = File("fixture-archive.zip")
                override fun commit(token: String) {
                    if (catalogFails) error("Catalog failure after host commit")
                }
                override fun discard(token: String) {}
            },
            journal = { _, _, _ -> },
            evidence = { UltraModuleEvidenceRecordResult.Dropped("fixture") },
            facts = { UltraModuleDeviceFacts.of() },
            clockMillis = { 1_700_000_000_123L },
            buildDigest = { UltraModuleBuildDigest.of("9f".repeat(32)) },
            bootId = { "1f2e3d4c-5b6a-4978-8c9d-0e1f2a3b4c5d" },
            processPid = { 4242 },
            receiptData = { null },
            onCommitted = onCommitted,
        )
        transaction.install(UltraModuleInstallRequest(
            File("source.zip"), UltraModulePackageIdentity(ID, "1.0", "ed".repeat(32)),
            "1.0", false, UltraModuleAction.INSTALL), {}, {})
    }

    private fun uninstallation(
        ok: Boolean,
        operation: String = "uninstall_module",
        listOkay: Boolean = true,
    ) = countNotifications { onCommitted ->
        UltraModuleUninstallTransaction(Host(receipt(operation, ok), listOkay)) {}
            .uninstall(ID, "operation-id", onCommitted)
    }
}
