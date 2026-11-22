package dev.maplesu.manager.modules.compat

import dev.maplesu.manager.ultra.model.MapleSuModInstalledItem
import dev.maplesu.manager.runtime.ultra.NativeReceipt
import dev.maplesu.manager.runtime.ultra.UltraOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UltraModuleUninstallTransactionTest {
    private fun receipt(operation: String, data: String = "{}") = NativeReceipt.parse(
        """{"schemaVersion":1,"backend":"maplesu_ultra","operation":"$operation","ok":true,"sdkError":"OK","sdkErrorCode":0,"data":$data}""",
    )!!

    private inner class Host(private val state: String = "Running") : UltraModuleHost {
        var calls = 0
        var reads = 0
        var removed = false
        var uninstall = receipt("uninstall_module")
        var list = receipt("get_all_modules_list", """{"modules":[]}""")
        override fun uninstallModule(id32: String): NativeReceipt { calls++; return uninstall }
        override fun moduleList(): NativeReceipt { reads++; return list }
        override fun modules(): List<MapleSuModInstalledItem> = error("Do not flatten read failures")
        override fun environmentState(): NativeReceipt = receipt("get_maplesu_environment_state", """{"state":"$state"}""")
        override fun parseModuleDescriptor(zipPath: String): NativeReceipt = error("unused")
        override fun installModule(zipPath: String, devRunOnce: Boolean): NativeReceipt = error("unused")
        override fun openModuleWebUI(id32: String): NativeReceipt = error("unused")
        fun run() = UltraModuleUninstallTransaction(this) { removed = true }.uninstall("id32")
    }

    @Test
    fun protectedEnvironmentStillUninstallsThroughSdkAndChecksReadback() {
        val host = Host("Fault")
        assertEquals("Fault", host.environmentState().string("state"))
        assertEquals(UltraOutcome.COMPLETED, host.run().outcome)
        assertTrue(host.removed)
        assertEquals(1, host.calls)
        assertEquals(1, host.reads)
    }

    @Test
    fun confirmedAbsenceRemovesCatalogAfterExactlyOneMutationAndOneRead() {
        val host = Host()
        assertEquals(UltraOutcome.COMPLETED, host.run().outcome)
        assertTrue(host.removed)
        assertEquals(1, host.calls)
        assertEquals(1, host.reads)
    }

    @Test
    fun unrelatedSuccessfulMutationDoesNotConfirmAnUninstall() {
        val host = Host()
        host.uninstall = receipt("install_module")
        val result = host.run()
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, result.outcome)
        assertEquals(host.uninstall.raw, result.raw)
        assertEquals(1, host.calls)
        assertEquals(0, host.reads)
        assertFalse(host.removed)
    }

    @Test
    fun anEmptyListFromAnUnrelatedOperationDoesNotProveAbsence() {
        val host = Host()
        host.list = receipt("get_module_control", """{"modules":[]}""")
        val result = host.run()
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, result.outcome)
        assertEquals("module_list_unverified", result.unknowns["postState"])
        assertEquals(1, host.calls)
        assertEquals(1, host.reads)
        assertFalse(host.removed)
    }

    @Test
    fun pendingRebootIsTerminalAndKeepsCatalog() {
        val host = Host()
        host.list = receipt("get_all_modules_list",
            """{"modules":[{"desc":{"id32":"id32"},"state":"RemovedPendingReboot"}]}""")
        val result = host.run()
        assertEquals(UltraOutcome.PENDING_REBOOT, result.outcome)
        assertTrue(result.needsReboot)
        assertFalse(host.removed)
    }

    @Test
    fun failedReadbackKeepsCatalogAndNeverReportsDeleted() {
        val host = Host()
        host.list = NativeReceipt.bridgeFailure("get_all_modules_list", "READ_FAILED", "test")
        val result = host.run()
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, result.outcome)
        assertEquals("READ_FAILED", result.sdkError)
        assertFalse(host.removed)
    }

    @Test
    fun missingOrMalformedListIsNotConfirmedAbsence() {
        listOf("{}", """{"modules":[{}]}""",
            """{"modules":[{"desc":{"id32":"%ZZ"}}]}""").forEach { data ->
            val host = Host()
            host.list = receipt("get_all_modules_list", data)
            assertEquals(UltraOutcome.NEEDS_RECONCILIATION, host.run().outcome)
            assertFalse(host.removed)
        }
    }

    @Test
    fun stillRunningIsNotRemoved() {
        val host = Host()
        host.list = receipt("get_all_modules_list",
            """{"modules":[{"desc":{"id32":"id32"},"state":"Running"}]}""")
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, host.run().outcome)
        assertFalse(host.removed)
    }

    @Test
    fun duplicateTargetRowsAreNotAConfirmedState() {
        val host = Host()
        host.list = receipt("get_all_modules_list", """{"modules":[
            {"desc":{"id32":"id32"},"state":"Running"},
            {"desc":{"id32":"id32"},"state":"RemovedPendingReboot"}]}""")
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, host.run().outcome)
        assertFalse(host.removed)
    }

    @Test
    fun interruptedNativeCallIsNeverReplayedOrReadAsSuccess() {
        val host = Host()
        host.uninstall = NativeReceipt.parse("""{"backend":"maplesu_ultra","ok":false,
            "sdkError":"MAPLESU_MODULE_UNINSTALL_INTERRUPTED","data":{"reconciliationRequired":true}}""")!!
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, host.run().outcome)
        assertEquals(1, host.calls)
        assertEquals(0, host.reads)
        assertFalse(host.removed)
    }

    @Test
    fun nativeFailureKeepsCatalogWithoutReadback() {
        val host = Host()
        host.uninstall = NativeReceipt.bridgeFailure("uninstall_module", "FAILED", "test")
        assertEquals(UltraOutcome.FAILED, host.run().outcome)
        assertEquals(0, host.reads)
        assertFalse(host.removed)
    }

    @Test
    fun catalogFailureDoesNotClaimCleanupSucceeded() {
        val result = UltraModuleUninstallTransaction(Host()) { error("disk error") }.uninstall("id32")
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, result.outcome)
        assertEquals("catalog_record_removal_failed", result.cleanupOutcome)
    }

    @Test
    fun completedUninstallStillChecksAbsenceAndKeepsOriginalError() {
        val host = Host()
        val completed = NativeReceipt.parse("""{"backend":"maplesu_ultra","operation":"uninstall_module",
            "ok":false,"sdkError":"SDK_CREDENTIAL_SCOPE_CHANGED","sdkErrorCode":-1001,
            "operationCompleted":true}""")!!
        host.uninstall = completed
        val result = host.run()
        assertEquals(UltraOutcome.COMPLETED, result.outcome)
        assertEquals(completed.raw, result.raw)
        assertTrue(host.removed)
        assertEquals(1, host.calls)
        assertEquals(1, host.reads)
    }

    @Test
    fun completedUninstallWithUnreadableListKeepsCatalogAndBothErrors() {
        val host = Host()
        val completed = NativeReceipt.parse("""{"backend":"maplesu_ultra","operation":"uninstall_module",
            "ok":false,"sdkError":"SDK_CREDENTIAL_SCOPE_CHANGED","sdkErrorCode":-1001,
            "operationCompleted":true}""")!!
        host.uninstall = completed
        host.list = NativeReceipt.bridgeFailure("get_all_modules_list", "READ_FAILED", "post-state")
        val result = host.run()
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, result.outcome)
        assertEquals(completed.raw, result.raw)
        assertEquals("post-state", result.unknowns["moduleList"])
        assertFalse(host.removed)
        host.uninstall = completed.copy(operation = "install_module")
        host.reads = 0
        assertEquals(UltraOutcome.FAILED, host.run().outcome)
        assertEquals(0, host.reads)
    }
}
