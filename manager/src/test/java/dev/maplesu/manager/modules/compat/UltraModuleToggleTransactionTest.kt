package dev.maplesu.manager.modules.compat

import dev.maplesu.manager.ultra.model.MapleSuModInstalledItem
import dev.maplesu.manager.runtime.ultra.NativeReceipt
import dev.maplesu.manager.runtime.ultra.UltraOutcome
import org.junit.Assert.*
import org.junit.Test
import org.json.JSONObject

class UltraModuleToggleTransactionTest {
    private val id = "touch_boost_oplus_1021_000000000"
    private fun receipt(enabled: Boolean, reboot: Boolean = true, supported: Boolean = true,
                        runtime: String = "Running", moduleId: String = id) = NativeReceipt.parse(
        """{"schemaVersion":1,"backend":"maplesu_ultra","operation":"get_module_control","ok":true,"sdkError":"OK","sdkErrorCode":0,
            "data":{"abiVersion":1,"id32":${JSONObject.quote(moduleId)},"enabled":$enabled,"needsReboot":$reboot,
            "supportsEnableToggle":$supported,"runtimeState":"$runtime"}}""",
    )!!
    private inner class Host : UltraModuleHost {
        var state = true
        var writes = 0
        var reads = 0
        var read: (() -> NativeReceipt)? = null
        var change: (() -> NativeReceipt)? = null
        override fun moduleControl(id32: String): NativeReceipt { reads++; return read?.invoke() ?: receipt(state, moduleId=id32) }
        override fun setModuleEnabled(id32: String, enabled: Boolean): NativeReceipt {
            writes++; return change?.invoke() ?: run { state = enabled; receipt(state, moduleId=id32) }
        }
        override fun environmentState(): NativeReceipt = error("unused")
        override fun parseModuleDescriptor(zipPath: String): NativeReceipt = error("never execute descriptor callbacks")
        override fun installModule(zipPath: String, devRunOnce: Boolean): NativeReceipt = error("never reinstall")
        override fun uninstallModule(id32: String): NativeReceipt = error("never uninstall")
        override fun modules(): List<MapleSuModInstalledItem> = error("never flatten SDK receipts")
        override fun openModuleWebUI(id32: String): NativeReceipt = error("never execute module entry")
        fun run(enabled: Boolean = false) = UltraModuleToggleTransaction(this).setEnabled(id, enabled)
    }

    @Test fun disablePersistsAndReadsDesiredStateWithoutClaimingImmediateStop() {
        val h = Host();val r = h.run()
        assertEquals(UltraOutcome.PENDING_REBOOT,r.outcome);assertTrue(r.needsReboot)
        assertFalse(r.data!!.getBoolean("enabled"));assertEquals("Running",r.data.getString("runtimeState"))
        assertEquals(1,h.writes);assertEquals(2,h.reads)
    }
    @Test fun reenableNotRunningWaitsForBootLifecycle() {
        val h = Host();h.state = false;h.read = { receipt(h.state, runtime="NotRunning") }
        assertEquals(UltraOutcome.PENDING_REBOOT,h.run(true).outcome);assertEquals(1,h.writes)
    }
    @Test fun repeatedRequestsAreIdempotent() {
        val h = Host();h.state = false;assertEquals(UltraOutcome.PENDING_REBOOT,h.run().outcome)
        assertEquals(0,h.writes);assertEquals(1,h.reads)
    }
    @Test fun disabledAfterBootCanBeCompleted() {
        val h = Host();h.read = { receipt(false, reboot=false, runtime="NotRunning") }
        val r = h.run();assertEquals(UltraOutcome.COMPLETED,r.outcome);assertFalse(r.needsReboot)
    }
    @Test fun oldHostDoesNotReceiveMutation() {
        val h = Host();h.read = { NativeReceipt.bridgeFailure("get_module_control","MISSING","old SDK") }
        assertEquals(UltraOutcome.CONDITION_UNMET,h.run().outcome);assertEquals(0,h.writes)
    }
    @Test fun oldInstalledHelperDisablesCapability() {
        val h = Host();h.read = { receipt(true,supported=false) }
        assertEquals(UltraOutcome.CONDITION_UNMET,h.run().outcome);assertEquals(0,h.writes)
    }
    @Test fun aReturnCodeAloneDoesNotConfirmDesiredState() {
        val h = Host();h.change = { receipt(false) }
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION,h.run().outcome);assertEquals(1,h.writes)
    }
    @Test fun concurrentUninstallIsReconciledWithoutReplay() {
        val h = Host();h.read = { if(h.writes==0) receipt(true) else NativeReceipt.bridgeFailure("get_module_control","NOT_FOUND","removed") }
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION,h.run().outcome);assertEquals(1,h.writes)
    }
    @Test fun interruptedReceiptStaysUncertainEvenIfDesiredStateCommitted() {
        val h = Host();h.change = { h.state=false;NativeReceipt.bridgeFailure("set_module_enabled","MAPLESU_MODULE_CONTROL_IO","interrupted") }
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION,h.run().outcome);assertEquals(1,h.writes)
    }
    @Test fun modeChangeBeforeMutationStopsWrite() {
        val h = Host();var allowed=true;h.read = { allowed=false;receipt(true) }
        val r = UltraModuleToggleTransaction(h,mutationAllowed={allowed}).setEnabled(id,false)
        assertEquals(UltraOutcome.CONDITION_UNMET,r.outcome);assertEquals(0,h.writes)
    }
    @Test fun modeChangeAfterMutationRequiresReconciliation() {
        val h = Host();var allowed=true;h.change = { allowed=false;h.state=false;receipt(false) }
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION,UltraModuleToggleTransaction(h,{allowed}).setEnabled(id,false).outcome)
        assertEquals(1,h.writes)
    }
    @Test fun malformedBooleanAndUnknownRuntimeAreNotTrusted() {
        for (bad in listOf(receipt(true).raw.replace("\"enabled\":true","\"enabled\":\"true\""),receipt(true,runtime="RemovedPendingReboot").raw)) {
            val h = Host();h.read={ NativeReceipt.parse(bad)!! }
            assertEquals(UltraOutcome.CONDITION_UNMET,h.run().outcome);assertEquals(0,h.writes)
        }
    }
    @Test fun invalidIdsAndWrongReadbackIdentityAreNotApplied() {
        val h = Host()
        for(bad in listOf("../bad", "", ".", "..", "a/b", "a\u0000b", "a".repeat(1024), "中".repeat(342), "😀".repeat(256)))
            assertEquals(UltraOutcome.CONDITION_UNMET,UltraModuleToggleTransaction(h).setEnabled(bad,false).outcome)
        assertEquals(0,h.reads)
        h.read={receipt(true,moduleId="a".repeat(32))}
        assertEquals(UltraOutcome.CONDITION_UNMET,h.run().outcome);assertEquals(0,h.writes)
    }
    @Test fun descriptorIdsUseSingleComponentsAndUtf8ByteBounds() {
        for (valid in listOf("a", "p0_probe", "z".repeat(32), "a".repeat(33), "a".repeat(1023),
            "中".repeat(341), "😀".repeat(255), "module with space", "module:colon", "module\\backslash")) {
            val h = Host()
            assertEquals(valid, UltraOutcome.PENDING_REBOOT, UltraModuleToggleTransaction(h).setEnabled(valid, false).outcome)
            assertEquals(valid, 1, h.writes)
            assertEquals(valid, 2, h.reads)
        }
    }
    @Test fun journalIsPreparedBeforeTheOnlyMutation() {
        val h = Host();var prepared=false
        h.change={assertTrue(prepared);h.state=false;receipt(false)}
        val r=UltraModuleToggleTransaction(h,beforeMutation={prepared=true}).setEnabled(id,false)
        assertEquals(UltraOutcome.PENDING_REBOOT,r.outcome);assertEquals(1,h.writes)
    }

    @Test fun completedMutationPreservesItsDiagnosticAndUsesExistingReadback() {
        val h = Host()
        val completed = NativeReceipt.parse("""{"backend":"maplesu_ultra","operation":"set_module_enabled",
            "ok":false,"sdkError":"SDK_CREDENTIAL_SCOPE_CHANGED","sdkErrorCode":-1001,
            "operationCompleted":true,"reason":"scope restore failed"}""")!!
        h.change = { h.state = false; completed }
        val result = h.run()
        assertEquals(UltraOutcome.PENDING_REBOOT, result.outcome)
        assertEquals(completed.raw, result.raw)
        assertEquals(completed.sdkErrorCode, result.sdkErrorCode)
        assertEquals(1, h.writes)
        assertEquals(2, h.reads)
    }

    @Test fun completedMutationDoesNotOverrideFailedPostStateOrWrongOperation() {
        val h = Host()
        val completed = NativeReceipt.parse("""{"backend":"maplesu_ultra","operation":"set_module_enabled",
            "ok":false,"sdkError":"SDK_CREDENTIAL_SCOPE_CHANGED","sdkErrorCode":-1001,
            "operationCompleted":true}""")!!
        h.change = { completed }
        h.read = { if (h.writes == 0) receipt(true) else
            NativeReceipt.bridgeFailure("get_module_control", "READ_FAILED", "post-state") }
        val pending = h.run()
        assertEquals(UltraOutcome.NEEDS_RECONCILIATION, pending.outcome)
        assertEquals(completed.raw, pending.raw)
        assertTrue(pending.unknowns.containsKey("moduleControl"))
        val wrongOperation = Host()
        wrongOperation.change = { completed.copy(operation = "install_module") }
        assertEquals(UltraOutcome.FAILED, wrongOperation.run().outcome)
    }
}
