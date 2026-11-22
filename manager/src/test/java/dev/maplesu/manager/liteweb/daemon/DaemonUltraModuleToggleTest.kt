package dev.maplesu.manager.liteweb.daemon

import dev.maplesu.manager.liteweb.LiteWebToggleView
import dev.maplesu.manager.modules.compat.UltraModuleHost
import dev.maplesu.manager.ultra.model.MapleSuModInstalledItem
import dev.maplesu.manager.runtime.ultra.NativeReceipt
import dev.maplesu.manager.runtime.ultra.UltraReceipt
import org.junit.Assert.*
import org.junit.Test

class DaemonUltraModuleToggleTest {
    private val id = "a".repeat(32)
    private inner class Host : UltraModuleHost {
        var enabled = true
        var supported = true
        var writes = 0
        var reads = 0
        var afterWrite: () -> Unit = {}
        var lostReadback = false
        override fun moduleControl(id32: String): NativeReceipt {
            reads++
            if (lostReadback && writes > 0) return NativeReceipt.bridgeFailure("get_module_control", "IO", "lost")
            return NativeReceipt.parse("""{"schemaVersion":1,"backend":"maplesu_ultra","operation":"get_module_control","ok":true,
                "sdkError":"OK","sdkErrorCode":0,"data":{"abiVersion":1,"id32":"$id32","enabled":$enabled,
                "needsReboot":true,"runtimeState":"Running","supportsEnableToggle":$supported}}""")!!
        }
        override fun setModuleEnabled(id32: String, enabled: Boolean): NativeReceipt {
            writes++;this.enabled=enabled;afterWrite();return moduleControl(id32)
        }
        override fun environmentState(): NativeReceipt = error("unused")
        override fun parseModuleDescriptor(zipPath: String): NativeReceipt = error("no callbacks")
        override fun installModule(zipPath: String, devRunOnce: Boolean): NativeReceipt = error("no install")
        override fun uninstallModule(id32: String): NativeReceipt = error("no uninstall")
        override fun modules(): List<MapleSuModInstalledItem> = error("no list fallback")
        override fun openModuleWebUI(id32: String): NativeReceipt = error("no entry")
    }
    @Test fun nativeAliasUsesVerifiedTransactionAndKeepsRebootPending() {
        val host=Host();val journal=mutableListOf<UltraReceipt>()
        val result=DaemonUltraModuleToggle(host,{true},journal::add).setEnabled("maplesu:$id",false)
        assertEquals(LiteWebToggleView.Ok("maplesu:$id",false,true),result)
        assertEquals(1,host.writes);assertEquals(2,journal.size)
        assertEquals("PREPARED",journal.first().phase.name)
        assertEquals("Running",journal.last().data!!.getString("runtimeState"))
    }
    @Test fun pendingModeSwitchBlocksWrite() {
        val host=Host();assertTrue(DaemonUltraModuleToggle(host,{false},{}).setEnabled("maplesu:$id",false) is LiteWebToggleView.Failed)
        assertEquals(0,host.writes);assertEquals(0,host.reads)
    }
    @Test fun modeChangeDuringWriteIsNotAcknowledgedAsSuccess() {
        val host=Host();var allowed=true;host.afterWrite={allowed=false}
        assertTrue(DaemonUltraModuleToggle(host,{allowed},{}).setEnabled("maplesu:$id",false) is LiteWebToggleView.Failed)
        assertEquals(1,host.writes)
    }
    @Test fun olderInstalledHelperReceivesNoMutation() {
        val host=Host();host.supported=false
        assertTrue(DaemonUltraModuleToggle(host,{true},{}).setEnabled("maplesu:$id",false) is LiteWebToggleView.Failed)
        assertEquals(0,host.writes)
    }
    @Test fun invalidAliasAndMissingReadbackAreNotSuccessful() {
        val host=Host();val port=DaemonUltraModuleToggle(host,{true},{})
        for (bad in listOf(id,"maplesu:","maplesu:.","maplesu:..","maplesu:../bad", "maplesu:a\u0000b",
            "maplesu:" + "中".repeat(342), "maplesu:" + "😀".repeat(256)))
            assertTrue(port.setEnabled(bad,false) is LiteWebToggleView.Failed)
        assertEquals(0,host.reads);host.lostReadback=true
        assertTrue(port.setEnabled("maplesu:$id",false) is LiteWebToggleView.Failed)
        assertEquals(1,host.writes)
    }
    @Test fun descriptorAliasesUseTheSameIdContractAsTheTransaction() {
        for (valid in listOf("a", "p0_probe", "z".repeat(32), "a".repeat(33), "a".repeat(1023),
            "中".repeat(341), "😀".repeat(255), "module with space")) {
            val host = Host()
            assertEquals(LiteWebToggleView.Ok("maplesu:$valid", false, true),
                DaemonUltraModuleToggle(host, {true}, {}).setEnabled("maplesu:$valid", false))
            assertEquals(1, host.writes)
        }
    }
    @Test fun journalFailurePreventsMutation() {
        val host=Host()
        try {DaemonUltraModuleToggle(host,{true},{error("disk full")}).setEnabled("maplesu:$id",false);fail("expected journal failure")}
        catch (_: IllegalStateException) {assertEquals(0,host.writes)}
    }
}
