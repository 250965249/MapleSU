package dev.maplesu.manager.modules

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Guard the real service and startup call sites, not a parallel test dispatcher. */
class JailbreakModuleWiringTest {
    private fun source(path: String) = File("src/main/java/$path.kt").readText()

    @Test fun moduleWorkerUsesTheLiveRootRouterInsteadOfPairedOnlyCredentials() {
        val service = source("dev/maplesu/manager/modules/LiteModuleBootService")
        assertFalse("Hook has no paired credential", service.contains("MapleSuRuntime.refresh"))
        assertTrue(service.contains("RootExec.execute(this, \"/system/bin/id -u\")"))
    }

    @Test fun moduleReceiptsDistinguishFrameworkRestartsFromKernelBoots() {
        val backend = source("dev/maplesu/manager/modules/LiteScriptModuleBackend")
        assertTrue("Soft reboot must advance module epochs", backend.contains("LiteModuleBootEpoch.read(context)"))
    }

    @Test fun moduleInventoryAndShellIdentityUseTheCurrentSdkOwner() {
        val shell = source("dev/maplesu/manager/modules/ModuleRootShell")
        assertTrue(shell.contains("val nextKey = UltraSdkCredentials.read(app)"))
        assertTrue(shell.contains("val client = UltraSdkCredentials.client(app)"))
        assertFalse(shell.contains("UltraRootKeyStore.read(app)"))
    }

    @Test fun hookOnlyModuleListsSkipTheSdkCatalogAndKeepSdkFailuresVisible() {
        val list = source("com/maplesu/core/ui/util/KsuCli")
            .substringAfter("fun listModules(): String {").substringBefore("fun getModuleCount()")
        val sdk = list.substringAfter("val ultraItems = if (").substringBefore("val merged =")
        assertTrue("Only the verified SDK owner may request native module rows",
            sdk.startsWith("dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe.usesUltraBackend(ksuApp))"))
        assertTrue("A selected SDK backend must preserve real list failures", sdk.contains(".listItems(required = true)"))
        assertTrue("Hook-only lists use the independently verified script tree", sdk.contains("else null"))
        assertFalse("A safety flag does not establish SDK ownership", sdk.contains("Natives.isSafeMode"))
    }

    @Test fun hookInventoryBypassesTheStreamingShellMonitor() {
        val snapshot = source("dev/maplesu/manager/modules/ModuleRootShell")
            .substringAfter("override fun readSnapshot(script: String)").substringBefore("private fun isQuiescing()")
        assertTrue("Mode switches still pause inventory reads", snapshot.contains("if (isQuiescing())"))
        assertTrue("Normal retains its own route", snapshot.contains("if (ModeRuntime.active == WorkMode.KSU) return run(script)"))
        assertTrue("Hook inventories must not call the synchronized streaming run method",
            snapshot.contains("if (!UltraEnvironmentProbe.usesUltraBackend(app)) return RootExecModuleScriptRunner.run(app, script)"))
    }

    @Test fun installedModulePolicyAndWebUiUseTheCurrentSdkOwner() {
        for (name in listOf("UltraModulePolicyRepository", "ModuleWebUiLauncher")) {
            val entry = source("dev/maplesu/manager/modules/$name")
            assertTrue(entry.contains("UltraSdkCredentials.client("))
            assertFalse(entry.contains("UltraRootKeyStore.read("))
        }
    }

    @Test fun temporarySdkOwnershipBlocksPermanentPairingAndQueuedMaintenance() {
        val recovery = source("dev/maplesu/manager/runtime/ultra/UltraIdentityRecovery")
        val blocked = recovery.substringAfter("internal fun blocked(context: Context)")
            .substringBefore("private data class Candidate")
        assertTrue(blocked.contains("UltraSdkSession.current(context) != null"))
        assertTrue(blocked.contains("HookRootExecutor.production(context).available()"))
        val pairing = source("dev/maplesu/manager/runtime/ultra/UltraAutoPair")
        assertTrue(pairing.substringBefore("UltraIdentityRecovery.recover(appContext)")
            .contains("if (UltraIdentityRecovery.blocked(appContext))"))
        assertTrue(pairing.substringAfter("current = {").substringBefore("alreadyPaired = {")
            .contains("!UltraIdentityRecovery.blocked(appContext)"))
        val maintenance = source("dev/maplesu/manager/runtime/ultra/UltraPairingMaintenance")
            .substringAfter("private fun allowed(").substringBefore("fun request(")
        assertTrue(maintenance.contains("!UltraIdentityRecovery.blocked(context)"))
    }

    @Test fun hookCompletionPreparesTheSdkBeforeSchedulingModuleDetection() {
        val controller = source("dev/maplesu/manager/jailbreak/JailbreakController")
            .substringAfter("private fun completed(").substringBefore("fun cancel(")
        val preparation = controller.substringAfter("prepare = {")
        assertTrue(preparation.contains("HookRootExecutor.production(context).available()"))
        assertTrue(preparation.contains("UltraEnvironmentAutoSetup.ensure(context)"))
        assertFalse(preparation.contains("UltraRootKeyStore"))
    }

    @Test fun resolvedUltraModeSchedulesPendingModules() {
        val bootstrap = source("dev/maplesu/manager/workmode/boot/ModeBootstrap")
        assertTrue(bootstrap.contains("LiteModuleBootService.request(appContext)"))
    }

    @Test fun hookReproofRestoresModuleComponentsDisabledByNormal() {
        val enabled = mutableListOf<String>()
        dev.maplesu.manager.runtime.enableHookComponents(dev.maplesu.manager.workmode.WorkMode.LITE, enabled::add)
        assertTrue(enabled.contains("dev.maplesu.manager.modules.LiteModuleBootReceiver"))
        assertTrue(enabled.contains("dev.maplesu.manager.modules.LiteModuleBootService"))
    }

    @Test fun bothSkinsKeepTheGreyJailbreakCardTappableForExplanationOnly() {
        for (skin in listOf("Material", "Miuix")) {
            val entry = source("com/maplesu/core/ui/screen/home/HomeWorkModeSwitch$skin")
            assertTrue(entry.contains("HomeWorkModeSwitchBlock.JAILBREAK_ACTIVE"))
            assertTrue(entry.contains("matchParentSize().clickable"))
            assertTrue(entry.contains("enabled = state.enabled"))
        }
        val home = source("com/maplesu/core/ui/screen/home/HomeScreen")
        assertTrue(home.contains("jailbreakModeDialog.show"))
        assertTrue(home.contains("showWorkModeSheet && !suppressEntries && workModeSwitch.enabled"))
    }
}
