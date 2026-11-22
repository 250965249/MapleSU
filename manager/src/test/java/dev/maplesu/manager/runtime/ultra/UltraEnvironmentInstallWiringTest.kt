// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime.ultra

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 接线守卫（source-level，JVM）：
 *
 *  1. **唯一安装入口**：`installEnvironment("Boot", ...)` 只允许出现在
 *     [UltraEnvironmentInstaller]（以及 [UltraRuntimeClient] 的定义处）。任何 UI/设置页
 *     重新直接调 SDK，都会绕过「安装成功 → 自白名单 + key 备份」（需求 1）。
 *  2. **启动恢复唯一入口**：[com.maplesu.core.KernelSUApplication] 只提交合并后的恢复请求。
 */
class UltraEnvironmentInstallWiringTest {

    private fun managerDir(): File {
        val cwd = File(System.getProperty("user.dir") ?: ".").absoluteFile
        if (File(cwd, "src/main/java").isDirectory) return cwd
        val child = File(cwd, "manager")
        if (File(child, "src/main/java").isDirectory) return child
        error("cannot locate manager module from $cwd")
    }

    private fun productionSources(): List<File> =
        File(managerDir(), "src/main/java").walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .toList()

    @Test
    fun onlyUltraEnvironmentInstallerCallsInstallEnvironmentWithBootMode() {
        val callers = productionSources()
            .filter { it.readText().contains("installEnvironment(\"Boot\"") }
            .map { it.name }
            .toSet()

        assertEquals(
            "installEnvironment(\"Boot\") must be centralized in UltraEnvironmentInstaller.kt",
            setOf("UltraEnvironmentInstaller.kt"),
            callers,
        )
    }

    @Test
    fun installerAlwaysRunsWhitelistAndBackupAfterSuccess() {
        val source = File(
            managerDir(),
            "src/main/java/dev/maplesu/manager/runtime/ultra/UltraEnvironmentInstaller.kt",
        ).readText()

        assertTrue("installer must route through afterInstall", source.contains("afterInstall("))
        assertTrue("installer must self-whitelist", source.contains("UltraSelfWhitelist"))
        assertTrue("installer must back up the key", source.contains("UltraRecoveryKeyStore"))
        // 白名单失败不得把安装改判失败：afterInstall 的 ok 只由 succeeded 决定。
        assertTrue(source.contains("if (!succeeded) return Outcome(false, receiptErrorName(false, sdkError), reason)"))
    }

    @Test
    fun startupRecoveryUsesOneConflatedPath() {
        val source = File(
            managerDir(),
            "src/main/java/com/maplesu/core/KernelSUApplication.kt",
        ).readText()

        assertFalse(source.contains("UltraSelfHeal.runOnStartup(this)"))
        assertTrue(source.contains("UltraRecoveryRequests("))
        assertTrue(source.contains("ultraRecoveryRequests.request()"))
        assertTrue(source.contains("recover = { recoverUltraEnvironment() }"))
    }

    @Test
    fun startupCanInitializePendingInstallBeforeModeActivation() {
        val source = File(managerDir(), "src/main/java/com/maplesu/core/KernelSUApplication.kt").readText()
        val warmup = source.substringAfter("private suspend fun recoverUltraEnvironment()")
            .substringBefore("override fun onCreate()")
        assertTrue(warmup.contains("UltraStartupWarmup.run("))
        assertFalse(warmup.contains("awaitDetectionSettled("))
        assertTrue(warmup.contains("liveEnvironmentReady ="))
        assertTrue(warmup.contains("hasPendingInstallCredential(this)"))
        assertTrue(warmup.contains("postBootUltraSwitchRecovery ="))
        assertTrue(warmup.contains("hasPostBootUltraSwitchRecovery(this)"))
        assertTrue(warmup.contains("verifiedUltraIdentity ="))
        assertTrue(warmup.contains("hasVerifiedUltraIdentity(this)"))
        assertTrue(warmup.contains("UltraEnvironmentAutoSetup.ensure(this)"))
        assertTrue(warmup.contains("UltraAutoPair.ensure(this, maintenance = false)"))
        assertTrue(warmup.indexOf("stage(\"capabilities\")") < warmup.indexOf("UltraPairingMaintenance.request("))
        assertTrue(warmup.contains("ModeBootstrap.retryEnvironmentDetection()"))
        assertTrue("warmup must not wait for the activation it prepares", !warmup.contains("awaitActivated("))
    }

    @Test
    fun normalRebootRecoveryRequiresTheMatchingVerifiedKeyAndKeepsWriteGuards() {
        val source = File(managerDir(),
            "src/main/java/dev/maplesu/manager/runtime/ultra/UltraEnvironmentAutoSetup.kt").readText()
        val eligibility = source.substringAfter("internal fun hasVerifiedUltraIdentity(")
            .substringBefore("private fun blockedReason(")
        assertTrue(eligibility.contains("UltraKernelCredential.isValid(key)"))
        assertTrue(eligibility.contains("sdkMetadataValid"))
        assertTrue(eligibility.contains("UltraKeyPairedStore.matchesVerifiedKey(context, key)"))
        assertTrue(source.contains("UltraAutoSetupAttempt.run("))
        assertTrue(source.contains("UltraRootKeyStore.read(appContext) != key"))
        assertTrue(source.contains("currentBootId() != bootId"))
    }

    @Test
    fun bootEvidenceDoesNotDependOnAWorkingRootChannel() {
        val source = File(managerDir(), "src/main/java/com/maplesu/core/ui/util/LogEvent.kt").readText()
        val capture = source.indexOf("ultra-boot-app.txt")
        assertTrue(capture in 0 until source.indexOf("val shell ="))
        assertTrue(source.contains("SystemClock.elapsedRealtime()"))
        assertTrue(source.contains("UltraEnvironmentAutoSetup.diagnostics(context)"))
        assertTrue(source.contains("ProcessBuilder(\"/system/bin/getprop\")"))
    }

    @Test
    fun permanentRecoveryPathsAndLastStageRecoveryStayWired() {
        val root = "src/main/java/dev/maplesu/manager/"
        val keys = File(managerDir(), root + "runtime/ultra/UltraRecoveryKeyStore.kt").readText()
        assertTrue(keys.contains("const val DIRECTORY = \"/data/adb/maplesu/recovery\""))
        assertTrue(keys.contains("const val PATH = \"\$DIRECTORY/rootkey\""))
        val paths = File(managerDir(), root + "workmode/storage/MoveSet.kt").readText()
        assertTrue(paths.contains("ULTRA_IDENTITY_ROOT = \"/data/adb/maplesu/ultra-identity\""))
        val adapter = File(managerDir(), root + "workmode/detect/probes/EnvironmentProbesAdapter.kt")
            .readText().substringAfter("override fun ultraFingerprint()")
        assertTrue(adapter.contains("UltraIdentityRecovery.recover(context.applicationContext)"))
        assertTrue(adapter.contains("UltraEnvironmentProbe.recoveryFingerprint(observed.state,"))
        assertTrue(adapter.contains("UltraEnvironmentProbe.refresh(context.applicationContext, force = false)"))
        val maintenance = File(managerDir(), root + "runtime/ultra/UltraPairingMaintenance.kt").readText()
        assertTrue(maintenance.indexOf("UltraEnvironmentInstaller.backupKey(app, key)") <
            maintenance.indexOf("UltraSelfWhitelist.ensureCurrentAuthority(app, client)"))
        val identity = File(managerDir(), root + "runtime/ultra/UltraIdentityRecovery.kt").readText()
        assertTrue(identity.contains("if (expected == key)"))
        assertTrue(identity.contains("UltraKeyPairedStore.markPaired(app, key)"))
        assertTrue(identity.contains("running?.key == key"))
        assertTrue(identity.contains("UltraIdentityBrokerDeployment.ensure(force"))
        assertTrue(identity.contains("UltraInstallCredentials.recoveryCandidates(app)"))
        val install = File(managerDir(), root + "runtime/ultra/UltraInstallCredentials.kt").readText()
        assertTrue(install.contains("UltraIdentityResolution.installCandidates("))
        assertTrue(install.contains("UltraPendingInstallCredentialStore(context).recoveryCredentials()"))
    }

    @Test
    fun cleanAppRecoveryRunsBeforeDetectionWithoutPrivateInstallReceipts() {
        val root = "src/main/java/dev/maplesu/manager/"
        val bootstrap = File(managerDir(), root + "workmode/boot/ModeBootstrap.kt").readText()
        val phaseTwo = bootstrap.substringAfter("private fun executePhaseTwo(")
        val recover = phaseTwo.indexOf("UltraInstallCredentialRecovery.recover(")
        assertTrue(recover >= 0 && recover < phaseTwo.indexOf("coordinator.runPhaseTwo()"))
        val recovery = File(managerDir(), root + "runtime/ultra/UltraInstallCredentialRecovery.kt").readText()
        assertTrue(recovery.indexOf("UltraIdentityRecovery.recover(") < recovery.indexOf("InstallerServiceClient.lastTaskId("))
        val pairing = File(managerDir(), root + "runtime/ultra/UltraAutoPair.kt").readText()
        val ensure = pairing.substringAfter("fun ensure(context: Context, maintenance: Boolean = true)")
        assertTrue(ensure.indexOf("UltraIdentityRecovery.recover(") < ensure.indexOf("UltraRootKeyStore.read("))
    }

    @Test
    fun firstRecoveryUsesLiveRootAndDefersAuthorizationUntilAfterPairing() {
        val source = File(managerDir(),
            "src/main/java/dev/maplesu/manager/runtime/ultra/UltraIdentityRecovery.kt").readText()
        val recovery = source.substringAfter("fun recover(context: Context)").substringBefore("internal fun uid(")
        assertTrue(recovery.contains("UltraIdentityResolution.recover("))
        assertTrue(recovery.contains("return uid(client)"))
        assertFalse(recovery.contains("UltraPairingMaintenance.request(app, key)"))
        assertTrue(recovery.contains("UltraEnvironmentProbe.hasCurrentRootProof(app)"))
        assertTrue(recovery.contains("elapsedMs="))
        assertTrue(source.contains("runRootCommand(\"/system/bin/id -u\")"))
        assertTrue(!recovery.contains("testRoot()") && !recovery.contains("testBasics("))
        assertTrue(recovery.contains("UltraKeyPairedStore.storeVerifiedKey("))
        assertTrue(recovery.contains("UltraRecoveryKeyStore.restore(app,"))
        assertTrue(recovery.contains("su.rootUid() != 0"))
        assertTrue(recovery.contains("UltraRootKeyStore.read(app) != expected"))
    }

    @Test
    fun independentRecoveryBootstrapIsPackagedAndKeptForR8() {
        val rules = File(managerDir(), "proguard-rules.pro").readText()
        assertTrue(rules.contains("-keep class dev.maplesu.manager.runtime.ultra.UltraIdentityBroker"))
        assertTrue(rules.substringAfter("-keep class dev.maplesu.manager.runtime.ultra.UltraIdentityBroker")
            .substringBefore("}").contains("public static void main(java.lang.String[]);"))
        val build = File(managerDir(), "build.gradle.kts").readText()
        assertTrue(build.contains("proguardFiles(getDefaultProguardFile(\"proguard-android-optimize.txt\"), \"proguard-rules.pro\")"))
        assertTrue(!build.contains("libmodule_maplesu_identity.so"))
        assertTrue(!build.contains("ultraIdentityLibrary"))
        val nativeBuild = File(managerDir().parentFile, "runtime/CMakeLists.txt").readText()
        assertTrue(!nativeBuild.contains("add_library(module_maplesu_identity"))
        val launcher = File(managerDir().parentFile, "runtime/ultra/identity/environment_start.c").readText()
        assertTrue(launcher.contains("maplesu_environment_identity_start"))
        assertTrue(!launcher.contains("MAPLESU_MODULE_"))
    }

    @Test
    fun postBootSwitchRecoveryOnlyOpensSetupAndPreservesPendingVerification() {
        val source = File(managerDir(),
            "src/main/java/dev/maplesu/manager/runtime/ultra/UltraEnvironmentAutoSetup.kt").readText()
        assertTrue(source.contains("WorkModeSwitchSession.executing -> \"SWITCH_PENDING\""))
        assertTrue(source.contains("ModeSwitchProgress.postBootUltraRecovery("))
        assertTrue(source.contains("UltraStartupWarmup.matchesPostBootSwitch("))
        assertTrue(source.contains("WorkModeSwitchSession.executing"))
        assertTrue("switch recovery retains boot diagnostics without a historical install gate",
            source.contains("putString(KEY_LAST_BOOT, bootId).apply()"))
        assertTrue(!source.contains("prefs.getString(KEY_LAST_BOOT, null) == bootId"))
        assertTrue("switch recovery must keep the single SDK install entry point",
            source.contains("UltraEnvironmentInstaller.install("))
        assertTrue("local provenance must not activate a mode", !source.contains("ModeRuntime.activate("))
        assertTrue("local provenance must not clear pending root verification",
            !source.contains("WorkModeSwitchSession.clear(") &&
                !source.contains("WorkModeSwitchSession.pending = false"))
    }
}
