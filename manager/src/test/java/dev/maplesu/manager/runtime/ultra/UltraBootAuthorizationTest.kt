package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class UltraBootAuthorizationTest {
    private fun source(path: String): String = listOf(File(path), File("manager/$path"))
        .first { it.isFile }.readText()

    @Test fun bootServiceLoadsDeployedRepairedSdkAfterSystemReady() {
        val deploy = source("src/main/java/dev/maplesu/manager/runtime/ultra/UltraIdentityRecovery.kt")
        val broker = source("src/main/java/dev/maplesu/manager/runtime/ultra/UltraIdentityBroker.kt")
        val bridge = source("src/main/java/dev/maplesu/manager/runtime/ultra/bridge/NativeBridge.java")
        val start = deploy.substringAfter("private fun startScript()")
        assertTrue(start.indexOf("sys.boot_completed") < start.indexOf("exec /system/bin/app_process"))
        assertTrue(start.contains("-Dmaplesu.ultra.boot.library="))
        assertTrue(deploy.contains("sha256(bridge)"))
        assertTrue(deploy.contains("chmod 600"))
        assertTrue(bridge.contains("android.os.Process.myUid() == 0"))
        assertTrue(bridge.contains("System.load(bootLibrary)"))
        assertTrue(broker.contains("UltraManagerSignatureAuthorization.Session(trust)"))
        assertTrue(broker.contains("authorization.refresh("))
        assertTrue(!broker.contains("client.refreshSuAuthList()"))
        assertTrue(broker.contains("isDaemon = true"))
        assertTrue(deploy.contains("!force && running?.key == key"))
        assertTrue(deploy.contains("running.deploymentId == fingerprint"))
        assertTrue(deploy.contains("UltraIdentityBootHook.ensure("))
        assertTrue(deploy.contains("UltraInstalledIdentityProbe.readAndVerify(context, client)"))
        assertTrue(!deploy.contains("client.installModule("))
    }

    @Test fun bootAndRootServiceRetryTheirVerifiedAuthorizationActions() {
        val brokerSource = source("src/main/java/dev/maplesu/manager/runtime/ultra/UltraIdentityBroker.kt")
        assertTrue(brokerSource.contains("UltraBootAuthorizationRestore().maintain("))
        val broker = brokerSource.substringAfter("UltraBootAuthorizationRestore().maintain(")
            .substringBefore("onResult =")
        assertTrue(broker.contains("File(DISABLED).exists()"))
        assertTrue(broker.contains("restoreAuthorization(trust, authorization, client)"))
        assertTrue(!broker.contains("client.addSuAuth("))
        assertTrue(brokerSource.indexOf(".start()") < brokerSource.indexOf("server.accept()"))
        val service = source("src/main/java/dev/maplesu/manager/installer/InstallerPartitionService.kt")
            .substringAfter("override fun refreshUltraAuthorization(").substringBefore("override fun ")
        assertTrue(service.contains("authorizationRestore.ensure("))
        assertTrue(service.contains("UltraIdentityBroker.DISABLED"))
        assertTrue(service.contains("refreshSuAuthList()"))
        assertTrue(!service.contains("addSuAuth("))
    }

    @Test fun productionUpgradePreparesTheCurrentRestorerBeforeSubmission() {
        val installer = source("src/main/java/dev/maplesu/manager/runtime/ultra/UltraEnvironmentInstaller.kt")
        assertTrue(installer.contains("prepareUpgrade = {"))
        val preparation = installer.substringAfter("prepareUpgrade = {").substringBefore("\n        ),")
        assertTrue(preparation.contains("backupKey(context, forceIdentity = true, preparingUpgrade = true)"))
        assertTrue(preparation.contains("prepared?.ok == true"))
        val install = installer.substringAfter("fun install(port: InstallPort,")
        assertTrue(install.contains("intent == Intent.UpgradeToBundledBuild"))
        assertTrue(install.indexOf("attachments.prepareUpgrade()") in 0 until install.indexOf("port.submitInstall()"))
    }
}
