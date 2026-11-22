package dev.maplesu.manager.runtime

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HookSuCompatibilityTest {
    @Test fun traditionalEntryDoesNotCreateAGloballyVisibleSuFile() {
        val script = HookSuCompatibility.cleanupScript()
        assertFalse("ungranted applications inherit an overlay mounted into init/zygote",
            script.contains("/system/bin/mount -t overlay"))
        assertFalse(script.contains("/system/bin/ln"))
        assertFalse(script.contains("/system/bin/mkdir"))
    }

    @Test fun cleanupCoversInheritedNamespacesButRemovesOnlyOurLegacyMounts() {
        val script = HookSuCompatibility.cleanupScript()
        assertTrue(script.contains("pids=\"1 "))
        assertTrue(script.contains("/system/bin/ps -A -o PID"))
        assertTrue(script.contains("/proc/\$pid/mountinfo"))
        assertTrue(script.contains(" - overlay maplesu-su "))
        assertTrue(script.contains("/system/bin/umount -l"))
        assertTrue(script.contains("/system/bin|/system/xbin|/product/bin|/system_ext/bin"))
        assertTrue(script.contains("case \"\$seen\""))
        assertTrue(script.contains("HOOK_SU_NAMESPACE_CLEANUP_FAILED"))
        assertTrue(script.contains("[ \"\$failed\" = 0 ] || exit 75"))
        assertTrue(script.trimEnd().endsWith("echo HOOK_SU_LEGACY_CLEAN"))
        assertFalse(script.contains("suToken"))
        assertFalse(script.contains("setenforce"))
    }

    @Test fun readyRequiresSdkAuthorityCleanupAndAnOrdinaryUidExecInOrder() {
        val calls = mutableListOf<String>()
        HookSuCompatibility.ensurePublication(
            prepare = { calls += "sdk"; null }, cleanup = { calls += "cleanup" },
            probe = { calls += "exec"; true })
        org.junit.Assert.assertEquals(listOf("cleanup", "sdk", "exec"), calls)
    }

    @Test fun missingSdkDoesNotPublishAGlobalFallbackOrClaimReady() {
        val calls = mutableListOf<String>()
        val error = runCatching { HookSuCompatibility.ensurePublication(
            prepare = { calls += "sdk"; "SDK_GATEWAY_UNAVAILABLE" }, cleanup = { calls += "cleanup" },
            probe = { error("unexpected exec") }) }.exceptionOrNull()
        org.junit.Assert.assertEquals("SDK_GATEWAY_UNAVAILABLE", error?.message)
        org.junit.Assert.assertEquals(listOf("cleanup", "sdk"), calls)
    }

    @Test fun unrelatedSetupFailuresStillVerifyTheCurrentSdkSuEntry() {
        for (reason in listOf("MODULE_LIST_UNVERIFIED", "AUTHORIZATION_SYNC_PENDING")) {
            val calls = mutableListOf<String>()
            HookSuCompatibility.ensurePublication(
                prepare = { calls += "setup"; reason }, cleanup = { calls += "cleanup" },
                sdkCurrent = { calls += "session"; true }, probe = { calls += "exec"; true })
            org.junit.Assert.assertEquals(listOf("cleanup", "setup", "session", "exec", "session"), calls)
        }
    }

    @Test fun absentCurrentSdkNeverProbesOrPublishesEvenAfterSuccessfulSetup() {
        val failure = runCatching { HookSuCompatibility.ensurePublication(
            prepare = { null }, cleanup = {}, sdkCurrent = { false },
            probe = { error("unexpected exec") }) }.exceptionOrNull()
        org.junit.Assert.assertEquals("SDK_SESSION_ABSENT", failure?.message)
    }

    @Test fun currentSdkStillRequiresARealSuccessfulExec() {
        val failure = runCatching { HookSuCompatibility.ensurePublication(
            prepare = { "MODULE_LIST_UNVERIFIED" }, cleanup = {}, sdkCurrent = { true },
            probe = { false }) }.exceptionOrNull()
        org.junit.Assert.assertEquals("HOOK_SU_EXEC_UNVERIFIED", failure?.message)
    }

    @Test fun sdkIdentityChangeDuringExecNeverPublishesTheOldReceipt() {
        var current = true
        val failure = runCatching { HookSuCompatibility.ensurePublication(
            prepare = { null }, cleanup = {}, sdkCurrent = { current },
            probe = { current = false; true }) }.exceptionOrNull()
        org.junit.Assert.assertEquals("SDK_SESSION_CHANGED", failure?.message)
    }

    @Test fun failedExecOrCleanupNeverClaimsReady() {
        val denied = runCatching { HookSuCompatibility.ensurePublication(
            prepare = { null }, cleanup = {}, probe = { false }) }.exceptionOrNull()
        org.junit.Assert.assertEquals("HOOK_SU_EXEC_UNVERIFIED", denied?.message)
        val cleanup = runCatching { HookSuCompatibility.ensurePublication(
            prepare = { null }, cleanup = { error("HOOK_SU_CLEANUP_FAILED") },
            probe = { error("unexpected exec") }) }.exceptionOrNull()
        org.junit.Assert.assertEquals("HOOK_SU_CLEANUP_FAILED", cleanup?.message)
    }

    @Test fun grantStartupAndUiUseTheSameCompatibilityPublisher() {
        fun source(name: String): String = listOf(File("src/main/java/$name"), File("manager/src/main/java/$name"))
            .first { it.isFile }.readText()
        val root = "dev/maplesu/manager/runtime/"
        val deploy = source(root + "RuntimeDeployment.kt")
        val grant = source(root + "authorization/SuperuserControl.kt")
        val display = source(root + "SuDelivery.kt")
        assertTrue(deploy.contains("HookSuCompatibility.publish(application, mode,"))
        assertTrue(grant.substringAfter("if (HookRootExecutor.production(context).available()) {")
            .substringBefore("val mirror").contains("RuntimeDeployment.start(context)"))
        assertTrue(display.contains("val wired = HookSuCompatibility.traditionalReady(context)"))
        assertTrue(display.contains("managerSuState(isGranted, packageName in stale, pending = false, entryReady = wired)"))
    }

    @Test fun publicationNeverPreparesTheLegacyManagementEndpoint() {
        fun source(name: String): String = listOf(File("src/main/java/$name"), File("manager/src/main/java/$name"))
            .first { it.isFile }.readText()
        val publisher = source("dev/maplesu/manager/runtime/HookSuCompatibility.kt")
        assertFalse("Ultra has no legacy management credential", publisher.contains("NativeSuDaemon.service(app)"))
        assertTrue(publisher.contains("NativeSuDiscovery.peek(app.applicationInfo.uid)"))
        assertTrue("recovery inside publication must not enqueue itself",
            publisher.contains("NativeSuDaemon.reproveHookOutcome(app, scheduleDeployment = false)"))
    }

    @Test fun liveBrokerDoesNotRecoverOrReprepare() {
        HookSuCompatibility.ensureBroker(published = { true }, recover = { error("unexpected recovery") })
    }

    @Test fun missingBrokerIsRecoveredOnceFromTheExistingGate() {
        var published = false
        var recoveries = 0
        HookSuCompatibility.ensureBroker(published = { published }, recover = { recoveries++; published = true })
        org.junit.Assert.assertEquals(1, recoveries)
    }

    @Test fun failedRecoveryIsNotRetriedAndKeepsItsReason() {
        var recoveries = 0
        val failure = runCatching {
            HookSuCompatibility.ensureBroker(published = { false }, recover = { recoveries++; error("SU_GATE_NOT_ARMED") })
        }.exceptionOrNull()
        org.junit.Assert.assertEquals(1, recoveries)
        org.junit.Assert.assertEquals("SU_GATE_NOT_ARMED", failure?.message)
    }

    @Test fun recoveryWithoutAPublicationIsAnErrorNotSuccess() {
        val failure = runCatching {
            HookSuCompatibility.ensureBroker(published = { false }, recover = {})
        }.exceptionOrNull()
        org.junit.Assert.assertEquals("SU_EXECUTOR_NOT_PUBLISHED", failure?.message)
    }

    @Test fun failedSdkPublicationRechecksBrokerWithoutRetainingATraditionalReceipt() {
        fun source(name: String): String = listOf(File("src/main/java/$name"), File("manager/src/main/java/$name"))
            .first { it.isFile }.readText()
        val deploy = source("dev/maplesu/manager/runtime/RuntimeDeployment.kt")
        val failure = deploy.substringAfter("} catch (error: Exception) {").substringBefore("} finally {")
        assertTrue(failure.contains("brokerReady = HookSuCompatibility.brokerReady(application)"))
        assertTrue(failure.contains("current = Status(brokerReady = brokerReady, error = reason)"))
        val publisher = source("dev/maplesu/manager/runtime/HookSuCompatibility.kt")
        assertTrue(publisher.contains("published = { brokerReady(app) }"))
        assertTrue(publisher.contains("NativeSuDiscovery.peek(app.applicationInfo.uid).isBinderAlive"))
        assertTrue(publisher.contains("check(probe()) { \"HOOK_SU_EXEC_UNVERIFIED\" }"))
        assertTrue(publisher.contains("status.brokerReady && status.error == null && status.standardPath == STANDARD_PATH"))
        assertTrue(publisher.contains("UltraSdkSession.current(context) != null"))
    }

    @Test fun generatedPublicationIsAValidShellProgram() {
        val script = HookSuCompatibility.cleanupScript()
        val exported = System.getProperty("maplesu.hook.su.script")?.let(::File)
        exported?.writeText(script + "\n")
        val bash = File("C:/Program Files/Git/bin/bash.exe")
        org.junit.Assume.assumeTrue(bash.isFile)
        val file = java.nio.file.Files.createTempFile("hook-entry-", ".sh").toFile()
        try {
            file.writeText(script + "\n")
            val process = ProcessBuilder(bash.path, "-n", file.path.replace('\\', '/')).redirectErrorStream(true).start()
            assertTrue(process.waitFor(5, java.util.concurrent.TimeUnit.SECONDS))
            org.junit.Assert.assertEquals(process.inputStream.bufferedReader().readText(), 0, process.exitValue())
        } finally { file.delete() }
    }

}
