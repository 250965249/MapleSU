package dev.maplesu.manager.workmode.detect.probes

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UltraRootEvidenceWiringTest {
    @Test fun inheritedUltraRevalidatesTheSdkTtlBeforeUsingAnyCachedFingerprint() {
        val path = "src/main/java/dev/maplesu/manager/workmode/detect/probes/EnvironmentProbesAdapter.kt"
        val file = listOf(File(path), File("manager/$path")).first { it.isFile }
        val body = file.readText().substringAfter("override fun currentUltraFingerprint()").substringBefore("override fun ultraFingerprint()")
        val refresh = body.indexOf("UltraEnvironmentProbe.refresh(context.applicationContext, force = false)")
        assertTrue("cached fingerprints must not bypass the probe TTL", refresh in 0 until body.indexOf("ultraJudges()"))
        assertTrue("a live Hook must not start a competing SDK root probe", body.indexOf("HookRootExecutor.production(") in 0 until refresh)
        assertTrue("Normal keeps priority without probing Ultra", body.indexOf("if (ksuNormal() == true) return null") in 0 until refresh)
        assertFalse("current channel reads must not recover credentials", body.contains("UltraIdentityRecovery.recover("))

        val recovery = file.readText().substringAfter("override fun ultraFingerprint()").substringBefore("override fun ksuNormal()")
        assertTrue("Unknown must not be polled again before credentials change",
            recovery.indexOf("UltraIdentityRecovery.recover(") in 0 until recovery.indexOf("UltraEnvironmentProbe.refresh("))
    }

    @Test fun ultraChannelIsWiredToSdkInsteadOfLegacyCredentialShell() {
        val path = "src/main/java/dev/maplesu/manager/workmode/detect/probes/RootEvidenceReaderAdapter.kt"
        val file = listOf(File(path), File("manager/$path")).first { it.isFile }
        val source = file.readText()
        assertFalse(source.contains("RootChannelKind.LITE_DIRECT, RootChannelKind.LITE_ULTRA ->"))
        assertTrue(source.contains("RootChannelKind.LITE_ULTRA ->"))
        assertTrue(source.contains("UltraRuntimeClient"))
        assertTrue(source.contains("client.runRootCommand(command)"))
        assertTrue(source.contains("UltraRootShellSession.open("))
    }

    @Test fun currentFingerprintJudgesKeepKeyBootAndSuspensionScoping() {
        val path = "src/main/java/dev/maplesu/manager/workmode/detect/probes/EnvironmentProbesAdapter.kt"
        val file = listOf(File(path), File("manager/$path")).first { it.isFile }
        val judges = file.readText().substringAfter("private fun ultraJudges()").substringBefore("companion object")
        assertTrue(judges.contains("UltraEnvironmentProbe.currentSnapshot(context).state"))
        assertTrue(judges.contains("UltraEnvironmentProbe.isSafeMode(context)"))
        assertTrue(judges.contains("UltraEnvironmentProbe.isKernelRootVerified(context)"))
        assertFalse(judges.contains("UltraEnvironmentProbe.currentSnapshot()"))
        assertFalse(judges.contains("UltraEnvironmentProbe.current()"))

        val probePath = "src/main/java/dev/maplesu/manager/runtime/ultra/UltraEnvironmentProbe.kt"
        val probe = listOf(File(probePath), File("manager/$probePath")).first { it.isFile }.readText()
        val scope = probe.substringAfter("internal fun currentSnapshot(context: Context)")
            .substringBefore("internal fun scopeSnapshot(")
        assertTrue(scope.contains("UltraSdkCredentials.read(context)"))
        assertTrue(scope.contains("UltraEnvironmentAutoSetup.currentBootId()"))
        assertTrue(scope.contains("scopeSnapshot(snapshot, key, snapshotKey, bootId, snapshotBootId,"))
        assertTrue(scope.contains("UltraSdkCredentials.suspended(context)"))
        assertTrue(scope.contains("UltraSdkCredentials.hookWithoutSdk(context)"))
    }
}
