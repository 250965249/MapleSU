package dev.maplesu.manager

import android.net.Uri
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.view.WindowManager
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.Natives
import com.maplesu.core.ui.MainActivity
import com.maplesu.core.ui.util.LkmSelection
import com.maplesu.core.ui.util.installBoot
import dev.maplesu.image.BootImageInspector
import dev.maplesu.manager.runtime.MapleSuCommandExecutor
import dev.maplesu.manager.runtime.MapleSuCredentialStore
import dev.maplesu.manager.runtime.MapleSuRuntime
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.RandomAccessFile

/** Hardware workflow checks are individually selected; ordinary test runs never write a partition. */
@RunWith(AndroidJUnit4::class)
class LiteWorkflowAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    @Test(timeout = 240_000) fun productionFilePatchExportsVerifiedImage() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("liteWorkflow") == "true")
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { it.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON) }
            val input = File(context.cacheDir, "lite-source.img")
            try {
                ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(
                    "cat /data/local/tmp/maplesu-lite-source.img")).use { stream ->
                    input.outputStream().use { stream.copyTo(it) }
                }
                val original = BootImageInspector.inspect(input)
                val before = context.filesDir.listFiles().orEmpty().map { it.name }.toSet()
                val output = mutableListOf<String>()
                val result = installBoot(Uri.fromFile(input), LkmSelection.KmiNone, false, "boot",
                    false, false, false, "", output::add, output::add)
                assertEquals(output.joinToString("\n"), 0, result.code)
                assertFalse(result.showReboot)
                val candidate = context.filesDir.listFiles().orEmpty().single {
                    it.name.startsWith("candidate-") && it.name !in before
                }
                val report = JSONObject(File(candidate, "candidate.json").readText())
                val image = BootImageInspector.inspect(File(candidate, "maplesu-patched.img"))
                assertEquals(original.sha256, report.getJSONObject("source").getString("sha256"))
                assertEquals(image.sha256, report.getJSONObject("image").getString("sha256"))
                assertNotEquals(original.sha256, image.sha256)
                assertTrue(report.getBoolean("candidateVerified"))
                assertTrue(report.getBoolean("credentialInitialized"))
                assertTrue(report.getInt("patchEdits") > 0)
                val footer = ByteArray(4)
                RandomAccessFile(input, "r").use { it.seek(input.length() - 64); it.readFully(footer) }
                if (footer.contentEquals("AVBf".toByteArray())) {
                    assertTrue(report.getJSONObject("rebuild").getBoolean("avbFooterPreserved"))
                    val rebuilt = File(candidate, "maplesu-patched.img")
                    assertEquals(input.length(), rebuilt.length())
                    RandomAccessFile(rebuilt, "r").use { it.seek(rebuilt.length() - 64); it.readFully(footer) }
                    assertArrayEquals("AVBf".toByteArray(), footer)
                }
                InstrumentationRegistry.getArguments().getString("expectedCandidateSha256")?.let {
                    assertEquals("Application patch differs from the verified boot image", it, image.sha256)
                }
                assertEquals(original.sha256, BootImageInspector.inspect(input).sha256)
                report.put("partitionWrites", false).put("exportVerified", true)
                File(context.filesDir, "lite-workflow.json").writeText(report.toString())
                instrumentation.sendStatus(2, Bundle().apply {
                    putString("candidateSha256", image.sha256)
                    putString("candidatePath", candidate.absolutePath)
                    putString("kernelRelease", report.getString("kernelRelease"))
                })
            } finally { input.delete() }
        }
    }

    @Test(timeout = 30_000) fun runningBackendUsesStoredCredential() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assertTrue(MapleSuRuntime.refresh(context))
        assertTrue(Natives.isManager)
        MapleSuRuntime.openShell(context).use { shell ->
            val result = shell.newJob().add("/system/bin/id -u", "/system/bin/getenforce")
                .to(ArrayList<String>(), null).exec()
            assertTrue(result.isSuccess)
            assertEquals(listOf("0", "Enforcing"), result.out)
        }
        val namespace = runCatching { MapleSuRuntime.openShell(context, globalMnt = true).close() }
        namespace.exceptionOrNull()?.let {
            assertEquals("MAPLESU_GLOBAL_NAMESPACE_UNAVAILABLE", it.message)
        }
        instrumentation.runOnMainSync {
            assertTrue("A deployment capability failure cleared authenticated Root state", Natives.isManager)
        }
        instrumentation.sendStatus(2, Bundle().apply {
            putString("globalNamespace", if (namespace.isSuccess) "available" else "unavailable")
            putString("authenticatedRootRetained", "true")
        })
        val wrong = requireNotNull(MapleSuCredentialStore(context).load())
        try {
            wrong[0] = if (wrong[0] == 'A'.code.toByte()) 'B'.code.toByte() else 'A'.code.toByte()
            val opened = runCatching { MapleSuCommandExecutor(context).openShell(wrong) }
            opened.getOrNull()?.close()
            assertTrue("Incorrect credential opened a root shell", opened.isFailure)
        } finally { wrong.fill(0) }
    }

    @Test(timeout = 300_000) fun explicitlyRequestedDirectInstallation() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("commitBoot") == "true")
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { it.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON) }
            val output = mutableListOf<String>()
            val taskId = java.util.UUID.randomUUID().toString()
            dev.maplesu.manager.installer.InstallerServiceClient.beginInstallation(context, taskId)
            val result = installBoot(null, LkmSelection.KmiNone, false, "boot",
                false, false, false, "", output::add, output::add, taskId,
                targetMode = dev.maplesu.manager.installer.InstallTargetMode.ULTRA,
                existingRootConflictAccepted = true)
            File(context.filesDir, "lite-install-result.json").writeText(JSONObject()
                .put("taskId", taskId).put("code", result.code).put("showReboot", result.showReboot)
                .put("log", output.joinToString("\n")).toString())
            assertEquals(output.joinToString("\n"), 0, result.code)
            assertTrue(result.showReboot)
            val status = dev.maplesu.manager.installer.InstallerServiceClient.installationStatus(context, taskId)
            assertEquals("REBOOT_REQUIRED", status.getString("state"))
            assertTrue(status.getInt("attemptedPartitionCount") > 0)
            val credentials = context.getSharedPreferences("maplesu-ultra", android.content.Context.MODE_PRIVATE)
            assertEquals(taskId, credentials.getString("installCredentialTaskId", null))
            instrumentation.sendStatus(2, Bundle().apply {
                putString("directInstallTaskId", taskId)
                putString("directInstallState", status.getString("state"))
                putInt("directInstallAttemptedPartitionCount", status.getInt("attemptedPartitionCount"))
                putBoolean("directInstallCredentialTaskMatches", true)
                putBoolean("directInstallPendingCredential",
                    dev.maplesu.manager.runtime.ultra.UltraInstallCredentialRecovery.hasPendingInstallCredential(context))
            })
        }
    }

    @Test(timeout = 90_000) fun verifiedRunningImageDoesNotRepatchOrRequestReboot() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyAlreadyInstalled") == "true")
        val client = dev.maplesu.manager.installer.InstallerServiceClient
        val before = client.observeBootChain(context)
        val digest = before.partitions.getValue("boot").sha256
        assertNotNull(dev.maplesu.manager.patching.LiteBootPatcher(context).findVerifiedCandidate(digest))
        assertTrue(MapleSuRuntime.refresh(context))
        val previous = client.lastTaskId(context)
        val taskId = java.util.UUID.randomUUID().toString()
        val output = mutableListOf<String>()
        try {
            client.beginInstallation(context, taskId)
            val result = installBoot(null, LkmSelection.KmiNone, false, "boot",
                false, false, false, "", output::add, output::add, taskId)
            assertEquals(output.joinToString("\n"), 0, result.code)
            assertFalse(result.showReboot)
            assertEquals("NONE", client.installationStatus(context, taskId).getString("state"))
            val after = client.observeBootChain(context)
            before.partitions.forEach { (name, partition) -> assertEquals(partition.sha256, after.partitions.getValue(name).sha256) }
            instrumentation.sendStatus(2, Bundle().apply {
                putString("alreadyInstalledBootSha256", digest)
                putBoolean("rebootRequired", false)
                putBoolean("partitionsUnchanged", true)
            })
        } finally {
            if (previous != null) client.rememberTask(context, previous)
            else context.getSharedPreferences("installer", android.content.Context.MODE_PRIVATE).edit().remove("lastTaskId").commit()
        }
    }
}
