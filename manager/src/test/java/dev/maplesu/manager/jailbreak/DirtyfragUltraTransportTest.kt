package dev.maplesu.manager.jailbreak

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DirtyfragUltraTransportTest {
    private val root = sequenceOf(File("."), File(".."))
        .map { it.absoluteFile.normalize() }
        .first { File(it, "jailbreak-providers").isDirectory }

    private fun source(path: String) = File(root, path).readText()

    @Test fun executorBindsTheRequestedBackendBeforeAdmission() {
        val executor = source("manager/src/main/java/dev/maplesu/manager/jailbreak/JailbreakExecutor.kt")
        val initial = executor.substringAfter("var status = JailbreakStatus(")
            .substringBefore("currentStatus = status")
        assertTrue("early failures must retain the requested backend through advance()",
            initial.contains("rootBackend = request.rootBackend"))
    }

    @Test fun hookListenerUsesTheNativeWorkersFilesystemNamespace() {
        val server = source("manager/src/main/java/dev/maplesu/manager/jailbreak/HookAttestServer.kt")
        val native = source("jailbreak-providers/dirtyfrag/adapter/bootstrap.c")
        assertTrue("native worker connects to a filesystem sun_path",
            native.contains("memcpy(peer.sun_path, state.socket_path, strlen(state.socket_path) + 1)"))
        assertTrue("the App must bind the same filesystem namespace",
            server.contains("LocalSocketAddress.Namespace.FILESYSTEM"))
        assertFalse("String constructor binds ABSTRACT, invisible to the native filesystem connector",
            Regex("LocalServerSocket\\(\\s*socket\\.path\\s*\\)").containsMatchIn(server))
    }

    @Test fun productHookDoesNotRequireTheLegacyExactReleaseIrSpec() {
        val caller = source("jailbreak-providers/android/src/main/java/dev/maplesu/manager/jailbreak/DirtyfragAttempt.java")
        assertTrue("hook must use its own staging route before the IR branch",
            caller.contains("if (hookAttemptId != null) IrImages.stageForHook(context, directory, admission.kernelRelease());"))
        val images = source("manager/src/main/java/dev/maplesu/manager/jailbreak/IrImages.kt")
        val hook = images.substringAfter("fun stageForHook(").substringBefore("fun stageHookModule(")
        assertTrue("only bring-up builds need IR staging", hook.contains("if (inventory.isRootCanary)"))
        assertTrue("product hook stages no per-release offsets", hook.contains("clear(directory)"))
        assertTrue("missing hook payload stays a named failure", hook.contains("MAPLESU_HOOK_NOT_PACKAGED"))
    }
}
