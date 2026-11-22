package dev.maplesu.manager.liteweb.daemon

import dev.maplesu.manager.litehidden.RecoveryIdentity
import dev.maplesu.manager.litehidden.HiddenRootRunner
import dev.maplesu.manager.litehidden.preparePermanentHiddenRecovery
import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import dev.maplesu.manager.runtime.ultra.UltraBootSdkRecovery
import dev.maplesu.manager.runtime.ultra.UltraBootSdkSession
import dev.maplesu.manager.runtime.ultra.UltraRecoveryKey
import dev.maplesu.manager.recovery.LocalRecoveryFs
import dev.maplesu.manager.recovery.RecoveryBundle
import dev.maplesu.manager.recovery.RecoveryCommandResult
import dev.maplesu.manager.recovery.RecoveryCommandRunner
import dev.maplesu.manager.recovery.RecoveryPrepareResult
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class DaemonManagerRecoveryReadinessTest {
    @get:Rule val temporary = TemporaryFolder()
    private val boot = "11111111-2222-4333-8444-555555555555"
    private var currentBoot: String? = boot
    private val pkg = DaemonManagerUninstall.PACKAGE
    private val identity = requireNotNull(RecoveryIdentity.of("0123456789abcdef", pkg, 10489))
    private val key = UltraKernelCredential.of("Aa1".repeat(16)).withMetadataDisplacement(-4096)
        .copySecret().toString(Charsets.US_ASCII)
    private var privateMaterial = true
    private var readableSdk = true
    private var runtimeChecks = 0
    private var sdkLoads = 0

    private fun recovery(): File = temporary.newFolder().apply {
        resolve("identity.json").writeText(identity.toJson())
        resolve("native").mkdir()
        resolve("native/libmaplesu_ultra_bridge.so").writeBytes(byteArrayOf(1))
    }

    private fun bootSession(root: File) {
        val session = requireNotNull(UltraBootSdkSession.create(boot, key))
        root.resolve(UltraBootSdkRecovery.FILE_NAME).writeText(requireNotNull(UltraBootSdkRecovery.seal(session, identity)))
    }

    private fun access(root: File) = DaemonUltraSdkAccess(
        shell = DaemonShell { command ->
            if (privateMaterial && command.contains("SDK_SESSION_PRIVATE")) DaemonShellResult(0, "SDK_SESSION_PRIVATE")
            else DaemonShellResult(1, "")
        },
        recoveryRoot = root.absolutePath,
        loadSdk = { sdkLoads++; true },
        bootId = { currentBoot },
    )

    private fun readiness(root: File, access: DaemonUltraSdkAccess = access(root)) = DaemonManagerRecoveryReadiness(
        identityText = { root.resolve("identity.json").takeIf { it.isFile }?.readText() },
        payload = { root.resolve("rootkey").takeIf { it.isFile }?.readText() },
        sdkReady = { runtimeChecks++; readableSdk },
        sdkAccess = access::open,
    )

    @Test fun currentBootSdkSessionWithoutPermanentRootkeyIsReady() {
        val root = recovery()
        bootSession(root)
        val access = access(root)
        assertEquals("boot-session", (access.open() as DaemonUltraSdkResult.Ready).source)
        assertFalse(root.resolve("rootkey").exists())
        assertTrue("a valid independent boot session must permit activation", readiness(root, access).ready())
        assertEquals(1, runtimeChecks)
        assertEquals(1, sdkLoads)
    }

    @Test fun bootSessionCanCompleteManagerRemovalButExpiryBlocksAnyNewCommand() {
        val root = recovery()
        val apk = temporary.newFile("source.apk")
        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("lib/arm64-v8a/libmaplesu_ultra_bridge.so"))
            zip.write(byteArrayOf(1))
            zip.closeEntry()
        }
        val bundle = RecoveryBundle(LocalRecoveryFs(), root.absolutePath, locationPolicy = { true })
        assertTrue(bundle.prepare(pkg, 1, apk.absolutePath) is RecoveryPrepareResult.Ok)
        // LocalRecoveryFs replaces the fixture directory; production RootRecoveryFs retains credentials.
        root.resolve("identity.json").writeText(identity.toJson())
        bootSession(root)
        val readiness = readiness(root)
        var commands = 0
        val uninstall = DaemonManagerUninstall(bundle, RecoveryCommandRunner {
            commands++
            RecoveryCommandResult(0, "MAPLESU_MANAGER_UNINSTALL ABSENT uid=10489 data=retained\n")
        }, hidden = { true }, recoveryReady = readiness::ready)
        assertEquals("""{"ok":true,"state":"absent","data":"retained"}""", uninstall.uninstall())
        assertEquals(1, commands)
        currentBoot = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        assertTrue(uninstall.uninstall().contains("MANAGER_FULL_RESTORE_UNAVAILABLE"))
        assertEquals(1, commands)
    }

    @Test fun currentBootSessionDoesNotDependOnAnOldPermanentRootkey() {
        val root = recovery()
        bootSession(root)
        root.resolve("rootkey").writeText("stale")
        assertTrue(readiness(root).ready())
    }

    @Test fun permanentRecoveryStillRequiresMatchingIdentityAndAReadableSdk() {
        val root = recovery()
        root.resolve("rootkey").writeText(requireNotNull(UltraRecoveryKey.seal(key, identity.androidId, pkg)))
        val readiness = readiness(root)
        assertTrue(readiness.ready())
        readableSdk = false
        assertFalse(readiness.ready())
        assertEquals(2, runtimeChecks)
        root.resolve("rootkey").writeText("corrupt")
        assertFalse(readiness.ready())
        assertEquals(2, runtimeChecks)
    }

    @Test fun expiredBootSessionNeverSelectsAValidPermanentKey() {
        val root = recovery()
        bootSession(root)
        root.resolve("rootkey").writeText(requireNotNull(UltraRecoveryKey.seal(key, identity.androidId, pkg)))
        currentBoot = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        assertFalse(readiness(root).ready())
        assertEquals(0, runtimeChecks)
        assertEquals(0, sdkLoads)
    }

    @Test fun unreadableOrCorruptSessionNeverSelectsAValidPermanentKey() {
        val root = recovery()
        root.resolve("rootkey").writeText(requireNotNull(UltraRecoveryKey.seal(key, identity.androidId, pkg)))
        bootSession(root)
        privateMaterial = false
        assertFalse(readiness(root).ready())
        privateMaterial = true
        root.resolve(UltraBootSdkRecovery.FILE_NAME).writeText("corrupt")
        assertFalse(readiness(root).ready())
        assertEquals(0, runtimeChecks)
        assertEquals(0, sdkLoads)
    }

    @Test fun liveSessionIsRevalidatedAfterTheSdkWasOpened() {
        val root = recovery()
        bootSession(root)
        // Keep a valid permanent key beside it to catch accidental fallback after expiry.
        root.resolve("rootkey").writeText(requireNotNull(UltraRecoveryKey.seal(key, identity.androidId, pkg)))
        val readiness = readiness(root)
        assertTrue(readiness.ready())
        currentBoot = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        assertFalse(readiness.ready())
        assertEquals(1, runtimeChecks)
    }

    @Test fun bootSessionStillRequiresCurrentManagerIdentityAndLiveRuntime() {
        val root = recovery()
        bootSession(root)
        readableSdk = false
        assertFalse(readiness(root).ready())
        assertEquals(1, runtimeChecks)
        readableSdk = true
        root.resolve("identity.json").writeText(requireNotNull(RecoveryIdentity.of(identity.androidId, "dev.other.manager", 10489)).toJson())
        assertFalse(readiness(root).ready())
        assertEquals(1, runtimeChecks)
    }

    @Test fun explicitPermanentPreparationReleasesExpiredSessionAndKeepsPermanentMaterial() {
        val root = recovery()
        bootSession(root)
        currentBoot = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        val permanent = requireNotNull(UltraRecoveryKey.seal(key, identity.androidId, pkg))
        val readiness = readiness(root)
        var backedUp = false
        val runner = shell(root) { assertTrue("backup must be verified before handoff", backedUp) }
        // An expired session must not silently select the permanent key.
        root.resolve("rootkey").writeText(permanent)
        assertFalse(readiness.ready())
        assertTrue(preparePermanentHiddenRecovery(runner) { backedUp = true; true })
        assertTrue("explicit verified permanent preparation must unblock the daemon", readiness.ready())
        assertFalse(root.resolve(UltraBootSdkRecovery.FILE_NAME).exists())
        assertEquals(permanent, root.resolve("rootkey").readText())
        assertEquals(identity.toJson(), root.resolve("identity.json").readText())
        assertTrue(preparePermanentHiddenRecovery(runner) { true })
        assertTrue(readiness.ready())
    }

    @Test fun failedPermanentBackupKeepsTheSessionAndNeverSubmitsHandoff() {
        val root = recovery()
        bootSession(root)
        val original = root.resolve(UltraBootSdkRecovery.FILE_NAME).readText()
        val runner = HiddenRootRunner { error("handoff must not run after a failed backup") }
        assertFalse(preparePermanentHiddenRecovery(runner) { false })
        assertEquals(original, root.resolve(UltraBootSdkRecovery.FILE_NAME).readText())
    }

    @Test fun failedOrUnconfirmedPermanentHandoffDoesNotReportReady() {
        for (result in listOf(RecoveryCommandResult(1, ""), RecoveryCommandResult(0, ""),
                              RecoveryCommandResult(-1, "ROOT_EXECUTION_BUSY"))) {
            assertFalse(preparePermanentHiddenRecovery(HiddenRootRunner { result }) { true })
        }
    }

    @Test fun aDirectoryAtTheSessionPathIsPreservedAndBlocksHandoff() {
        val root = recovery()
        root.resolve(UltraBootSdkRecovery.FILE_NAME).mkdir()
        root.resolve("${UltraBootSdkRecovery.FILE_NAME}/sentinel").writeText("keep")
        assertFalse(preparePermanentHiddenRecovery(shell(root)) { true })
        assertEquals("keep", root.resolve("${UltraBootSdkRecovery.FILE_NAME}/sentinel").readText())
    }

    private fun shell(root: File, beforeRun: () -> Unit = {}): HiddenRootRunner {
        val bash = if (System.getProperty("os.name").startsWith("Windows"))
            File("C:/Program Files/Git/bin/bash.exe") else File("/bin/bash")
        assumeTrue("Bash is required for the real handoff script", bash.isFile)
        return HiddenRootRunner { script ->
            beforeRun()
            val path = root.resolve(UltraBootSdkRecovery.FILE_NAME).absolutePath.replace('\\', '/')
                .replace("'", "'\\''")
            val process = ProcessBuilder(bash.path, "--noprofile", "--norc", "-c",
                script.replace(UltraBootSdkRecovery.PATH, path)).redirectErrorStream(true).start()
            if (!process.waitFor(10, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                error("handoff script timed out")
            }
            RecoveryCommandResult(process.exitValue(), process.inputStream.bufferedReader().use { it.readText() })
        }
    }
}
