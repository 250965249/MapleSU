package dev.maplesu.manager.workmode.snapshot

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.control.ControlPaths
import dev.maplesu.manager.workmode.control.schema.AppSnapshotFacts
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.superuser.RootScriptRunner
import dev.maplesu.manager.workmode.superuser.RootScriptResult
import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import dev.maplesu.manager.workmode.switch.ModeSwitchRequest
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.UUID

/** P0：S1 快照写控制面（清数据不丢）+ 真实回滚恢复；主机 fake 桥使用临时目录。 */
class ControlPlaneModeSwitchSnapshotsTest {
    private lateinit var appDir: File
    private lateinit var stagingRoot: File
    private lateinit var controlRoot: File
    private val clock = Clock { 1_000L }
    private val boot = BootIdSource { "boot-1" }

    private class FakeBridge(private val controlRoot: File) : ControlPlaneSnapshotBridge {
        var available = true
        private fun resolve(path: String): File =
            File(controlRoot, path.removePrefix(ControlPaths.ROOT).trimStart('/'))

        override fun controlPlaneAvailable(): Boolean = available

        override fun listSnapshotRevisions(mode: WorkMode): List<Long>? {
            val directory = File(controlRoot, "snapshots/${mode.suffix}")
            if (!directory.isDirectory) return emptyList()
            return directory.listFiles().orEmpty().mapNotNull { file ->
                Regex("^rev-(\\d+)-${mode.suffix}$").find(file.name)?.groupValues?.get(1)?.toLongOrNull()
            }.sorted()
        }

        override fun publishSnapshot(localSnapshotDir: File, destination: String, expectedManifestSha256: String): Boolean {
            val manifest = File(localSnapshotDir, "manifest.json")
            if (!manifest.isFile) return false
            if (Hashes.sha256(manifest.readBytes()) != expectedManifestSha256) return false
            val target = resolve(destination)
            target.deleteRecursively()
            return localSnapshotDir.copyRecursively(target, overwrite = true)
        }

        override fun materializeSnapshot(source: String, localSnapshotDir: File): Boolean {
            val origin = resolve(source)
            if (!File(origin, "manifest.json").isFile) return false
            localSnapshotDir.deleteRecursively()
            return origin.copyRecursively(localSnapshotDir, overwrite = true)
        }
    }

    @Before
    fun setUp() {
        appDir = tempDirectory("snapshot-cp-app")
        stagingRoot = tempDirectory("snapshot-cp-staging")
        controlRoot = tempDirectory("snapshot-cp-control")
        File(appDir, "wallpaper").mkdirs()
        File(appDir, "wallpaper/a.png").writeBytes(byteArrayOf(1, 2, 3))
    }

    /**
     * 自包含的 app facts（不借用 `TestFixtures`）：本类的 9 个写/恢复用例都依赖它，
     * 跨域共享 fixture 若在并发构建中被其他 agent 改动，会把本类变成"全红"。
     */
    private fun appFacts() = AppSnapshotFacts(
        packageName = "dev.maplesu.manager",
        versionCode = 1,
        apkSha256 = "a".repeat(64),
        signerSha256 = listOf("b".repeat(64)),
        settingsRevision = 3,
        appPrefsRevision = 3,
    )

    private fun tempDirectory(prefix: String): File =
        Files.createTempDirectory("maplesu-$prefix").toFile()

    private fun snapshots(bridge: ControlPlaneSnapshotBridge = FakeBridge(controlRoot)) =
        ControlPlaneModeSwitchSnapshots(
            appDir = appDir,
            stagingRoot = stagingRoot,
            bridge = bridge,
            appFactsProvider = { appFacts() },
            clock = clock,
            bootIdSource = boot,
        )

    private fun request() = ModeSwitchRequest(
        switchId = UUID.randomUUID().toString(),
        fromMode = WorkMode.LITE,
        toMode = WorkMode.KSU,
        baselineId = "bl-1",
    )

    @Test
    fun preSwitchPublishesToControlPlaneAndCleansStaging() = runBlocking {
        val request = request()
        val outcome = snapshots().preSwitchSnapshot(request)
        assertTrue("outcome=$outcome", outcome.ok)
        val published = File(controlRoot, "snapshots/A/rev-1-A")
        assertTrue(File(published, "manifest.json").isFile)
        assertTrue(File(published, "payload/app/wallpaper/a.png").isFile)
        assertFalse("staging must be cleaned", File(stagingRoot, "switch-${request.switchId}").exists())
    }

    @Test
    fun controlPlaneUnavailableFailsClosedAndDoesNotFallBackToFilesDir() = runBlocking {
        val bridge = FakeBridge(controlRoot).apply { available = false }
        val outcome = snapshots(bridge).preSwitchSnapshot(request())
        assertFalse(outcome.ok)
        assertEquals(ModeSwitchCodes.SNAPSHOT_FAILED, outcome.code)
        assertFalse(File(appDir, "workmode/snapshots").exists())
        assertFalse(File(controlRoot, "snapshots").exists())
    }

    @Test
    fun appFactsUnknownFailsClosed() = runBlocking {
        val service = ControlPlaneModeSwitchSnapshots(
            appDir, stagingRoot, FakeBridge(controlRoot), { null }, clock, boot,
        )
        val outcome = service.preSwitchSnapshot(request())
        assertFalse(outcome.ok)
        assertEquals(ModeSwitchCodes.SNAPSHOT_FAILED, outcome.code)
    }

    @Test
    fun revisionIncrementsAcrossSwitches() = runBlocking {
        val service = snapshots()
        assertTrue(service.preSwitchSnapshot(request()).ok)
        assertTrue(service.preSwitchSnapshot(request()).ok)
        val revisions = FakeBridge(controlRoot).listSnapshotRevisions(WorkMode.LITE)
        assertEquals(listOf(1L, 2L), revisions)
        assertTrue(File(controlRoot, "snapshots/A/rev-2-A/manifest.json").isFile)
    }

    @Test
    fun restoreAfterRollbackRestoresDeletedFile() = runBlocking {
        val service = snapshots()
        val request = request()
        assertTrue(service.preSwitchSnapshot(request).ok)
        File(appDir, "wallpaper/a.png").delete()

        val outcome = service.restoreAfterRollback(request)
        assertTrue("outcome=$outcome", outcome.ok)
        assertTrue(File(appDir, "wallpaper/a.png").isFile)
        assertEquals(3, File(appDir, "wallpaper/a.png").readBytes().size)
    }

    @Test
    fun missingSnapshotFailsWithRestoreFailedCode() = runBlocking {
        val outcome = snapshots().restoreAfterRollback(request())
        assertFalse(outcome.ok)
        assertEquals(ControlPlaneModeSwitchSnapshots.SNAPSHOT_RESTORE_FAILED, outcome.code)
    }

    @Test
    fun corruptControlPlaneSnapshotFailsInsteadOfPretendingSuccess() = runBlocking {
        val service = snapshots()
        val request = request()
        assertTrue(service.preSwitchSnapshot(request).ok)
        File(controlRoot, "snapshots/A/rev-1-A/manifest.json").writeText("{ tampered")
        val outcome = service.restoreAfterRollback(request)
        assertFalse("corrupt snapshot must not be reported as success", outcome.ok)
        assertEquals(ControlPlaneModeSwitchSnapshots.SNAPSHOT_RESTORE_FAILED, outcome.code)
    }

    @Test
    fun restoreForRollbackReportsBlockersOnMissing() = runBlocking {
        val result = snapshots().restoreForRollback(WorkMode.LITE)
        assertTrue(result.blockers.contains(SnapshotErrors.SNAPSHOT_NOT_FOUND) ||
            result.blockers.contains(ControlPlaneModeSwitchSnapshots.SNAPSHOT_RESTORE_FAILED))
    }

    @Test
    fun rootBridgePublishScriptIsAtomicAndVerifiesSha() {
        val local = tempDirectory("snapshot-publish-local")
        File(local, "manifest.json").writeText("{}")
        val sha = Hashes.sha256(File(local, "manifest.json").readBytes())
        val scripts = mutableListOf<String>()
        val runner = RootScriptRunner { script ->
            scripts += script
            RootScriptResult(0, "PUBLISHED:$sha\n")
        }
        val bridge = RootScriptSnapshotBridge(runner)
        assertTrue(
            bridge.publishSnapshot(local, "${ControlPaths.SNAPSHOTS}/A/rev-1-A", sha),
        )
        val script = scripts.last()
        assertTrue(script.contains("chown -R 0:0"))
        assertTrue(script.contains("chmod 0600"))
        assertTrue(script.contains("mktemp -d"))
        assertTrue(script.contains("mv "))
        assertTrue(script.contains(sha))
        assertFalse(script.contains("filesDir"))
    }

    @Test
    fun rootBridgeAvailabilityUsesControlPlaneWritability() {
        var code = 1
        val bridge = RootScriptSnapshotBridge(RootScriptRunner { RootScriptResult(code, "") })
        assertFalse(bridge.controlPlaneAvailable())
        code = 0
        assertTrue(bridge.controlPlaneAvailable())
    }
}
