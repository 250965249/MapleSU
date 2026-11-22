package dev.maplesu.manager.parasite

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.detect.Clock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/** 私有恢复备份：清单完整性/读回校验/只从备份恢复/失败阻断。 */
class ParasiteRecoveryStoreTest {
    private val clock = Clock { 1_000L }

    private class FailingOps(
        private val delegate: RecoveryFileOps = RealRecoveryFileOps(),
        private val failWrite: (File) -> Boolean = { false },
    ) : RecoveryFileOps by delegate {
        override fun write(file: File, bytes: ByteArray): Boolean =
            if (failWrite(file)) false else delegate.write(file, bytes)
    }

    private fun tempDir(): File = Files.createTempDirectory("maplesu-parasite-recovery-").toFile()

    private fun store(
        root: File,
        ops: RecoveryFileOps = RealRecoveryFileOps(),
        policy: (File) -> Boolean = { true },
    ) = ParasiteRecoveryStore(root = root, ops = ops, clock = clock, locationPolicy = policy)

    private fun sourceDirectory(): File = Files.createTempDirectory("maplesu-parasite-src-").toFile()

    private fun sources(directory: File): List<RecoverySource> {
        val apk = File(directory, "base.apk").apply { writeBytes(byteArrayOf(1, 2, 3, 4)) }
        val config = File(directory, "settings.json").apply { writeText("{\"ui\":\"dark\"}") }
        return listOf(
            RecoverySource("APK", apk, "apk/base.apk", mode = 0x1A4, uid = 10_100, gid = 10_100),
            RecoverySource("CONFIG", config, "config/settings.json"),
        )
    }

    @Test
    fun backupWritesPayloadManifestAndReadsBack() {
        val root = tempDir()
        val result = store(root).backup("reg-1", "com.example.host", "v1", sources(sourceDirectory()), "bk-1")
        assertTrue(result is RecoveryBackupResult.Ok)
        val manifest = (result as RecoveryBackupResult.Ok).manifest
        assertEquals(2, manifest.files.size)
        assertEquals(64, manifest.integritySha256.length)
        val manifestFile = File(root, "bk-1/manifest.json")
        assertTrue(manifestFile.isFile)
        assertEquals(
            dev.maplesu.manager.workmode.control.ShaCheck.OK,
            AtomicControlFile.verifySha(manifestFile),
        )
        val payload = File(root, "bk-1/files/apk/base.apk")
        assertEquals(4, payload.readBytes().size)
        assertTrue(store(root).verify("bk-1").ok)
    }

    @Test
    fun tamperedPayloadIsDetectedAndBlocksRestore() {
        val root = tempDir()
        store(root).backup("reg-1", "com.example.host", "v1", sources(sourceDirectory()), "bk-1")
        File(root, "bk-1/files/config/settings.json").writeText("{\"ui\":\"tampered\"}")
        val verification = store(root).verify("bk-1")
        assertFalse(verification.ok)
        assertEquals(ParasiteRecoveryCodes.SHA_MISMATCH, verification.code)
        assertTrue(verification.problems.any { it.startsWith("sha:") })

        val target = tempDir()
        val restore = store(root).restore("bk-1", target)
        assertFalse(restore.ok)
        assertEquals(ParasiteRecoveryCodes.RECOVERY_VERIFICATION_FAILED, restore.code)
        assertFalse(File(target, "config/settings.json").exists())
    }

    @Test
    fun corruptManifestBlocksRestore() {
        val root = tempDir()
        store(root).backup("reg-1", "com.example.host", "v1", sources(sourceDirectory()), "bk-1")
        File(root, "bk-1/manifest.json").writeText("{ corrupt")
        val verification = store(root).verify("bk-1")
        assertFalse(verification.ok)
        assertEquals(ParasiteRecoveryCodes.MANIFEST_CORRUPT, verification.code)
        assertFalse(store(root).restore("bk-1", tempDir()).ok)
    }

    @Test
    fun integrityMismatchIsDetectedEvenWithValidShaSibling() {
        val root = tempDir()
        val backed = store(root).backup("reg-1", "com.example.host", "v1", sources(sourceDirectory()), "bk-1")
        val manifest = (backed as RecoveryBackupResult.Ok).manifest
        val tampered = manifest.copy(hostPackage = "com.example.evil")
        val manifestFile = File(root, "bk-1/manifest.json")
        AtomicControlFile.writeJson(
            manifestFile,
            ControlJsonCodec.encode(tampered, ParasiteRecoveryManifest.serializer()),
        )
        val verification = store(root).verify("bk-1")
        assertFalse(verification.ok)
        assertEquals(ParasiteRecoveryCodes.MANIFEST_CORRUPT, verification.code)
        assertTrue(verification.problems.any { it.contains("integrity") })
    }

    @Test
    fun insecureLocationFailsClosed() {
        val root = tempDir()
        val result = store(root, policy = { false })
            .backup("reg-1", "com.example.host", "v1", sources(sourceDirectory()), "bk-1")
        assertFalse(result is RecoveryBackupResult.Ok)
        assertEquals(ParasiteRecoveryCodes.LOCATION_INSECURE, (result as RecoveryBackupResult.Failed).code)
        assertFalse(File(root, "bk-1").exists())
    }

    @Test
    fun emptySourcesAndTraversalAreRejected() {
        val root = tempDir()
        assertEquals(
            ParasiteRecoveryCodes.BACKUP_EMPTY,
            (store(root).backup("reg-1", "host", "v1", emptyList(), "bk-1") as RecoveryBackupResult.Failed).code,
        )
        val traversal = listOf(
            RecoverySource("CONFIG", File(sourceDirectory(), "x").apply { writeText("x") }, "../evil.json"),
        )
        val result = store(root).backup("reg-1", "host", "v1", traversal, "bk-1") as RecoveryBackupResult.Failed
        assertEquals(ParasiteRecoveryCodes.RELATIVE_PATH_INVALID, result.code)
        assertFalse(File(root, "bk-1").exists())
    }

    @Test
    fun restoreOnlyUsesBackupAndReadsBack() {
        val source = sourceDirectory()
        val root = tempDir()
        store(root).backup("reg-1", "com.example.host", "v1", sources(source), "bk-1")
        // 源文件事后被改：恢复必须得到备份时的内容。
        File(source, "settings.json").writeText("{\"ui\":\"changed-after-backup\"}")
        val target = tempDir()
        val restore = store(root).restore("bk-1", target)
        assertTrue(restore.ok)
        assertEquals("{\"ui\":\"dark\"}", File(target, "config/settings.json").readText())
        assertTrue(restore.restored.contains("config/settings.json"))
    }

    @Test
    fun partialRestoreFailureIsNotSuccess() {
        val root = tempDir()
        store(root).backup("reg-1", "com.example.host", "v1", sources(sourceDirectory()), "bk-1")
        val ops = FailingOps(failWrite = { file -> file.path.contains("config") })
        val target = tempDir()
        val restore = store(root, ops).restore("bk-1", target)
        assertFalse(restore.ok)
        assertEquals(ParasiteRecoveryCodes.RESTORE_FAILED, restore.code)
        assertTrue(restore.failed.any { it.contains("config") })
        assertTrue(restore.restored.any { it.contains("apk") })
    }

    @Test
    fun previousVerifiedBackupSurvivesFailedNewBackup() {
        val root = tempDir()
        val source = sourceDirectory()
        assertTrue(store(root).backup("reg-1", "host", "v1", sources(source), "bk-1") is RecoveryBackupResult.Ok)
        val failing = FailingOps(failWrite = { file -> file.path.contains("config") })
        val second = store(root, failing).backup("reg-1", "host", "v2", sources(source), "bk-2")
        assertFalse(second is RecoveryBackupResult.Ok)
        assertFalse("partial new backup must be cleaned", File(root, "bk-2").exists())
        assertTrue(store(root).verify("bk-1").ok)
        assertEquals(listOf("bk-1"), store(root).list().map { it.backupId })
    }

    @Test
    fun missingBackupVerificationIsStructured() {
        val verification = store(tempDir()).verify("nope")
        assertFalse(verification.ok)
        assertEquals(ParasiteRecoveryCodes.RECOVERY_MISSING, verification.code)
        val restore = store(tempDir()).restore("nope", tempDir())
        assertFalse(restore.ok)
        assertEquals(ParasiteRecoveryCodes.RECOVERY_VERIFICATION_FAILED, restore.code)
    }

    @Test
    fun manifestEntriesCarryIntegrityMetadata() {
        val root = tempDir()
        val result = store(root).backup("reg-1", "com.example.host", "v1", sources(sourceDirectory()), "bk-1")
        val manifest = (result as RecoveryBackupResult.Ok).manifest
        val apk = manifest.files.first { it.role == "APK" }
        assertEquals("apk/base.apk", apk.relativePath)
        assertEquals(4L, apk.size)
        assertEquals(0x1A4, apk.mode)
        assertEquals(10_100, apk.uid)
        assertEquals(Hashes.sha256(byteArrayOf(1, 2, 3, 4)), apk.sha256)
    }
}
