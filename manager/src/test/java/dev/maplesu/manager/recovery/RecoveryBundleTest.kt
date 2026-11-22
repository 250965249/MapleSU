package dev.maplesu.manager.recovery

import dev.maplesu.manager.workmode.Hashes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/** 真实卸载前恢复备份：逐项 sha 读回、manifest 完整性、失败 fail-closed。 */
class RecoveryBundleTest {
    private fun tempDir(): File = Files.createTempDirectory("maplesu-recovery-").toFile()

    private fun bundle(dir: File = tempDir(), policy: (String) -> Boolean = { true }) =
        RecoveryBundle(LocalRecoveryFs(), dir.absolutePath, { 1_000L }, policy)

    private fun sourceFile(name: String, content: ByteArray = byteArrayOf(1, 2, 3)): File =
        File(tempDir(), name).apply { writeBytes(content) }

    private fun prepare(
        dir: File = tempDir(),
        extras: List<RecoverySource> = listOf(
            RecoverySource("ASSET", sourceFile("index.html").absolutePath, "assets/liteweb/index.html"),
        ),
        config: ByteArray? = "port=18437\ntoken=0123456789abcdef".toByteArray(),
    ): Pair<RecoveryBundle, RecoveryPrepareResult> {
        val bundle = bundle(dir)
        val apk = sourceFile("base.apk", ByteArray(2048) { it.toByte() })
        val result = bundle.prepare("dev.maplesu.manager", 42, apk.absolutePath, extras, config)
        return bundle to result
    }

    @Test
    fun prepareWritesApkAssetsConfigAndManifestWithReadback() {
        val dir = tempDir()
        val (bundle, result) = prepare(dir)
        assertTrue(result is RecoveryPrepareResult.Ok)
        val manifest = (result as RecoveryPrepareResult.Ok).manifest
        assertEquals("dev.maplesu.manager", manifest.packageName)
        assertEquals(42L, manifest.versionCode)
        assertEquals(64, manifest.apkSha256.length)
        assertEquals(2048L, manifest.apkSize)
        assertTrue(File(dir, "manager.apk").isFile)
        assertTrue(File(dir, "assets/liteweb/index.html").isFile)
        assertTrue(File(dir, "webui.conf").isFile)
        assertTrue(File(dir, "manifest.json").isFile)
        assertTrue(bundle.verify().ok)
    }

    @Test
    fun manifestItemsCoverEveryFileAndConfig() {
        val (bundle, result) = prepare()
        val manifest = (result as RecoveryPrepareResult.Ok).manifest
        assertEquals(
            listOf("APK", "ASSET", "WEBUI_CONFIG"),
            manifest.items.map { it.role }.sorted(),
        )
        assertTrue(manifest.items.all { it.sha256.length == 64 && it.size > 0 })
        assertTrue(bundle.verify().ok)
    }

    @Test
    fun tamperedBackupFailsVerificationAndBlocksUse() {
        val dir = tempDir()
        val (bundle, result) = prepare(dir)
        assertTrue(result is RecoveryPrepareResult.Ok)
        File(dir, "manager.apk").writeBytes(ByteArray(2048) { 9 })
        val verification = bundle.verify()
        assertFalse(verification.ok)
        assertEquals(RecoveryCodes.VERIFY_FAILED, verification.code)
        assertTrue(verification.problems.any { it.startsWith("sha:manager.apk") })
    }

    @Test
    fun corruptManifestFailsClosed() {
        val dir = tempDir()
        val (bundle, result) = prepare(dir)
        assertTrue(result is RecoveryPrepareResult.Ok)
        File(dir, "manifest.json").writeText("{broken")
        val verification = bundle.verify()
        assertFalse(verification.ok)
        assertEquals(RecoveryCodes.MANIFEST_CORRUPT, verification.code)
    }

    @Test
    fun manifestIntegrityMismatchDetectedAfterFieldChange() {
        val dir = tempDir()
        val (bundle, result) = prepare(dir)
        val manifest = (result as RecoveryPrepareResult.Ok).manifest
        val tampered = manifest.copy(packageName = "dev.evil")
        File(dir, "manifest.json").writeText(
            kotlinx.serialization.json.Json { encodeDefaults = true }
                .encodeToString(RecoveryManifest.serializer(), tampered),
        )
        val verification = bundle.verify()
        assertFalse(verification.ok)
        assertEquals(RecoveryCodes.MANIFEST_CORRUPT, verification.code)
        assertTrue(verification.problems.contains("integrity"))
    }

    @Test
    fun missingSourceFailsWithoutLeavingManifest() {
        val dir = tempDir()
        val bundle = bundle(dir)
        val result = bundle.prepare(
            "dev.maplesu.manager", 1, File(dir, "missing.apk").absolutePath, emptyList(), null,
        )
        assertEquals(RecoveryCodes.SOURCE_UNREADABLE, (result as RecoveryPrepareResult.Failed).code)
        assertFalse(File(dir, "manifest.json").exists())
    }

    @Test
    fun insecureLocationIsRejectedBeforeAnyWrite() {
        val dir = tempDir()
        val result = bundle(dir, policy = { false }).prepare(
            "dev.maplesu.manager", 1, sourceFile("base.apk").absolutePath, emptyList(), null,
        )
        assertEquals(RecoveryCodes.LOCATION_INSECURE, (result as RecoveryPrepareResult.Failed).code)
        assertFalse(File(dir, "manifest.json").exists())
    }

    @Test
    fun prepareIsAtomicAcrossRepeatedRuns() {
        val dir = tempDir()
        val bundle = bundle(dir)
        val apk = sourceFile("base.apk")
        val first = bundle.prepare("dev.maplesu.manager", 1, apk.absolutePath, emptyList(), null)
        assertTrue(first is RecoveryPrepareResult.Ok)
        val second = bundle.prepare("dev.maplesu.manager", 2, apk.absolutePath, emptyList(), null)
        assertTrue(second is RecoveryPrepareResult.Ok)
        assertEquals(2L, (second as RecoveryPrepareResult.Ok).manifest.versionCode)
        assertTrue(bundle.verify().ok)
    }
}
