package dev.maplesu.manager.liteweb.daemon

import java.io.File
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** APK extraction fixtures only; no JNI, root command, credentials or device. */
class DaemonSdkLibraryTest {
    @get:Rule val temporary = TemporaryFolder()

    private fun apk(root: File, entries: Map<String, ByteArray>, name: String = "manager.apk"): File {
        val file = File(root, name)
        ZipOutputStream(file.outputStream()).use { zip ->
            entries.forEach { (name, bytes) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        return file
    }

    private fun access(root: File) = DaemonUltraSdkAccess(
        shell = { error("extraction must not execute a shell") },
        recoveryRoot = root.absolutePath,
        loadSdk = { error("extraction must not load native code") },
    )

    @Test
    fun packagedArm64V8aLibraryAndSiblingDependenciesAreExtracted() {
        val root = temporary.newFolder()
        val sdk = byteArrayOf(1, 2, 3, 4)
        val dependency = byteArrayOf(5, 6)
        apk(root, mapOf(
            "lib/arm64-v8a/libmaplesu_ultra_bridge.so" to sdk,
            "lib/arm64-v8a/libdependency.so" to dependency,
            "lib/x86_64/libmaplesu_ultra_bridge.so" to byteArrayOf(9),
        ))
        val path = access(root).ensureSdkLibrary()
        assertEquals(File(root, "native/libmaplesu_ultra_bridge.so").absolutePath, path)
        assertArrayEquals(sdk, File(requireNotNull(path)).readBytes())
        assertArrayEquals(dependency, File(root, "native/libdependency.so").readBytes())
    }

    @Test
    fun unrelatedLibrariesBeforeSdkCannotExhaustItsExtractionBudget() {
        val root = temporary.newFolder()
        val sdk = ByteArray(9 * 1024 * 1024) { 7 }
        apk(root, linkedMapOf(
            "lib/arm64-v8a/libmaplesu_patch.so" to ByteArray(13 * 1024 * 1024),
            "lib/arm64-v8a/libmaplesu_policy.so" to ByteArray(14 * 1024 * 1024),
            "lib/arm64-v8a/libmaplesu_policy_boot.so" to ByteArray(13 * 1024 * 1024),
            "lib/arm64-v8a/libmaplesu_ultra_bridge.so" to sdk,
        ))

        val path = access(root).ensureSdkLibrary()
        assertEquals(File(root, "native/libmaplesu_ultra_bridge.so").absolutePath, path)
        assertArrayEquals(sdk, File(requireNotNull(path)).readBytes())
    }

    @Test
    fun deliveredManagerApkHasAnExtractableRecoverySdk() {
        val source = System.getProperty("maplesu.test.parasite.apk")
        assumeTrue("pass --apk to verify a delivered APK", source != null)
        val root = temporary.newFolder()
        File(requireNotNull(source)).copyTo(File(root, "manager.apk"))
        val path = access(root).ensureSdkLibrary()
        assertEquals(File(root, "native/libmaplesu_ultra_bridge.so").absolutePath, path)
        java.util.zip.ZipFile(source).use { zip ->
            val entry = requireNotNull(zip.getEntry("lib/arm64-v8a/libmaplesu_ultra_bridge.so"))
            assertArrayEquals(zip.getInputStream(entry).use { it.readBytes() }, File(requireNotNull(path)).readBytes())
        }
    }

    @Test
    fun wrongAbiAndNestedEntriesDoNotMasqueradeAsArm64V8a() {
        val root = temporary.newFolder()
        apk(root, mapOf(
            "lib/arm64/libmaplesu_ultra_bridge.so" to byteArrayOf(1),
            "lib/armeabi-v7a/libmaplesu_ultra_bridge.so" to byteArrayOf(2),
            "lib/arm64-v8a/nested/libmaplesu_ultra_bridge.so" to byteArrayOf(3),
            "lib/arm64-v8a/../libmaplesu_ultra_bridge.so" to byteArrayOf(4),
        ))
        assertNull(access(root).ensureSdkLibrary())
        assertFalse(File(root, "native").exists())
        assertFalse(File(root, "libmaplesu_ultra_bridge.so").exists())
    }

    @Test
    fun existingRecoveryLibraryDoesNotNeedTheOriginalInstalledApk() {
        val root = temporary.newFolder()
        val library = File(root, "native/libmaplesu_ultra_bridge.so")
        Files.createDirectories(requireNotNull(library.parentFile).toPath())
        library.writeBytes(byteArrayOf(7, 8))
        assertEquals(library.absolutePath, access(root).ensureSdkLibrary())
        assertFalse(File(root, "manager.apk").exists())
    }

    @Test
    fun updatedRecoveryApkReplacesCachedSdkAndItsDependencies() {
        val root = temporary.newFolder()
        val library = File(root, "native/libmaplesu_ultra_bridge.so")
        Files.createDirectories(requireNotNull(library.parentFile).toPath())
        library.writeBytes(byteArrayOf(7, 8))
        val dependency = File(root, "native/libdependency.so")
        dependency.writeBytes(byteArrayOf(9))
        apk(root, mapOf(
            "lib/arm64-v8a/libmaplesu_ultra_bridge.so" to byteArrayOf(1, 2),
            "lib/arm64-v8a/libdependency.so" to byteArrayOf(3, 4),
        ))

        assertEquals(library.absolutePath, access(root).ensureSdkLibrary())
        assertArrayEquals(byteArrayOf(1, 2), library.readBytes())
        assertArrayEquals(byteArrayOf(3, 4), dependency.readBytes())
    }

    @Test
    fun brokenRecoveryApkDoesNotFallBackToAnUnverifiedCachedSdk() {
        val root = temporary.newFolder()
        val library = File(root, "native/libmaplesu_ultra_bridge.so")
        Files.createDirectories(requireNotNull(library.parentFile).toPath())
        library.writeBytes(byteArrayOf(7, 8))
        File(root, "manager.apk").writeText("invalid backup")

        assertNull(access(root).ensureSdkLibrary())
        assertArrayEquals(byteArrayOf(7, 8), library.readBytes())
    }

    @Test
    fun oversizedPackagedSdkDoesNotReturnAnOlderCachedLibrary() {
        val root = temporary.newFolder()
        val library = File(root, "native/libmaplesu_ultra_bridge.so")
        Files.createDirectories(requireNotNull(library.parentFile).toPath())
        library.writeBytes(byteArrayOf(7, 8))
        apk(root, mapOf(
            "lib/arm64-v8a/libmaplesu_ultra_bridge.so" to ByteArray(16 * 1024 * 1024 + 1),
        ))

        assertNull(access(root).ensureSdkLibrary())
        assertArrayEquals(byteArrayOf(7, 8), library.readBytes())
    }

    @Test
    fun currentClasspathApkAlsoReplacesAnOlderCachedSdk() {
        val root = temporary.newFolder()
        val library = File(root, "native/libmaplesu_ultra_bridge.so")
        Files.createDirectories(requireNotNull(library.parentFile).toPath())
        library.writeBytes(byteArrayOf(7, 8))
        val source = apk(temporary.newFolder(), mapOf(
            "lib/arm64-v8a/libmaplesu_ultra_bridge.so" to byteArrayOf(1, 3, 5),
        ), "base.apk")

        assertEquals(library.absolutePath, access(root).ensureSdkLibrary(listOf(source.absolutePath)))
        assertArrayEquals(byteArrayOf(1, 3, 5), library.readBytes())
        assertFalse(File(root, "manager.apk").exists())
    }

    @Test
    fun missingRecoveryApkUsesOnlyTheCurrentClasspathApk() {
        val root = temporary.newFolder()
        val source = apk(temporary.newFolder(), mapOf(
            "lib/arm64-v8a/libmaplesu_ultra_bridge.so" to byteArrayOf(1, 3, 5),
            "lib/arm64-v8a/libdependency.so" to byteArrayOf(2, 4, 6),
        ), "base.apk")
        val path = access(root).ensureSdkLibrary(listOf(source.absolutePath))
        assertEquals(File(root, "native/libmaplesu_ultra_bridge.so").absolutePath, path)
        assertArrayEquals(byteArrayOf(1, 3, 5), File(requireNotNull(path)).readBytes())
        assertArrayEquals(byteArrayOf(2, 4, 6), File(root, "native/libdependency.so").readBytes())
        assertFalse(File(root, "manager.apk").exists())
        assertFalse(source.length() == 0L)
    }

    @Test
    fun recoveryApkWinsOverTheCurrentClasspathApk() {
        val root = temporary.newFolder()
        apk(root, mapOf("lib/arm64-v8a/libmaplesu_ultra_bridge.so" to byteArrayOf(9)))
        val source = apk(temporary.newFolder(), mapOf(
            "lib/arm64-v8a/libmaplesu_ultra_bridge.so" to byteArrayOf(1),
        ), "base.apk")
        val path = access(root).ensureSdkLibrary(listOf(source.absolutePath))
        assertArrayEquals(byteArrayOf(9), File(requireNotNull(path)).readBytes())
    }

    @Test
    fun fallbackRejectsJarsDirectoriesMissingFilesAndRelativePaths() {
        val root = temporary.newFolder()
        val source = apk(temporary.newFolder(), mapOf(
            "lib/arm64-v8a/libmaplesu_ultra_bridge.so" to byteArrayOf(1),
        ), "classes.jar")
        val directory = temporary.newFolder("folder.apk")
        assertNull(access(root).ensureSdkLibrary(listOf(
            source.absolutePath, directory.absolutePath, File(root, "missing.apk").absolutePath,
            "relative-base.apk",
        )))
        assertFalse(File(root, "native").exists())
    }

    @Test
    fun existingBrokenRecoveryApkDoesNotSilentlyUseAnotherSource() {
        val root = temporary.newFolder()
        File(root, "manager.apk").writeText("invalid backup")
        val source = apk(temporary.newFolder(), mapOf(
            "lib/arm64-v8a/libmaplesu_ultra_bridge.so" to byteArrayOf(1),
        ), "base.apk")
        assertNull(access(root).ensureSdkLibrary(listOf(source.absolutePath)))
        assertFalse(File(root, "native").exists())
    }

    @Test
    fun fallbackKeepsTheArm64V8aDirectEntryBoundary() {
        val root = temporary.newFolder()
        val source = apk(temporary.newFolder(), mapOf(
            "lib/arm64/libmaplesu_ultra_bridge.so" to byteArrayOf(1),
            "lib/arm64-v8a/nested/libmaplesu_ultra_bridge.so" to byteArrayOf(2),
            "lib/arm64-v8a/../libmaplesu_ultra_bridge.so" to byteArrayOf(3),
        ), "base.apk")
        assertNull(access(root).ensureSdkLibrary(listOf(source.absolutePath)))
        assertFalse(File(root, "native").exists())
    }

    @Test
    fun fallbackRejectsLibrariesBeyondTheSingleFileLimit() {
        val root = temporary.newFolder()
        val source = apk(temporary.newFolder(), mapOf(
            "lib/arm64-v8a/libmaplesu_ultra_bridge.so" to ByteArray(16 * 1024 * 1024 + 1),
        ), "base.apk")
        assertNull(access(root).ensureSdkLibrary(listOf(source.absolutePath)))
        assertFalse(File(root, "native/libmaplesu_ultra_bridge.so").exists())
    }

    @Test
    fun extractionRejectsDeclaredSizeMismatchWithoutLeavingALoadablePartialFile() {
        val root = temporary.newFolder()
        val source = apk(root, mapOf(
            "lib/arm64-v8a/libmaplesu_ultra_bridge.so" to ByteArray(1024),
        ))
        val zip = source.readBytes()
        val central = (0 until zip.size - 28).first { at ->
            zip[at] == 0x50.toByte() && zip[at + 1] == 0x4b.toByte() &&
                zip[at + 2] == 0x01.toByte() && zip[at + 3] == 0x02.toByte()
        }
        // Corrupt only the central directory's uncompressed size, not its actual deflated bytes.
        repeat(4) { index -> zip[central + 24 + index] = if (index == 0) 1 else 0 }
        source.writeBytes(zip)
        assertNull(access(root).ensureSdkLibrary())
        assertFalse(File(root, "native/libmaplesu_ultra_bridge.so").exists())
        assertFalse(File(root, "native/libmaplesu_ultra_bridge.so.tmp").exists())
    }
}
