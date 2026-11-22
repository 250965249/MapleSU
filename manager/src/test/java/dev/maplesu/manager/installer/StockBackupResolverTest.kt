package dev.maplesu.manager.installer

import dev.maplesu.image.KernelCompression
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.security.MessageDigest

class StockBackupResolverTest {
    @get:Rule val temp = TemporaryFolder()
    private val ksuRoot get() = File(temp.root, "ksu").apply { mkdirs() }
    private val output get() = File(temp.root, "out")
    private val shaName = "stock_image.sha1"
    private val userDeRoot get() = File(temp.root, "user_de")
    private val ksuManager = "me.weishu.kernelsu"

    @Test
    fun restoresOnlyThePartitionWhoseRamdiskNamesTheExactBackup() {
        val originalInit = image("original-init.img", stock())
        val hash = sha1(originalInit)
        backup(hash, originalInit)
        val liveInit = image("live-init.img", patched(hash))
        val liveBoot = image("live-boot.img", ByteArray(0), kernel = byteArrayOf(1, 2, 3))
        val resolved = resolve(mapOf("boot" to liveBoot, "init_boot" to liveInit))
        assertEquals(setOf("init_boot"), resolved.restoredPartitions)
        assertEquals("ksu", resolved.family)
        assertArrayEquals(originalInit.readBytes(), resolved.originals.getValue("init_boot").readBytes())
        assertArrayEquals(liveBoot.readBytes(), resolved.originals.getValue("boot").readBytes())
        assertArrayEquals(patched(hash), ramdiskBytes(liveInit))
    }

    @Test
    fun supportsTheBoundedLz4RamdiskDecoder() {
        val original = image("original.img", stock("LZ4_LEGACY"))
        val hash = sha1(original)
        backup(hash, original)
        val live = image("live.img", patched(hash, "LZ4_LEGACY"))
        assertArrayEquals(original.readBytes(), resolve(mapOf("init_boot" to live)).originals.getValue("init_boot").readBytes())
    }

    @Test
    fun markerlessImagesAreOnlyCopiedCandidatesWithoutACleanClaim() {
        val live = image("live.img", stock(), kernel = byteArrayOf(8, 9))
        val result = resolve(mapOf("boot" to live))
        assertEquals("none", result.family)
        assertTrue(result.restoredPartitions.isEmpty())
        assertArrayEquals(live.readBytes(), result.originals.getValue("boot").readBytes())
    }

    @Test
    fun missingReferencedBackupDoesNotChooseAnotherSameSizeBackup() {
        val original = image("original.img", stock())
        backup(sha1(original), original)
        val live = image("live.img", patched("a".repeat(40)))
        expect("INSTALLER_STOCK_BACKUP_UNAVAILABLE") { resolve(mapOf("init_boot" to live)) }
    }

    @Test
    fun missingRamdiskReferenceDoesNotChooseTheNewestBackup() {
        val original = image("original.img", stock())
        backup(sha1(original), original)
        val live = image("live.img", archive(listOf("init" to byteArrayOf(1), "kernelsu.ko" to byteArrayOf(2))))
        expect("INSTALLER_STOCK_BACKUP_UNAVAILABLE") { resolve(mapOf("init_boot" to live)) }
    }

    @Test
    fun backupDigestMustMatchTheReferenceRatherThanItsName() {
        val original = image("original.img", stock())
        backup("a".repeat(40), original)
        val live = image("live.img", patched("a".repeat(40)))
        expect("INSTALLER_STOCK_BACKUP_MISMATCH") { resolve(mapOf("init_boot" to live)) }
    }

    @Test
    fun anExactBackupWithADifferentKernelIsRejected() {
        val original = image("original.img", stock(), kernel = byteArrayOf(1, 2, 3))
        val hash = sha1(original)
        backup(hash, original)
        val live = image("live.img", patched(hash), kernel = byteArrayOf(1, 2, 4))
        expect("INSTALLER_STOCK_BACKUP_MISMATCH") { resolve(mapOf("boot" to live)) }
    }

    @Test
    fun unmodifiedHeaderFieldsMustStillAgree() {
        val original = image("original.img", stock())
        val hash = sha1(original)
        backup(hash, original)
        val live = image("live.img", patched(hash)).apply {
            val bytes = readBytes()
            bytes[16] = 1 // v4 os_version, not the mutable ramdisk-size field.
            writeBytes(bytes)
        }
        expect("INSTALLER_STOCK_BACKUP_MISMATCH") { resolve(mapOf("init_boot" to live)) }
    }

    @Test
    fun aPatchedBackupNeverBecomesAnOriginalImage() {
        val dirty = image("dirty.img", archive(listOf("init" to byteArrayOf(1), "kernelsu.ko" to byteArrayOf(2))))
        val hash = sha1(dirty)
        backup(hash, dirty)
        val live = image("live.img", patched(hash))
        expect("INSTALLER_STOCK_BACKUP_MISMATCH") { resolve(mapOf("init_boot" to live)) }
    }

    @Test
    fun duplicateRamdiskReferencesAreAmbiguous() {
        val bytes = "a".repeat(40).toByteArray()
        val live = image("live.img", archive(listOf("init" to byteArrayOf(1), shaName to bytes, shaName to bytes)))
        expect("INSTALLER_STOCK_BACKUP_AMBIGUOUS") { resolve(mapOf("init_boot" to live)) }
    }

    @Test
    fun invalidReferencesAndWrongPartitionSizesAreRejected() {
        val invalid = image("invalid.img", patched("../" + "a".repeat(37)))
        expect("INSTALLER_STOCK_BACKUP_MISMATCH") { resolve(mapOf("init_boot" to invalid)) }
        val live = image("live.img", stock())
        expect("INSTALLER_STOCK_BACKUP_MISMATCH") {
            StockBackupResolver(ksuRoot = ksuRoot).resolve(mapOf("boot" to live), mapOf("boot" to live.length() + 1), output)
        }
    }

    @Test
    fun selectingAnotherFamilyDoesNotAssertThatItIsActive() {
        val original = image("original.img", stock())
        val hash = sha1(original)
        backup(hash, original)
        val live = image("live.img", patched(hash))
        expect("INSTALLER_STOCK_BACKUP_UNAVAILABLE") {
            StockBackupResolver(ksuRoot = ksuRoot, managerPackage = "com.topjohnwu.magisk")
                .resolve(mapOf("init_boot" to live), mapOf("init_boot" to live.length()), output)
        }
    }

    @Test
    fun sourceImagesAreNeverOverwrittenByTheOutputDirectory() {
        val live = image("boot.img", stock())
        expect("INSTALLER_STOCK_BACKUP_MISMATCH") {
            StockBackupResolver(ksuRoot = ksuRoot).resolve(mapOf("boot" to live), mapOf("boot" to live.length()), temp.root)
        }
    }

    @Test
    fun deviceEncryptedBackupSupportsTheExplicitUserWhenAdbBackupIsMissing() {
        val original = image("original.img", stock())
        val hash = sha1(original)
        deBackup(hash, original)
        val live = image("live.img", patched(hash))
        val absentAdb = File(temp.root, "absent-adb/ksu")
        val result = resolveWithDe(live, primary = absentAdb)
        assertEquals(setOf("init_boot"), result.restoredPartitions)
        assertEquals("ksu", result.family)
        assertArrayEquals(original.readBytes(), result.originals.getValue("init_boot").readBytes())
        assertTrue(!absentAdb.exists())
    }

    @Test
    fun theStandardBackupWinsWithoutReadingAnInvalidDeCopy() {
        val original = image("original.img", stock())
        val hash = sha1(original)
        backup(hash, original)
        deBackup(hash, original).writeText("invalid-fallback")
        val live = image("live.img", patched(hash))
        assertArrayEquals(original.readBytes(), resolveWithDe(live, primary = ksuRoot)
            .originals.getValue("init_boot").readBytes())
    }

    @Test
    fun anInvalidStandardBackupIsNotHiddenByAValidDeCopy() {
        val original = image("original.img", stock())
        val hash = sha1(original)
        backup(hash, original).apply { writeBytes(readBytes().also { it[50000] = 1 }) }
        deBackup(hash, original)
        val live = image("live.img", patched(hash))
        expect("INSTALLER_STOCK_BACKUP_MISMATCH") { resolveWithDe(live, primary = ksuRoot) }
    }

    @Test
    fun deFallbackRequiresAnExplicitAndroidUser() {
        val original = image("original.img", stock())
        val hash = sha1(original)
        deBackup(hash, original)
        val live = image("live.img", patched(hash))
        expect("INSTALLER_STOCK_BACKUP_UNAVAILABLE") { resolveWithDe(live, user = null) }
    }

    @Test
    fun deFallbackNeverSearchesAnotherUserOrAnUnselectedManager() {
        val original = image("original.img", stock())
        val hash = sha1(original)
        deBackup(hash, original, user = 11)
        deBackup(hash, original, owner = "unselected.manager")
        val live = image("live.img", patched(hash))
        expect("INSTALLER_STOCK_BACKUP_UNAVAILABLE") { resolveWithDe(live) }
    }

    @Test
    fun deFallbackRequiresTheExactReferenceAndItsImageDigest() {
        val original = image("original.img", stock())
        deBackup(sha1(original), original)
        val reference = "a".repeat(40)
        val live = image("live.img", patched(reference))
        expect("INSTALLER_STOCK_BACKUP_UNAVAILABLE") { resolveWithDe(live) }
        deBackup(reference, original)
        expect("INSTALLER_STOCK_BACKUP_MISMATCH") { resolveWithDe(live) }
    }

    @Test
    fun aSymbolicDeBackupOrParentIsRejected() {
        val original = image("original.img", stock())
        val hash = sha1(original)
        val backup = deBackup(hash, original)
        assertTrue(backup.delete())
        Files.createSymbolicLink(backup.toPath(), original.toPath())
        val live = image("live.img", patched(hash))
        expect("INSTALLER_STOCK_BACKUP_MISMATCH") { resolveWithDe(live) }
        assertTrue(backup.delete())
        val directory = backup.parentFile
        assertTrue(directory.delete())
        val target = File(temp.root, "linked-backups").apply { mkdir() }
        original.copyTo(File(target, backup.name))
        Files.createSymbolicLink(directory.toPath(), target.toPath())
        expect("INSTALLER_STOCK_BACKUP_MISMATCH") { resolveWithDe(live) }
    }

    @Test
    fun deFallbackDoesNotAssumeAUserForAnotherRootFamily() {
        val original = image("original.img", stock())
        val hash = sha1(original)
        deBackup(hash, original, owner = "com.topjohnwu.magisk")
        val live = image("live.img", patched(hash))
        expect("INSTALLER_STOCK_BACKUP_UNAVAILABLE") { resolveWithDe(live, owner = "com.topjohnwu.magisk") }
    }

    private fun resolveWithDe(
        live: File,
        user: Int? = 10,
        owner: String = ksuManager,
        primary: File = File(temp.root, "absent-adb/ksu"),
    ) = StockBackupResolver(ksuRoot = primary, managerPackage = owner, userId = user, userDeRoot = userDeRoot)
        .resolve(mapOf("init_boot" to live), mapOf("init_boot" to live.length()), output)

    private fun deBackup(hash: String, original: File, user: Int = 10, owner: String = ksuManager): File {
        val directory = File(userDeRoot, "$user/$owner/boot_backup").apply { mkdirs() }
        return original.copyTo(File(directory, "ksu_backup_$hash"))
    }

    private fun resolve(live: Map<String, File>) = StockBackupResolver(ksuRoot = ksuRoot)
        .resolve(live, live.mapValues { it.value.length() }, output)

    private fun expect(code: String, block: () -> Unit) {
        val failure = runCatching(block).exceptionOrNull()
        assertTrue("expected $code, got $failure", failure is IllegalStateException)
        assertEquals(code, failure?.message)
    }

    private fun backup(hash: String, original: File) = original.copyTo(File(ksuRoot, "ksu_backup_$hash"))
    private fun sha1(file: File) = MessageDigest.getInstance("SHA-1").digest(file.readBytes())
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun stock(compression: String = "GZIP") = archive(listOf("init" to byteArrayOf(1, 2, 3)), compression)
    private fun patched(hash: String, compression: String = "GZIP") = archive(
        listOf("init" to byteArrayOf(4), "init.real" to byteArrayOf(1, 2, 3), "kernelsu.ko" to byteArrayOf(5), shaName to hash.toByteArray()),
        compression,
    )

    private fun image(name: String, ramdisk: ByteArray, kernel: ByteArray = ByteArray(0)): File {
        val bytes = ByteArray(64 * 1024)
        val header = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        header.put("ANDROID!".toByteArray())
        header.putInt(8, kernel.size)
        header.putInt(12, ramdisk.size)
        header.putInt(20, 1584)
        header.putInt(40, 4)
        kernel.copyInto(bytes, 4096)
        ramdisk.copyInto(bytes, ((4096 + kernel.size + 4095) / 4096) * 4096)
        return File(temp.root, name).apply { writeBytes(bytes) }
    }

    private fun ramdiskBytes(image: File): ByteArray {
        val bytes = image.readBytes()
        val size = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt(12)
        return bytes.copyOfRange(4096, 4096 + size)
    }

    private fun archive(entries: List<Pair<String, ByteArray>>, compression: String = "GZIP"): ByteArray {
        val out = ByteArrayOutputStream()
        (entries + ("TRAILER!!!" to ByteArray(0))).forEachIndexed { index, (name, data) ->
            val encodedName = (name + "\u0000").toByteArray()
            val header = ByteArray(110) { '0'.code.toByte() }
            "070701".toByteArray().copyInto(header)
            listOf(6 to index + 1, 14 to 0x81a4, 38 to 1, 54 to data.size, 94 to encodedName.size).forEach { (offset, value) ->
                "%08x".format(value).toByteArray().copyInto(header, offset)
            }
            out.write(header)
            out.write(encodedName)
            while (out.size() % 4 != 0) out.write(0)
            out.write(data)
            while (out.size() % 4 != 0) out.write(0)
        }
        return KernelCompression.encode(out.toByteArray(), compression)
    }
}
