package dev.maplesu.manager.installer

import dev.maplesu.image.AvbFooter
import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.KernelCompression
import dev.maplesu.image.RamdiskInspector
import dev.maplesu.manager.workmode.migration.MigrationPaths
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.security.MessageDigest

data class StockBackupResolution(
    val originals: Map<String, File>,
    val restoredPartitions: Set<String>,
    val family: String,
)

/** Resolves only the backup named by each supplied current-slot ramdisk; never writes partitions. */
class StockBackupResolver(
    private val ksuRoot: File = File("/data/adb/ksu"),
    @Suppress("UNUSED_PARAMETER") magiskRoot: File = File("/data"),
    private val managerPackage: String? = null,
    private val userId: Int? = null,
    private val userDeRoot: File = File("/data/user_de"),
) {
    fun resolve(live: Map<String, File>, sizes: Map<String, Long>, output: File): StockBackupResolution = try {
        resolveImages(live, sizes, output)
    } catch (error: IllegalStateException) {
        throw error
    } catch (error: Exception) {
        fail(MISMATCH, error)
    }

    private fun resolveImages(live: Map<String, File>, sizes: Map<String, Long>, output: File): StockBackupResolution {
        check(live.isNotEmpty() && live.keys.all { it == "boot" || it == "init_boot" }) { MISMATCH }
        check(output.isDirectory || output.mkdirs()) { MISMATCH }
        val originals = linkedMapOf<String, File>()
        val restored = linkedSetOf<String>()
        for ((partition, image) in live.entries.sortedBy { it.key }) {
            val expectedSize = sizes[partition] ?: fail(MISMATCH)
            val currentHeader = inspectContainer(image, expectedSize)
            val currentRamdisk = inspectRamdisk(image)
            val references = currentRamdisk.entries.filter { it.path.removePrefix("./") == STOCK_SHA1 }
            if (references.size > 1) fail(AMBIGUOUS)
            val reference = references.singleOrNull()
            val patched = reference != null || hasRootMarkers(currentRamdisk)
            var originalSha1: String? = null
            val source = if (patched) {
                if (currentRamdisk.hasMagiskMarker && reference != null) fail(AMBIGUOUS)
                if (currentRamdisk.hasMagiskMarker || reference == null) fail(UNAVAILABLE)
                if (managerPackage != null && managerPackage !in KSU_PACKAGES) fail(UNAVAILABLE)
                check(reference.isRegularFile && reference.size in 40L..64L) { MISMATCH }
                val sha1 = readEntry(image, currentRamdisk, reference).toString(Charsets.US_ASCII).trim()
                check(sha1.matches(Regex("[0-9a-f]{40}"))) { MISMATCH }
                originalSha1 = sha1
                val backup = referencedBackup(sha1)
                val originalHeader = inspectContainer(backup, expectedSize)
                check(digest(backup, "SHA-1") == sha1) { MISMATCH }
                val originalRamdisk = inspectRamdisk(backup)
                check(!hasRootMarkers(originalRamdisk) && originalRamdisk.entries.none {
                    it.path.removePrefix("./") == STOCK_SHA1
                }) { MISMATCH }
                verifyUnchangedComponents(image, currentHeader, backup, originalHeader)
                restored += partition
                backup
            } else {
                // A ramdisk without markers is only a candidate source. Kernel cleanliness is proved elsewhere.
                image
            }
            val target = File(output, "$partition.img")
            check(!Files.isSymbolicLink(target.toPath()) && target.canonicalFile.parentFile == output.canonicalFile) { MISMATCH }
            check(target.canonicalFile != source.canonicalFile && live.values.none { it.canonicalFile == target.canonicalFile }) { MISMATCH }
            val expectedHash = digest(source, "SHA-256")
            source.copyTo(target, overwrite = true)
            check(target.length() == expectedSize && digest(target, "SHA-256") == expectedHash) { MISMATCH }
            if (originalSha1 != null) check(digest(target, "SHA-1") == originalSha1) { MISMATCH }
            originals[partition] = target
        }
        return StockBackupResolution(originals, restored, if (restored.isEmpty()) "none" else "ksu")
    }

    /** The upstream fallback belongs to the selected manager and calling Android user only. */
    private fun referencedBackup(sha1: String): File {
        val filename = "ksu_backup_$sha1"
        val primary = File(ksuRoot, filename)
        val (directory, backup) = if (primary.exists() || Files.isSymbolicLink(primary.toPath())) {
            ksuRoot to primary
        } else {
            val owner = managerPackage?.takeIf { it in KSU_PACKAGES } ?: fail(UNAVAILABLE)
            val user = userId?.takeIf { it >= 0 } ?: fail(UNAVAILABLE)
            val fallback = File(userDeRoot, "$user/$owner/boot_backup")
            fallback to File(fallback, filename)
        }
        var path: File? = backup.absoluteFile
        while (path != null) {
            check(!Files.isSymbolicLink(path.toPath())) { MISMATCH }
            path = path.parentFile
        }
        if (!backup.exists()) fail(UNAVAILABLE)
        check(backup.canonicalFile.parentFile == directory.canonicalFile) { MISMATCH }
        return backup
    }

    private fun inspectContainer(image: File, expectedSize: Long): BootImageInspector.Report {
        check(expectedSize in 1..RamdiskInspector.MAX_IMAGE_BYTES && image.isFile &&
            !Files.isSymbolicLink(image.toPath()) && image.length() == expectedSize) { MISMATCH }
        return try {
            val footer = AvbFooter.parse(image)
            check(footer.invalidReason(image.length()).isEmpty()) { MISMATCH }
            BootImageInspector.inspect(image)
        } catch (error: Exception) {
            fail(MISMATCH, error)
        }
    }

    private fun inspectRamdisk(image: File): RamdiskInspector.Report = try {
        RamdiskInspector.inspect(image).also {
            check(!it.malformed || it.errorCode == "EMPTY_RAMDISK") { MISMATCH }
        }
    } catch (error: Exception) {
        fail(MISMATCH, error)
    }

    private fun hasRootMarkers(report: RamdiskInspector.Report): Boolean =
        report.hasInitReal || report.hasKernelsuKo || report.hasKsuConfig || report.hasMaplesuId ||
            report.hasKsud || report.hasSevenkKo || report.hasMagiskMarker ||
            report.hasDataAdbKsuPath || report.ksuRelatedPaths.isNotEmpty()

    private fun readEntry(image: File, report: RamdiskInspector.Report, entry: RamdiskInspector.Entry): ByteArray {
        check(report.ramdiskSize in 1..RamdiskInspector.MAX_COMPONENT_BYTES) { MISMATCH }
        val encoded = readRegion(image, report.ramdiskOffset, report.ramdiskSize.toInt())
        val decoded = if (report.compression == "RAW") encoded else {
            KernelCompression.decode(encoded, report.compression, RamdiskInspector.DEFAULT_MAX_BYTES.toInt())
        }
        check(digest(decoded, "SHA-256") == report.decompressedSha256 &&
            entry.offset >= 0 && entry.size <= decoded.size && entry.offset <= decoded.size - entry.size) { MISMATCH }
        return decoded.copyOfRange(entry.offset.toInt(), (entry.offset + entry.size).toInt())
    }

    internal fun verifyUnchangedComponents(
        live: File,
        current: BootImageInspector.Report,
        backup: File,
        original: BootImageInspector.Report,
        compareKernel: Boolean = true,
    ) {
        check(current.headerVersion == original.headerVersion && current.headerSize == original.headerSize &&
            current.pageSize == original.pageSize) { MISMATCH }
        val currentBytes = readRegion(live, 0, current.headerSize.toInt())
        val originalBytes = readRegion(backup, 0, original.headerSize.toInt())
        fun mask(offset: Int, length: Int) {
            currentBytes.fill(0, offset, offset + length)
            originalBytes.fill(0, offset, offset + length)
        }
        mask(if (current.headerVersion < 3) 16 else 12, 4) // Ramdisk size changes after patching.
        if (!compareKernel) mask(8, 4) // Ultra changes the encoded kernel length.
        if (current.headerVersion < 3) mask(576, 32) // Legacy image id includes the ramdisk digest.
        if (current.headerVersion == 1 || current.headerVersion == 2) mask(1636, 8) // DTBO moves with ramdisk.
        if (current.headerVersion == 4) mask(1580, 4) // Repacking may drop the derived boot signature.
        check(currentBytes.contentEquals(originalBytes)) { MISMATCH }
        listOf(
            Triple(current.kernelOffset, original.kernelOffset, current.kernelSize to original.kernelSize),
            Triple(current.secondOffset, original.secondOffset, current.secondSize to original.secondSize),
            Triple(current.recoveryDtboOffset, original.recoveryDtboOffset, current.recoveryDtboSize to original.recoveryDtboSize),
            Triple(current.dtbOffset, original.dtbOffset, current.dtbSize to original.dtbSize),
        ).drop(if (compareKernel) 0 else 1).forEach { (currentOffset, originalOffset, lengths) ->
            check(lengths.first == lengths.second) { MISMATCH }
            if (lengths.first > 0) {
                check(regionDigest(live, currentOffset, lengths.first) == regionDigest(backup, originalOffset, lengths.second)) { MISMATCH }
            }
        }
    }

    private fun readRegion(file: File, offset: Long, size: Int): ByteArray =
        RandomAccessFile(file, "r").use { input ->
            check(offset >= 0 && size >= 0 && offset <= input.length() - size) { MISMATCH }
            input.seek(offset)
            ByteArray(size).also { input.readFully(it) }
        }

    private fun regionDigest(file: File, offset: Long, length: Long): String {
        val hash = MessageDigest.getInstance("SHA-256")
        RandomAccessFile(file, "r").use { input ->
            input.seek(offset)
            var remaining = length
            val buffer = ByteArray(64 * 1024)
            while (remaining > 0) {
                if (Thread.currentThread().isInterrupted) fail(MISMATCH)
                val count = minOf(remaining, buffer.size.toLong()).toInt()
                input.readFully(buffer, 0, count)
                hash.update(buffer, 0, count)
                remaining -= count
            }
        }
        return hash.digest().hex()
    }

    private fun digest(file: File, algorithm: String): String {
        val hash = MessageDigest.getInstance(algorithm)
        file.inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                if (Thread.currentThread().isInterrupted) fail(MISMATCH)
                val count = input.read(buffer)
                if (count < 0) break
                hash.update(buffer, 0, count)
            }
        }
        return hash.digest().hex()
    }

    private fun digest(bytes: ByteArray, algorithm: String): String =
        MessageDigest.getInstance(algorithm).digest(bytes).hex()

    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun fail(code: String, cause: Exception? = null): Nothing = throw IllegalStateException(code, cause)

    private companion object {
        const val STOCK_SHA1 = "stock_image.sha1"
        const val UNAVAILABLE = "INSTALLER_STOCK_BACKUP_UNAVAILABLE"
        const val MISMATCH = "INSTALLER_STOCK_BACKUP_MISMATCH"
        const val AMBIGUOUS = "INSTALLER_STOCK_BACKUP_AMBIGUOUS"
        val KSU_PACKAGES = MigrationPaths.KSU_MANAGER_PACKAGES + MigrationPaths.SEVENK_MANAGER_PACKAGES
    }
}
