package dev.maplesu.ghostlock.extract

import java.io.IOException
import java.nio.charset.StandardCharsets

/**
 * Just enough ZIP to find `payload.bin` inside an OTA archive without a full
 * random-access unzip: EOCD (incl. ZIP64) location, central-directory entry
 * lookup and local-file-header data offset.
 *
 * Port of GhostLock-App `data/ota/ZipFileUtils.kt` (Apache-2.0, commit 437b3b2),
 * including its ZIP64 handling and its refusal to trust a malformed header.
 */
object ZipArchive {
    private const val CENSIG = 0x02014b50L
    private const val LOCSIG = 0x04034b50L
    private const val ENDSIG = 0x06054b50L
    private const val ENDHDR = 22
    private const val ZIP64_ENDSIG = 0x06064b50L
    private const val ZIP64_LOCSIG = 0x07064b50L
    private const val ZIP64_LOCHDR = 20
    private const val ZIP64_MAGICVAL = 0xFFFFFFFFL

    const val END_BYTES_SIZE = 65536
    const val LOCAL_HEADER_PROBE_SIZE = 256

    class FileInfo(val offset: Long, val size: Long)

    class CdEntry(
        val fileName: String,
        val localHeaderOffset: Long,
        val compressedSize: Long,
        val uncompressedSize: Long,
        val method: Int,
    )

    private fun u32(bytes: ByteArray, pos: Int): Long =
        (bytes[pos].toLong() and 0xFF) or
            ((bytes[pos + 1].toLong() and 0xFF) shl 8) or
            ((bytes[pos + 2].toLong() and 0xFF) shl 16) or
            ((bytes[pos + 3].toLong() and 0xFF) shl 24)

    private fun u16(bytes: ByteArray, pos: Int): Int =
        (bytes[pos].toInt() and 0xFF) or ((bytes[pos + 1].toInt() and 0xFF) shl 8)

    private fun u64(bytes: ByteArray, pos: Int): Long =
        (u32(bytes, pos) and ZIP64_MAGICVAL) or (u32(bytes, pos + 4) shl 32)

    /** Locate the central directory from a tail window of the archive. */
    fun locateCentralDirectory(bytes: ByteArray, fileLength: Long): FileInfo {
        val searchStart = bytes.size - ENDHDR
        var cenSize = -1L
        var cenOffset = -1L
        var current = searchStart
        while (current >= 0) {
            if ((u32(bytes, current) and 0xFFFFFFFFL) == ENDSIG) {
                val offsetField = current + 16
                val sizeField = current + 12
                if (sizeField + 4 > bytes.size) {
                    current--
                    continue
                }
                val offsetOfCentralDir = u32(bytes, offsetField) and 0xFFFFFFFFL
                val sizeOfCentralDir = u32(bytes, sizeField) and 0xFFFFFFFFL
                if (offsetOfCentralDir == ZIP64_MAGICVAL || sizeOfCentralDir == ZIP64_MAGICVAL) {
                    val locator = current - ZIP64_LOCHDR
                    if (locator >= 0 && (u32(bytes, locator) and 0xFFFFFFFFL) == ZIP64_LOCSIG) {
                        val recordOffsetInFile = u64(bytes, locator + 8)
                        val recordInBuffer = bytes.size - (fileLength - recordOffsetInFile).toInt()
                        if (recordInBuffer >= 0 && recordInBuffer + 56 <= bytes.size &&
                            (u32(bytes, recordInBuffer) and 0xFFFFFFFFL) == ZIP64_ENDSIG
                        ) {
                            cenSize = u64(bytes, recordInBuffer + 40)
                            cenOffset = u64(bytes, recordInBuffer + 48)
                            break
                        }
                    }
                } else {
                    cenSize = sizeOfCentralDir
                    cenOffset = offsetOfCentralDir
                    break
                }
            }
            current--
        }
        return FileInfo(cenOffset, cenSize)
    }

    /** Entries of the central directory that match [fileNames]. */
    fun locateEntries(bytes: ByteArray, fileNames: Set<String>): Map<String, CdEntry> {
        val results = LinkedHashMap<String, CdEntry>()
        var pos = 0
        while (pos + 46 <= bytes.size) {
            if ((u32(bytes, pos) and 0xFFFFFFFFL) != CENSIG) break
            val method = u16(bytes, pos + 10)
            var compressedSize = u32(bytes, pos + 20) and 0xFFFFFFFFL
            var uncompressedSize = u32(bytes, pos + 24) and 0xFFFFFFFFL
            val nameLength = u16(bytes, pos + 28)
            val extraLength = u16(bytes, pos + 30)
            val commentLength = u16(bytes, pos + 32)
            var localHeaderOffset = u32(bytes, pos + 42) and 0xFFFFFFFFL
            val nameStart = pos + 46
            if (nameStart + nameLength > bytes.size) break
            val name = String(bytes, nameStart, nameLength, StandardCharsets.UTF_8)
            if (name in fileNames) {
                val extraStart = nameStart + nameLength
                val extraEnd = minOf(extraStart + extraLength, bytes.size)
                if (uncompressedSize == ZIP64_MAGICVAL || compressedSize == ZIP64_MAGICVAL ||
                    localHeaderOffset == ZIP64_MAGICVAL
                ) {
                    var extraPos = extraStart
                    while (extraPos + 4 <= extraEnd) {
                        val id = u16(bytes, extraPos)
                        val size = u16(bytes, extraPos + 2)
                        val dataStart = extraPos + 4
                        if (dataStart + size > extraEnd) break
                        if (id == 0x0001) {
                            var field = dataStart
                            if (uncompressedSize == ZIP64_MAGICVAL && field + 8 <= dataStart + size) {
                                uncompressedSize = u64(bytes, field)
                                field += 8
                            }
                            if (compressedSize == ZIP64_MAGICVAL && field + 8 <= dataStart + size) {
                                compressedSize = u64(bytes, field)
                                field += 8
                            }
                            if (localHeaderOffset == ZIP64_MAGICVAL && field + 8 <= dataStart + size) {
                                localHeaderOffset = u64(bytes, field)
                            }
                            break
                        }
                        extraPos = dataStart + size
                    }
                }
                results[name] = CdEntry(
                    fileName = name,
                    localHeaderOffset = localHeaderOffset,
                    compressedSize = compressedSize,
                    uncompressedSize = uncompressedSize,
                    method = method,
                )
                if (results.size == fileNames.size) break
            }
            pos = nameStart + nameLength + extraLength + commentLength
        }
        return results
    }

    /** Data offset inside the local file header, or -1. */
    fun locateLocalFileOffset(bytes: ByteArray): Long {
        if (bytes.size >= 30 && (u32(bytes, 0) and 0xFFFFFFFFL) == LOCSIG) {
            val nameLength = u16(bytes, 26)
            val extraLength = u16(bytes, 28)
            return 30L + nameLength + extraLength
        }
        return -1L
    }

    /** Locate a stored entry's data start inside [source], throwing on a bad archive. */
    fun locateStoredEntry(source: RangeSource, entryName: String): Long {
        val fileLength = source.length
        val tailSize = minOf(fileLength, END_BYTES_SIZE.toLong()).toInt()
        val tail = source.read(fileLength - tailSize, tailSize)
            ?: throw IOException("Failed to read ZIP tail from remote file")
        val directory = locateCentralDirectory(tail, fileLength)
        if (directory.offset < 0 || directory.size <= 0 ||
            directory.offset + directory.size > fileLength
        ) {
            throw IOException("Failed to locate ZIP Central Directory in remote file")
        }
        if (directory.size > Int.MAX_VALUE) throw IOException("ZIP Central Directory is too large")
        val directoryBytes = source.read(directory.offset, directory.size.toInt())
            ?: throw IOException("Failed to read ZIP Central Directory (${directory.size} bytes)")
        val entry = locateEntries(directoryBytes, setOf(entryName))[entryName]
            ?: throw IOException("Remote OTA ZIP does not contain '$entryName'")
        if (entry.method != 0) {
            throw IOException(
                "$entryName in remote ZIP must be Stored (uncompressed), " +
                    "found compression method ${entry.method}")
        }
        if (entry.localHeaderOffset !in 0 until fileLength) {
            throw IOException("Invalid local header offset in ZIP: ${entry.localHeaderOffset}")
        }
        val probeSize = minOf(fileLength - entry.localHeaderOffset, LOCAL_HEADER_PROBE_SIZE.toLong()).toInt()
        val localHeader = source.read(entry.localHeaderOffset, probeSize)
            ?: throw IOException("Failed to read local file header for $entryName")
        val internalOffset = locateLocalFileOffset(localHeader)
        if (internalOffset !in 0..probeSize.toLong()) {
            throw IOException("Failed to parse local file header offset for $entryName")
        }
        return entry.localHeaderOffset + internalOffset
    }
}
