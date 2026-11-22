package dev.maplesu.ghostlock.extract

import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream
import org.tukaani.xz.XZInputStream
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile

/**
 * Streaming OTA partition extractor: reads `payload.bin` metadata and only the
 * data blobs needed for `boot`, `xbl_config`, `uefi` and `vendor_boot`.
 *
 * Port of GhostLock-App `data/ota/OtaPayloadExtractor.kt` (Apache-2.0, commit
 * 437b3b2). The reference resolves remote OTA URLs with this pure-Kotlin path and
 * hands the extracted images to the native reference extractor. Limits are
 * deliberately tight because the whole path is
 * user-triggered and remote:
 *
 * - `payload.bin` manifest <= 64 MiB (inside [PayloadBin]);
 * - one decompressed partition <= [MAX_PARTITION_BYTES];
 * - the total downloaded blob data <= [MAX_TOTAL_DATA_BYTES];
 * - each compressed operation <= [MAX_OPERATION_BYTES].
 *
 * Failures are fail-closed: a partially written image is deleted before the
 * exception propagates.
 */
object OtaPayloadExtractor {
    const val MAX_PARTITION_BYTES = 512L * 1024 * 1024
    const val MAX_TOTAL_DATA_BYTES = 1024L * 1024 * 1024
    const val MAX_OPERATION_BYTES = 256L * 1024 * 1024

    class ExtractedPartitions(
        val bootFile: File, val xblConfigFile: File? = null,
        val uefiFile: File? = null, val vendorBootFile: File? = null,
    ) {
        fun images() = ExtractInput.BootImageFile(bootFile, xblConfigFile, uefiFile, vendorBootFile)
        fun delete() { listOfNotNull(bootFile, xblConfigFile, uefiFile, vendorBootFile).forEach { it.delete() } }
    }

    /** Locate `payload.bin` at [source] (raw payload or inside an OTA ZIP). */
    private fun locatePayloadStart(source: RangeSource): Long {
        val headBytes = source.read(0, 4)
        if (headBytes != null && PayloadBin.looksLikePayload(headBytes)) return 0L
        return ZipArchive.locateStoredEntry(source, PayloadBin.PAYLOAD_ENTRY)
    }

    @Throws(IOException::class)
    fun extractPartitions(
        source: RangeSource,
        workDir: File,
        onLog: (String) -> Unit = {},
    ): ExtractedPartitions {
        if (!workDir.isDirectory && !workDir.mkdirs()) {
            throw IOException("cannot create work directory")
        }
        val fileLength = source.length
        if (fileLength <= 0) throw IOException("Remote file length is zero or invalid")

        onLog("locating payload metadata (file size: ${formatSize(fileLength)})...")
        val payloadStart = locatePayloadStart(source)
        val (payloadHeader, _) = PayloadBin.headerAt(source, payloadStart)

        val manifestStart = payloadStart + PayloadBin.HEADER_SIZE
        if (payloadHeader.manifestSize > Int.MAX_VALUE) {
            throw IOException(
                "Payload manifest size exceeds maximum supported memory " +
                    "(${payloadHeader.manifestSize} bytes)")
        }
        val manifest = source.read(manifestStart, payloadHeader.manifestSize.toInt())
            ?: throw IOException("Failed to read payload manifest (${payloadHeader.manifestSize} bytes)")

        val partitions = PayloadBin.listPartitions(manifest)
        if ("boot" !in partitions) {
            throw IOException(
                "Payload does not contain 'boot' partition (found: ${partitions.joinToString()})")
        }
        val wanted = ArrayList<String>().apply {
            add("boot")
            if ("xbl_config" in partitions) add("xbl_config")
            if ("uefi" in partitions) add("uefi")
            if ("vendor_boot" in partitions) add("vendor_boot")
        }
        onLog("analyzing partitions: ${wanted.joinToString(", ")}")

        val blockSize = PayloadBin.blockSize(manifest)
        val dataBase = payloadStart + PayloadBin.HEADER_SIZE +
            payloadHeader.manifestSize + payloadHeader.signatureSize
        val partitionOps = LinkedHashMap<String, List<PayloadBin.PayloadOperation>>()
        for (name in wanted) {
            val ops = PayloadBin.partitionOperations(manifest, name)
            if (ops.isEmpty()) throw IOException("Partition '$name' has no operations in payload")
            partitionOps[name] = ops
        }
        val totalDownloadBytes = partitionOps.values.sumOf { ops -> ops.sumOf { it.dataLength } }
        if (totalDownloadBytes > MAX_TOTAL_DATA_BYTES) {
            throw IOException(
                "Payload data exceeds the download bound " +
                    "(${formatSize(totalDownloadBytes)} > ${formatSize(MAX_TOTAL_DATA_BYTES)})")
        }

        var downloaded = 0L
        var lastLog = 0L
        fun reportProgress(force: Boolean = false) {
            val now = System.currentTimeMillis()
            if (force || now - lastLog >= 2000) {
                lastLog = now
                val percent = if (totalDownloadBytes > 0) {
                    downloaded.toDouble() / totalDownloadBytes * 100.0
                } else 0.0
                onLog("download: ${formatSize(downloaded)} / ${formatSize(totalDownloadBytes)} " +
                    "(${String.format(java.util.Locale.US, "%.1f", percent)}%)")
            }
        }

        val timestamp = System.currentTimeMillis()
        var bootFile: File? = null
        var xblConfigFile: File? = null
        var uefiFile: File? = null
        var vendorBootFile: File? = null
        try {
            for ((name, ops) in partitionOps) {
                val outFile = File(workDir, "ghostlock_ota_${name}_$timestamp.img")
                when (name) {
                    "boot" -> bootFile = outFile
                    "xbl_config" -> xblConfigFile = outFile
                    "uefi" -> uefiFile = outFile
                    "vendor_boot" -> vendorBootFile = outFile
                }
                val totalSize = ops.maxOfOrNull { op ->
                    op.destExtents.maxOfOrNull { (it.startBlock + it.numBlocks) * blockSize } ?: 0L
                } ?: throw IOException("Partition '$name' has zero length")
                if (totalSize <= 0 || totalSize > MAX_PARTITION_BYTES) {
                    throw IOException(
                        "Partition '$name' size ${formatSize(totalSize)} is outside the supported bound")
                }
                RandomAccessFile(outFile, "rw").use { handle ->
                    handle.setLength(totalSize)
                    for (op in ops) {
                        when (op.type) {
                            PayloadBin.OP_ZERO, PayloadBin.OP_DISCARD -> Unit // already zero-filled
                            PayloadBin.OP_REPLACE -> {
                                val data = readOperation(source, dataBase, op, name)
                                writeExtents(handle, data, op.destExtents, blockSize)
                                downloaded += op.dataLength
                                reportProgress()
                            }

                            PayloadBin.OP_REPLACE_XZ -> {
                                val compressed = readOperation(source, dataBase, op, name)
                                val uncompressedSize = op.destExtents.sumOf { it.numBlocks } * blockSize
                                if (uncompressedSize <= 0 || uncompressedSize > MAX_PARTITION_BYTES) {
                                    throw IOException(
                                        "Partition '$name' XZ output ${formatSize(uncompressedSize)} " +
                                            "is outside the supported bound")
                                }
                                val decompressed = XZInputStream(ByteArrayInputStream(compressed))
                                    .use { stream -> stream.readNBytes(uncompressedSize.toInt()) }
                                writeExtents(handle, decompressed, op.destExtents, blockSize)
                                downloaded += op.dataLength
                                reportProgress()
                            }

                            PayloadBin.OP_REPLACE_BZ -> {
                                val compressed = readOperation(source, dataBase, op, name)
                                val decompressed = BZip2CompressorInputStream(
                                    ByteArrayInputStream(compressed)).use { it.readBytes() }
                                writeExtents(handle, decompressed, op.destExtents, blockSize)
                                downloaded += op.dataLength
                                reportProgress()
                            }

                            else -> throw IOException(
                                "Unsupported payload operation type: ${op.type} in partition '$name'")
                        }
                    }
                }
                onLog("extracted $name=${outFile.name} (${formatSize(outFile.length())}) from payload")
            }
            reportProgress(force = true)
            return ExtractedPartitions(bootFile!!, xblConfigFile, uefiFile, vendorBootFile)
        } catch (error: Exception) {
            bootFile?.delete()
            xblConfigFile?.delete()
            uefiFile?.delete()
            vendorBootFile?.delete()
            throw error
        }
    }

    @Throws(IOException::class)
    private fun readOperation(
        source: RangeSource,
        dataBase: Long,
        op: PayloadBin.PayloadOperation,
        partition: String,
    ): ByteArray {
        if (op.dataLength <= 0 || op.dataLength > MAX_OPERATION_BYTES || op.dataLength > Int.MAX_VALUE) {
            throw IOException(
                "Operation for '$partition' has an unsupported data length ${op.dataLength}")
        }
        val data = source.read(dataBase + op.dataOffset, op.dataLength.toInt())
            ?: throw IOException(
                "Failed to read operation for $partition at offset ${dataBase + op.dataOffset}")
        if (data.size < op.dataLength) {
            throw IOException("Truncated operation data for $partition")
        }
        return data
    }

    private fun writeExtents(
        handle: RandomAccessFile,
        data: ByteArray,
        extents: List<PayloadBin.Extent>,
        blockSize: Long,
    ) {
        var dataOffset = 0
        for (extent in extents) {
            val extentBytes = (extent.numBlocks * blockSize)
            val end = minOf(dataOffset.toLong() + extentBytes, data.size.toLong()).toInt()
            if (dataOffset < end) {
                handle.seek(extent.startBlock * blockSize)
                handle.write(data, dataOffset, end - dataOffset)
                dataOffset = end
            }
        }
    }

    fun formatSize(bytes: Long): String {
        if (bytes < 0) return "0 B"
        val units = arrayOf("B", "KiB", "MiB", "GiB", "TiB")
        var value = bytes.toDouble()
        var unit = 0
        while (value >= 1024.0 && unit + 1 < units.size) {
            value /= 1024.0
            unit++
        }
        return String.format(java.util.Locale.US, "%.1f %s", value, units[unit])
    }
}
