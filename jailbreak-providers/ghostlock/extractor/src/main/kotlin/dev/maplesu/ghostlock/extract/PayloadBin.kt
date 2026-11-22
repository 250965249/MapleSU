package dev.maplesu.ghostlock.extract

import java.io.IOException

/**
 * Minimal `payload.bin` reader: parses install operations and exposes the block
 * layout. The manifest is scanned as raw protobuf with unknown fields skipped.
 *
 * Port of GhostLock-App `data/ota/PayloadBinUtils.kt` (Apache-2.0, commit
 * 437b3b2), including the 64 MiB manifest bound and the exact field numbers.
 */
object PayloadBin {
    const val PAYLOAD_ENTRY = "payload.bin"
    const val HEADER_SIZE = 24

    const val OP_REPLACE = 0L
    const val OP_REPLACE_BZ = 1L
    const val OP_ZERO = 6L
    const val OP_DISCARD = 7L
    const val OP_REPLACE_XZ = 8L

    val PAYLOAD_MAGIC = byteArrayOf(0x43, 0x72, 0x41, 0x55) // "CrAU"
    private const val MAX_MANIFEST_SIZE = 64L shl 20

    class PayloadHeader(val manifestSize: Long, val signatureSize: Long)

    class Extent(val startBlock: Long, val numBlocks: Long)

    class PayloadOperation(
        val type: Long,
        /** Relative to the start of the payload's data blobs. */
        val dataOffset: Long,
        val dataLength: Long,
        val destExtents: List<Extent>,
    )

    fun parseHeader(header: ByteArray): PayloadHeader? {
        if (header.size < HEADER_SIZE) return null
        for (i in 0 until 4) if (header[i] != PAYLOAD_MAGIC[i]) return null
        val manifestSize = u64be(header, 12)
        val signatureSize = u32be(header, 20)
        if (manifestSize < 1 || manifestSize > MAX_MANIFEST_SIZE) return null
        return PayloadHeader(manifestSize, signatureSize)
    }

    /** All partition names present in the manifest. */
    fun listPartitions(manifest: ByteArray): List<String> {
        val partitions = ArrayList<String>()
        scanProto(manifest, 0, manifest.size) { field, wire, _, dataStart, dataEnd ->
            if (field == 13 && wire == 2) {
                scanProto(manifest, dataStart, dataEnd) { pf, pw, _, pdStart, pdEnd ->
                    if (pf == 1 && pw == 2) {
                        partitions.add(String(manifest, pdStart, pdEnd - pdStart, Charsets.UTF_8))
                        false
                    } else true
                }
            }
            true
        }
        return partitions
    }

    /** Block size from the manifest, defaulting to 4096. */
    fun blockSize(manifest: ByteArray): Long {
        var blockSize = 4096L
        scanProto(manifest, 0, manifest.size) { field, wire, number, _, _ ->
            if (field == 3 && wire == 0) {
                blockSize = number
                false
            } else true
        }
        return if (blockSize > 0) blockSize else 4096L
    }

    /** The named partition's operations in image-write order; empty when absent. */
    fun partitionOperations(manifest: ByteArray, partition: String): List<PayloadOperation> {
        var operations: List<PayloadOperation> = emptyList()
        scanProto(manifest, 0, manifest.size) { field, wire, _, dataStart, dataEnd ->
            if (field != 13 || wire != 2) return@scanProto true
            var name = ""
            val ops = ArrayList<PayloadOperation>()
            scanProto(manifest, dataStart, dataEnd) { pf, pw, _, pdStart, pdEnd ->
                when {
                    pf == 1 && pw == 2 -> name = String(manifest, pdStart, pdEnd - pdStart, Charsets.UTF_8)
                    pf == 8 && pw == 2 -> parseOperation(manifest, pdStart, pdEnd)?.let(ops::add)
                }
                true
            }
            if (name == partition) {
                operations = ops
                false
            } else true
        }
        return operations
    }

    private fun parseOperation(buffer: ByteArray, start: Int, end: Int): PayloadOperation? {
        var type = 0L
        var dataOffset = 0L
        var dataLength = 0L
        val extents = ArrayList<Extent>()
        scanProto(buffer, start, end) { field, wire, number, dataStart, dataEnd ->
            when (field) {
                1 if wire == 0 -> type = number
                2 if wire == 0 -> dataOffset = number
                3 if wire == 0 -> dataLength = number
                6 if wire == 2 -> {
                    var startBlock = 0L
                    var numBlocks = 0L
                    scanProto(buffer, dataStart, dataEnd) { ef, ew, en, _, _ ->
                        when {
                            ef == 1 && ew == 0 -> startBlock = en
                            ef == 2 && ew == 0 -> numBlocks = en
                        }
                        true
                    }
                    if (numBlocks > 0) extents.add(Extent(startBlock, numBlocks))
                }
            }
            true
        }
        if (extents.isEmpty()) return null
        return PayloadOperation(type, dataOffset, dataLength, extents)
    }

    /** Walks protobuf wire format; returning false from [visit] stops the walk. */
    private fun scanProto(
        buffer: ByteArray,
        start: Int,
        end: Int,
        visit: (field: Int, wire: Int, number: Long, dataStart: Int, dataEnd: Int) -> Boolean,
    ) {
        var pos = start
        while (pos < end) {
            val tagRead = readVarint(buffer, pos, end) ?: break
            pos += tagRead.second
            val wire = (tagRead.first and 7L).toInt()
            val field = (tagRead.first ushr 3).toInt()
            when (wire) {
                0 -> {
                    val (number, length) = readVarint(buffer, pos, end) ?: break
                    pos += length
                    if (!visit(field, wire, number, 0, 0)) return
                }

                1 -> {
                    if (pos + 8 > end) break
                    val number = u64le(buffer, pos)
                    pos += 8
                    if (!visit(field, wire, number, 0, 0)) return
                }

                2 -> {
                    val (length, lengthBytes) = readVarint(buffer, pos, end) ?: break
                    pos += lengthBytes
                    if (length < 0 || pos + length > end) break
                    val dataStart = pos
                    val dataEnd = (pos + length).toInt()
                    pos = dataEnd
                    if (!visit(field, wire, length, dataStart, dataEnd)) return
                }

                5 -> {
                    if (pos + 4 > end) break
                    val number = u32le(buffer, pos)
                    pos += 4
                    if (!visit(field, wire, number, 0, 0)) return
                }

                else -> break
            }
        }
    }

    private fun readVarint(buffer: ByteArray, start: Int, end: Int): Pair<Long, Int>? {
        var value = 0L
        var shift = 0
        var pos = start
        while (pos < end && shift <= 63) {
            val b = buffer[pos++].toLong()
            value = value or ((b and 0x7F) shl shift)
            if (b and 0x80 == 0L) return value to (pos - start)
            shift += 7
        }
        return null
    }

    private fun u32le(bytes: ByteArray, pos: Int): Long =
        (bytes[pos].toLong() and 0xFF) or
            ((bytes[pos + 1].toLong() and 0xFF) shl 8) or
            ((bytes[pos + 2].toLong() and 0xFF) shl 16) or
            ((bytes[pos + 3].toLong() and 0xFF) shl 24)

    private fun u64le(bytes: ByteArray, pos: Int): Long = u32le(bytes, pos) or (u32le(bytes, pos + 4) shl 32)

    private fun u32be(bytes: ByteArray, pos: Int): Long =
        (bytes[pos + 3].toLong() and 0xFF) or
            ((bytes[pos + 2].toLong() and 0xFF) shl 8) or
            ((bytes[pos + 1].toLong() and 0xFF) shl 16) or
            ((bytes[pos].toLong() and 0xFF) shl 24)

    private fun u64be(bytes: ByteArray, pos: Int): Long = (u32be(bytes, pos) shl 32) or u32be(bytes, pos + 4)

    /** True when the bytes start with the payload magic (a raw payload.bin file). */
    fun looksLikePayload(bytes: ByteArray): Boolean =
        bytes.size >= 4 && bytes.copyOfRange(0, 4).contentEquals(PAYLOAD_MAGIC)

    /** True when the file name looks like an OTA/payload input. */
    fun looksLikePayloadName(name: String): Boolean {
        val lower = name.lowercase()
        return lower.endsWith(".zip") || lower.endsWith(".bin") || lower.contains("payload")
    }

    /** Read the 24-byte header of a payload.bin starting at [start]. */
    @Throws(IOException::class)
    fun headerAt(source: RangeSource, start: Long): Pair<PayloadHeader, Long> {
        val headerBytes = source.read(start, HEADER_SIZE)
            ?: throw IOException("Failed to read payload.bin header at offset $start")
        val header = parseHeader(headerBytes)
            ?: throw IOException("Invalid payload.bin header (missing CrAU magic)")
        return header to start
    }
}
