package dev.maplesu.ghostlock.extract

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.zip.GZIPInputStream

/**
 * Android boot image / raw arm64 Image parsing.
 *
 * Behaviour is a field-for-field port of GhostLock-App
 * `tools/extract_rs/src/boot.rs` (Apache-2.0, commit 437b3b2):
 * - `ANDROID!` boot header v3/v4 only (v0-v2 are rejected with the same
 *   message), kernel at `align(header_size, 4096)`, `kernel_size` bytes;
 * - MTK legacy LZ4 frames and gzip kernels are decompressed;
 * - the UTS release is the first `Linux version <release>` banner whose release
 *   is shaped `major.minor.patch[-...]` (format strings carrying `%` skipped);
 * - the embedded BTF blob is the largest candidate found by the `0xEB9F` magic
 *   signature, its strings table optionally extended past the declared
 *   `str_len` over a printable tail.
 *
 * The port keeps the reference's limits so a hostile image cannot make the
 * parser allocate beyond the same bounds (256 MiB LZ4 output, 8 MiB LZ4 block).
 */
class BootImage private constructor(
    /** Uncompressed arm64 Image bytes (the kernel payload). */
    val kernel: ByteArray,
    /** True when the payload was an MTK LZ4 legacy frame. */
    val mtkLz4: Boolean,
    /** True when the payload was gzip. */
    val mtkGzip: Boolean,
) {
    /** The UTS release, or null when the image carries no recognisable banner. */
    fun release(): String? = extractRelease(kernel)

    /**
     * The embedded BTF blob (file offset inside [kernel] + bytes), or null.
     * The largest valid candidate wins, exactly like the reference.
     */
    fun embeddedBtfAt(): BtfBlob? = findEmbeddedBtf(kernel)

    data class BtfBlob(val offset: Int, val bytes: ByteArray)

    companion object {
        val ANDROID_MAGIC = "ANDROID!".toByteArray(Charsets.US_ASCII)
        const val BTF_MAGIC = 0xEB9F
        const val PAGE_SIZE = 4096
        val LZ4_LEGACY_MAGIC = byteArrayOf(0x02, 0x21, 0x4C, 0x18)
        const val LZ4_MAX_IMAGE = 0x1000_0000
        private const val MAX_BTF_STR_EXTENSION = 1 shl 20

        /** Parse an Android boot image, a raw arm64 Image or a gzipped Image. */
        @Throws(IOException::class)
        fun load(raw: ByteArray): BootImage {
            if (raw.size >= 8 && raw.copyOfRange(0, 8).contentEquals(ANDROID_MAGIC)) {
                return fromAndroidBoot(raw)
            }
            var bytes = raw
            if (bytes.size >= 3 && (bytes[0].toInt() and 0xFF) == 0x1f &&
                (bytes[1].toInt() and 0xFF) == 0x8b && (bytes[2].toInt() and 0xFF) == 0x08
            ) {
                bytes = gunzip(bytes)
            }
            if (bytes.size < 64 || !bytes.copyOfRange(56, 60).contentEquals("ARM\u0064".toByteArray())) {
                throw IOException("input is not an Android boot image or arm64 Image")
            }
            return BootImage(bytes, false, false)
        }

        @Throws(IOException::class)
        private fun fromAndroidBoot(raw: ByteArray): BootImage {
            if (raw.size < 44) throw IOException("truncated Android boot header")
            val kernelSize = readU32(raw, 8)
            val headerSize = readU32(raw, 20)
            val version = readU32(raw, 40)
            if (version != 3 && version != 4) {
                throw IOException("unsupported boot header version $version")
            }
            val start = align(headerSize, PAGE_SIZE)
            val end = start.toLong() + kernelSize.toLong()
            if (end > raw.size.toLong()) throw IOException("kernel payload exceeds boot image")
            val kernel = raw.copyOfRange(start, end.toInt())
            if (kernel.size >= 4 && kernel.copyOfRange(0, 4).contentEquals(LZ4_LEGACY_MAGIC)) {
                return BootImage(decompressLz4Legacy(kernel), true, false)
            }
            if (kernel.size >= 3 && (kernel[0].toInt() and 0xFF) == 0x1f &&
                (kernel[1].toInt() and 0xFF) == 0x8b && (kernel[2].toInt() and 0xFF) == 0x08
            ) {
                return BootImage(gunzip(kernel), false, true)
            }
            return BootImage(kernel, false, false)
        }

        /** MTK boot kernels: 4-byte magic, size-prefixed LZ4 blocks, 8 MiB blocks. */
        @Throws(IOException::class)
        fun decompressLz4Legacy(payload: ByteArray): ByteArray {
            val out = decompressLz4LegacyFrame(payload)
            if (out.size < 0x3C || out[0].toInt() != 'M'.code || out[1].toInt() != 'Z'.code ||
                !out.copyOfRange(0x38, 0x3C).contentEquals("ARM\u0064".toByteArray())
            ) {
                throw IOException("LZ4 decompression did not yield an arm64 Image")
            }
            return out
        }

        @Throws(IOException::class)
        private fun decompressLz4LegacyFrame(payload: ByteArray): ByteArray {
            val maxBlock = 8 * 1024 * 1024
            if (payload.size <= 8 || !payload.copyOfRange(0, 4).contentEquals(LZ4_LEGACY_MAGIC)) {
                throw IOException("LZ4 kernel payload too short")
            }
            val out = ByteArrayOutputStream()
            var ip = 4
            while (ip + 4 <= payload.size) {
                val blockLength = readU32(payload, ip)
                ip += 4
                if (blockLength == 0) break // trailing zero padding
                val end = ip.toLong() + blockLength.toLong()
                if (end > payload.size.toLong()) throw IOException("truncated LZ4 legacy block")
                val block = decompressLz4Block(payload.copyOfRange(ip, end.toInt()), maxBlock)
                ip = end.toInt()
                if (out.size().toLong() + block.size > LZ4_MAX_IMAGE) {
                    throw IOException("LZ4 output exceeds size bound")
                }
                out.write(block)
                if (block.size < maxBlock) break
            }
            return out.toByteArray()
        }

        /**
         * Decode one LZ4 block like the reference C decoder: an offset-0 match
         * expands to zeros (MTK legacy streams use it as padding), which
         * lz4_flex would reject.
         */
        @Throws(IOException::class)
        private fun decompressLz4Block(input: ByteArray, maxOutput: Int): ByteArray {
            var buffer = ByteArray(maxOf(64, minOf(input.size, maxOutput)))
            var size = 0
            var ip = 0
            while (ip < input.size) {
                val token = input[ip].toInt() and 0xFF
                ip += 1
                var literal = token ushr 4
                if (literal == 15) {
                    while (true) {
                        if (ip >= input.size) throw IOException("truncated LZ4 literal length")
                        val b = input[ip].toInt() and 0xFF
                        ip += 1
                        literal += b
                        if (b != 255) break
                    }
                }
                if (ip + literal > input.size) throw IOException("truncated LZ4 literals")
                if (size + literal > maxOutput) throw IOException("LZ4 output exceeds size bound")
                if (size + literal > buffer.size) buffer = buffer.copyOf(grow(buffer.size, size + literal))
                System.arraycopy(input, ip, buffer, size, literal)
                size += literal
                ip += literal
                if (ip >= input.size) break // final literals-only sequence
                if (ip + 2 > input.size) throw IOException("truncated LZ4 match offset")
                val offset = (input[ip].toInt() and 0xFF) or ((input[ip + 1].toInt() and 0xFF) shl 8)
                ip += 2
                var matchLength = (token and 0x0F) + 4
                if (matchLength == 19) {
                    while (true) {
                        if (ip >= input.size) throw IOException("truncated LZ4 match length")
                        val b = input[ip].toInt() and 0xFF
                        ip += 1
                        matchLength += b
                        if (b != 255) break
                    }
                }
                if (offset > size) throw IOException("LZ4 match before start of output")
                if (size + matchLength > maxOutput) throw IOException("LZ4 output exceeds size bound")
                if (size + matchLength > buffer.size) {
                    buffer = buffer.copyOf(grow(buffer.size, size + matchLength))
                }
                if (offset == 0) {
                    java.util.Arrays.fill(buffer, size, size + matchLength, 0)
                    size += matchLength
                } else {
                    val start = size - offset
                    for (i in 0 until matchLength) buffer[size + i] = buffer[start + i]
                    size += matchLength
                }
            }
            return buffer.copyOf(size)
        }

        private fun grow(current: Int, needed: Int): Int {
            var next = maxOf(current, 64)
            while (next < needed) next = next shl 1
            return next
        }

        /** Extract the UTS release from an image, skipping `Linux version %s`. */
        fun extractRelease(kernel: ByteArray): String? {
            val needle = "Linux version ".toByteArray(Charsets.US_ASCII)
            var cursor = 0
            while (true) {
                val pos = findSubslice(kernel, needle, cursor) ?: return null
                cursor = pos + needle.size
                val rest = pos + needle.size
                var end = rest
                while (end < kernel.size) {
                    val b = kernel[end].toInt() and 0xFF
                    if (b == 0 || b == '\r'.code || b == '\n'.code || b == ' '.code) break
                    end++
                }
                val candidate = String(kernel, rest, end - rest, Charsets.US_ASCII)
                if (isReleaseShape(candidate)) return candidate
            }
        }

        private fun isReleaseShape(candidate: String): Boolean {
            if (candidate.contains('%')) return false
            val parts = candidate.split('.')
            if (parts.size < 3) return false
            val major = parts[0].toIntOrNull()
            val minor = parts[1].toIntOrNull()
            val patch = parts[2].substringBefore('-').toIntOrNull()
            return major != null && minor != null && patch != null
        }

        /** Largest valid embedded BTF blob, or null. */
        fun findEmbeddedBtf(kernel: ByteArray): BtfBlob? {
            val signature = ByteArray(8).apply {
                putU16Le(this, 0, BTF_MAGIC)
                this[2] = 1
                this[3] = 0
                putU32Le(this, 4, 24)
            }
            var best: BtfBlob? = null
            var cursor = 0
            while (true) {
                val pos = findSubslice(kernel, signature, cursor) ?: break
                cursor = pos + 1
                if (pos + 24 > kernel.size) continue
                val magic = readU16(kernel, pos)
                val version = kernel[pos + 2].toInt() and 0xFF
                val headerLength = readU32(kernel, pos + 4)
                val typeOffset = readU32(kernel, pos + 8)
                val typeLength = readU32(kernel, pos + 12)
                val stringOffset = readU32(kernel, pos + 16)
                val stringLength = readU32(kernel, pos + 20)
                if (magic != BTF_MAGIC || version != 1 || headerLength < 24) continue
                var total = headerLength.toLong() +
                    maxOf(typeOffset.toLong() + typeLength, stringOffset.toLong() + stringLength)
                if (total <= headerLength || pos.toLong() + total > kernel.size) continue
                val strings = pos + headerLength + stringOffset
                if (stringLength != 0 && kernel.getOrElse(strings) { 0 } == 0.toByte()) {
                    // Some vendors append strings past the declared str_len (only
                    // when strings are the last section); extend over the
                    // NUL-terminated printable tail instead of cutting a string.
                    if (stringOffset + stringLength >= typeOffset + typeLength) {
                        val stringEnd = strings + stringLength
                        var scan = stringEnd
                        while (scan < kernel.size && scan - stringEnd < MAX_BTF_STR_EXTENSION) {
                            val byte = kernel[scan].toInt() and 0xFF
                            if (byte == 0) {
                                if (scan + 1 < kernel.size &&
                                    (0x20..0x7E).contains(kernel[scan + 1].toInt() and 0xFF)
                                ) {
                                    scan += 1
                                    continue
                                }
                                break
                            }
                            if ((0x20..0x7E).contains(byte)) {
                                val windowEnd = minOf(scan + 256, kernel.size)
                                val next = findSubsliceIn(kernel, byteArrayOf(0), scan, windowEnd)
                                if (next != null) {
                                    scan = next
                                    continue
                                }
                                break
                            }
                            break
                        }
                        total = maxOf(total, (scan - pos).toLong())
                    }
                    val blob = BtfBlob(pos, kernel.copyOfRange(pos, (pos + total).toInt()))
                    if (best == null || blob.bytes.size > best.bytes.size) best = blob
                }
            }
            return best
        }

        /** `value` rounded up to the next multiple of `size` (power of two). */
        fun align(value: Int, size: Int): Int = (value + size - 1) and (size - 1).inv()

        fun findSubslice(haystack: ByteArray, needle: ByteArray, from: Int = 0): Int? {
            if (needle.isEmpty() || haystack.size < needle.size) return null
            val start = from.coerceIn(0, haystack.size)
            var i = start
            val last = haystack.size - needle.size
            while (i <= last) {
                var j = 0
                while (j < needle.size && haystack[i + j] == needle[j]) j++
                if (j == needle.size) return i
                i++
            }
            return null
        }

        fun findSubsliceIn(haystack: ByteArray, needle: ByteArray, from: Int, to: Int): Int? {
            if (needle.isEmpty()) return from
            val start = from.coerceIn(0, haystack.size)
            val end = to.coerceAtMost(haystack.size)
            if (end < needle.size) return null
            var i = start
            while (i <= end - needle.size) {
                var j = 0
                while (j < needle.size && haystack[i + j] == needle[j]) j++
                if (j == needle.size) return i
                i++
            }
            return null
        }

        internal fun readU16(data: ByteArray, offset: Int): Int =
            (data[offset].toInt() and 0xFF) or ((data[offset + 1].toInt() and 0xFF) shl 8)

        internal fun readU32(data: ByteArray, offset: Int): Int =
            (data[offset].toInt() and 0xFF) or
                ((data[offset + 1].toInt() and 0xFF) shl 8) or
                ((data[offset + 2].toInt() and 0xFF) shl 16) or
                ((data[offset + 3].toInt() and 0xFF) shl 24)

        internal fun readU64(data: ByteArray, offset: Int): Long {
            var value = 0L
            for (i in 0 until 8) {
                value = value or ((data[offset + i].toLong() and 0xFF) shl (8 * i))
            }
            return value
        }

        internal fun readI32(data: ByteArray, offset: Int): Int = readU32(data, offset)

        internal fun putU16Le(data: ByteArray, offset: Int, value: Int) {
            data[offset] = (value and 0xFF).toByte()
            data[offset + 1] = ((value ushr 8) and 0xFF).toByte()
        }

        internal fun putU32Le(data: ByteArray, offset: Int, value: Int) {
            data[offset] = (value and 0xFF).toByte()
            data[offset + 1] = ((value ushr 8) and 0xFF).toByte()
            data[offset + 2] = ((value ushr 16) and 0xFF).toByte()
            data[offset + 3] = ((value ushr 24) and 0xFF).toByte()
        }

        internal fun putU64Le(data: ByteArray, offset: Int, value: Long) {
            for (i in 0 until 8) data[offset + i] = ((value ushr (8 * i)) and 0xFF).toByte()
        }

        @Throws(IOException::class)
        private fun gunzip(data: ByteArray): ByteArray = try {
            GZIPInputStream(data.inputStream()).use { it.readBytes() }
        } catch (error: IOException) {
            throw IOException("invalid gzip payload: ${error.message}", error)
        }
    }
}
