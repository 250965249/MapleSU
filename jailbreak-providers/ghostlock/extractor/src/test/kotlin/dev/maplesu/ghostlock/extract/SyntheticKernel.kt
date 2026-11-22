package dev.maplesu.ghostlock.extract

import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Synthetic-but-realistic fixtures for the host tests: a boot image whose kernel
 * really carries an arm64 Image header, a linux_banner release string, a valid
 * embedded BTF blob and a complete (pre-6.4 layout) kallsyms table, plus an OTA
 * ZIP with a `payload.bin` that contains that boot image.
 *
 * Nothing here is a recorded device artefact; the point is that the *parsers*
 * run for real on bytes that satisfy the same invariants a real image does.
 */
object SyntheticKernel {
    const val RELEASE = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k"
    const val IMAGE_SIZE = 0x200000
    val BASE: Long = 0xFFFFFFC080000000uL.toLong()

    private const val BANNER_OFFSET = 0x200
    private const val NAMES_OFFSET = 0x8000
    private const val COUNT = 2048
    private const val BTF_OFFSET = 0x18000

    class Fixture(
        val image: ByteArray,
        val bootImage: ByteArray,
    )

    fun build(): Fixture {
        val btf = BtfFixture.build()
        val names = symbolTable()
        require(names.size == COUNT)

        // Encode names into the kernel's kallsyms format.
        val tokens = tokenTable()
        val encoded = ByteArrayOutputStream()
        val markers = ArrayList<Int>()
        var cumulative = 0
        for ((index, entry) in names.withIndex()) {
            if (index % 256 == 0) markers.add(cumulative)
            val bytes = encodeName(entry.name, entry.type)
            encoded.write(bytes.size)
            encoded.write(bytes)
            cumulative += bytes.size + 1
        }
        val encodedNames = encoded.toByteArray()
        require(encodedNames.size == cumulative)
        require(markers.size == COUNT / 256)

        val image = ByteArray(maxOf(NAMES_OFFSET + encodedNames.size + 0x4000, BTF_OFFSET + btf.size))
        // arm64 Image header: "ARM\x64" at 0x38 and the declared image size at 0x10.
        copyAscii(image, 0x38, "ARM\u0064")
        putU64(image, 0x10, IMAGE_SIZE.toLong())
        copyAscii(image, BANNER_OFFSET, "Linux version $RELEASE (builder@host) (clang 17) #1 SMP PREEMPT")
        // BTF blob.
        System.arraycopy(btf, 0, image, BTF_OFFSET, btf.size)
        // kallsyms pre-6.4 layout: offsets, relative_base, num_syms+pad, names,
        // markers, token table, token index.
        val offsetsBytes = COUNT * 4
        val relativeBaseAt = NAMES_OFFSET - 16
        val offsetsAt = relativeBaseAt - align8(offsetsBytes)
        for ((index, entry) in names.withIndex()) putU32(image, offsetsAt + index * 4, entry.offset)
        putU64(image, relativeBaseAt, BASE)
        putU32(image, NAMES_OFFSET - 8, COUNT)
        putU32(image, NAMES_OFFSET - 4, 0)
        System.arraycopy(encodedNames, 0, image, NAMES_OFFSET, encodedNames.size)
        var cursor = align8(NAMES_OFFSET + encodedNames.size)
        for (marker in markers) {
            putU32(image, cursor, marker)
            cursor += 4
        }
        val tokenTableAt = cursor
        System.arraycopy(tokens, 0, image, tokenTableAt, tokens.size)
        var indexAt = align8(tokenTableAt + tokens.size)
        val tokenOffsets = tokenOffsets(tokens)
        for (i in 0 until 256) putU16(image, indexAt + i * 2, tokenOffsets[i])
        indexAt += 512
        require(indexAt <= BTF_OFFSET) { "fixture tables overlap the BTF blob" }

        return Fixture(image, wrapBootImage(image))
    }

    /** Android boot v4 wrapper with the kernel at `align(header_size, 4096)`. */
    fun wrapBootImage(kernel: ByteArray): ByteArray {
        val headerSize = 1584
        val start = align4096(headerSize)
        val out = ByteArray(start + kernel.size)
        copyAscii(out, 0, "ANDROID!")
        putU32(out, 8, kernel.size)
        putU32(out, 20, headerSize)
        putU32(out, 40, 4)
        System.arraycopy(kernel, 0, out, start, kernel.size)
        return out
    }

    /**
     * A `payload.bin` carrying [bootImage] as partition `boot`.
     * [xz] selects the REPLACE_XZ operation (type 8) instead of REPLACE (0).
     */
    fun payload(bootImage: ByteArray, blockSize: Int = 4096, xz: Boolean = false): ByteArray {
        val blocks = (bootImage.size + blockSize - 1) / blockSize
        val raw = bootImage.copyOf(blocks * blockSize)
        val data = if (xz) {
            val out = ByteArrayOutputStream()
            org.tukaani.xz.XZOutputStream(out, org.tukaani.xz.LZMA2Options()).use { it.write(raw) }
            out.toByteArray()
        } else {
            raw
        }
        // Build messages explicitly so the field numbers are visible.
        val extent = ByteArrayOutputStream().apply {
            writeVarintField(1, 0L)
            writeVarintField(2, blocks.toLong())
        }.toByteArray()
        val operation = ByteArrayOutputStream().apply {
            writeVarintField(1, if (xz) 8L else 0L)     // REPLACE / REPLACE_XZ
            writeVarintField(2, 0L)                     // data_offset
            writeVarintField(3, data.size.toLong())     // data_length
            writeBytesField(6, extent)                  // dst_extents
        }.toByteArray()
        val partition = ByteArrayOutputStream().apply {
            writeBytesField(1, "boot".toByteArray(Charsets.UTF_8))
            writeBytesField(8, operation)
        }.toByteArray()
        val manifest = ByteArrayOutputStream().apply {
            writeVarintField(3, blockSize.toLong()) // block_size
            writeBytesField(13, partition)          // partitions
        }.toByteArray()
        val header = ByteArrayOutputStream().apply {
            write("CrAU".toByteArray(Charsets.US_ASCII))
            // payload.bin header numbers are big-endian uint64/uint32.
            write(beU64(2))
            write(beU64(manifest.size.toLong()))
            write(beU32(0))
        }.toByteArray()
        return header + manifest + data
    }

    fun payloadImages(images: Map<String, ByteArray>): ByteArray {
        val blobs = ByteArrayOutputStream()
        val manifest = ByteArrayOutputStream().apply {
            writeVarintField(3, 4096L)
            for ((name, image) in images) {
                val blocks = (image.size + 4095) / 4096
                val data = image.copyOf(blocks * 4096)
                val extent = ByteArrayOutputStream().apply {
                    writeVarintField(1, 0L); writeVarintField(2, blocks.toLong())
                }.toByteArray()
                val operation = ByteArrayOutputStream().apply {
                    writeVarintField(1, 0L)
                    writeVarintField(2, blobs.size().toLong())
                    writeVarintField(3, data.size.toLong())
                    writeBytesField(6, extent)
                }.toByteArray()
                val partition = ByteArrayOutputStream().apply {
                    writeBytesField(1, name.toByteArray())
                    writeBytesField(8, operation)
                }.toByteArray()
                writeBytesField(13, partition)
                blobs.write(data)
            }
        }.toByteArray()
        return "CrAU".toByteArray() + beU64(2) + beU64(manifest.size.toLong()) +
            beU32(0) + manifest + blobs.toByteArray()
    }

    /** A stored-only ZIP containing `payload.bin`. */
    fun otaZip(payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            val entry = ZipEntry("payload.bin").apply {
                method = ZipEntry.STORED
                size = payload.size.toLong()
                compressedSize = payload.size.toLong()
                crc = CRC32().apply { update(payload) }.value
            }
            zip.putNextEntry(entry)
            zip.write(payload)
            zip.closeEntry()
        }
        return out.toByteArray()
    }

    fun writeTemp(bytes: ByteArray, name: String, directory: File): File {
        val file = File(directory, name)
        file.writeBytes(bytes)
        return file
    }

    // --- kallsyms symbol table -------------------------------------------------

    private class Symbol(val name: String, val offset: Int, val type: Char)

    /** Sorted by offset, which kallsyms requires. */
    private fun symbolTable(): List<Symbol> {
        val symbols = ArrayList<Symbol>()
        symbols.add(Symbol("_text", 0, 'T'))
        var offset = 0x1000
        for (name in listOf(
            "init_task", "init_cred", "root_task_group", "selinux_state",
            "selinux_blob_sizes", "security_hook_heads", "nfulnl_logger",
            "sysctl_bootid", "loggers", "empty_zero_page", "load_module",
        )) {
            symbols.add(Symbol(name, offset, if (name == "load_module") 't' else 'D'))
            offset += 0x1000
        }
        // Filler symbols keep the 256-name marker deltas inside 0x200..0x40000.
        var filler = 0x10000
        var index = 0
        while (symbols.size < COUNT - 3) {
            symbols.add(Symbol("sym%05d".format(index), filler, 'd'))
            filler += 8
            index++
        }
        symbols.add(Symbol("__start_BTF", BTF_OFFSET, 'D'))
        symbols.add(Symbol("__stop_BTF", BTF_OFFSET + BtfFixture.build().size, 'D'))
        symbols.add(Symbol("_end", IMAGE_SIZE, 'T'))
        return symbols.sortedBy { it.offset }
    }

    private fun encodeName(name: String, type: Char): ByteArray {
        val chars = (type + name).map { it.code }
        return ByteArray(chars.size) { chars[it].toByte() }
    }

    /** 256 NUL-terminated tokens; token[i] is the single char i for printable bytes. */
    private fun tokenTable(): ByteArray {
        val out = ByteArrayOutputStream()
        for (i in 0 until 256) {
            if (i in 0x20..0x7E) {
                out.write(i)
            } else {
                // Non-printable indices never appear in an encoded name; a
                // repeated placeholder token is still valid for the table.
                out.write('~'.code)
                out.write('~'.code)
            }
            out.write(0)
        }
        return out.toByteArray()
    }

    private fun tokenOffsets(tokens: ByteArray): IntArray {
        val offsets = IntArray(256)
        var position = 0
        for (i in 0 until 256) {
            offsets[i] = position
            while (position < tokens.size && tokens[position].toInt() != 0) position++
            position++
        }
        return offsets
    }

    // --- byte helpers ----------------------------------------------------------

    private fun align8(value: Int): Int = (value + 7) and 7.inv()
    private fun align4096(value: Int): Int = (value + 4095) and 4095.inv()

    private fun copyAscii(destination: ByteArray, offset: Int, value: String) {
        val bytes = value.toByteArray(Charsets.US_ASCII)
        System.arraycopy(bytes, 0, destination, offset, bytes.size)
    }

    private fun putU16(destination: ByteArray, offset: Int, value: Int) {
        destination[offset] = (value and 0xFF).toByte()
        destination[offset + 1] = ((value ushr 8) and 0xFF).toByte()
    }

    private fun putU32(destination: ByteArray, offset: Int, value: Int) {
        destination[offset] = (value and 0xFF).toByte()
        destination[offset + 1] = ((value ushr 8) and 0xFF).toByte()
        destination[offset + 2] = ((value ushr 16) and 0xFF).toByte()
        destination[offset + 3] = ((value ushr 24) and 0xFF).toByte()
    }

    private fun putU64(destination: ByteArray, offset: Int, value: Long) {
        for (i in 0 until 8) destination[offset + i] = ((value ushr (8 * i)) and 0xFF).toByte()
    }

    private fun leU32(value: Int): ByteArray = ByteArray(4) { ((value ushr (8 * it)) and 0xFF).toByte() }
    private fun leU64(value: Long): ByteArray = ByteArray(8) { ((value ushr (8 * it)) and 0xFF).toByte() }
    private fun beU32(value: Int): ByteArray = ByteArray(4) { ((value ushr (8 * (3 - it))) and 0xFF).toByte() }
    private fun beU64(value: Long): ByteArray = ByteArray(8) { ((value ushr (8 * (7 - it))) and 0xFF).toByte() }

    private fun varint(value: Long): ByteArray {
        val out = ByteArrayOutputStream()
        var remaining = value
        while (true) {
            val byte = (remaining and 0x7F).toInt()
            remaining = remaining ushr 7
            if (remaining == 0L) {
                out.write(byte)
                break
            }
            out.write(byte or 0x80)
        }
        return out.toByteArray()
    }

    private fun ByteArrayOutputStream.writeVarintField(number: Int, value: Long) {
        write(varint((number shl 3).toLong()))
        write(varint(value))
    }

    private fun ByteArrayOutputStream.writeBytesField(number: Int, value: ByteArray) {
        write(varint(((number shl 3) or 2).toLong()))
        write(varint(value.size.toLong()))
        write(value)
    }
}

/** Builds the minimal BTF blob the extractor needs (struct layouts only). */
object BtfFixture {
    private const val KIND_INT = 1
    private const val KIND_STRUCT = 4

    fun build(): ByteArray {
        val strings = ByteArrayOutputStream().apply { write(0) }
        val stringOffsets = HashMap<String, Int>()

        fun stringOffset(name: String): Int {
            stringOffsets[name]?.let { return it }
            val offset = strings.size()
            strings.write(name.toByteArray(Charsets.UTF_8))
            strings.write(0)
            stringOffsets[name] = offset
            return offset
        }
        val types = ByteArrayOutputStream()
        var nextId = 1

        fun addType(kind: Int, name: String, sizeOrType: Int, members: List<Triple<String, Int, Int>>): Int {
            val id = nextId++
            val vlen = if (kind == KIND_STRUCT) members.size else 0
            val info = (kind shl 24) or vlen
            types.write(leU32(stringOffset(name)))
            types.write(leU32(info))
            types.write(leU32(sizeOrType))
            // `struct btf_int` appends one u32 after the common header.
            if (kind == KIND_INT) types.write(leU32(0x00000020))
            if (kind == KIND_STRUCT) {
                for ((memberName, typeId, bitOffset) in members) {
                    types.write(leU32(stringOffset(memberName)))
                    types.write(leU32(typeId))
                    types.write(leU32(bitOffset))
                }
            }
            return id
        }

        val intType = addType(KIND_INT, "int", 4, emptyList())

        fun struct(name: String, size: Int, fields: List<Pair<String, Int>>): Int =
            addType(KIND_STRUCT, name, size, fields.map { (fieldName, byteOffset) ->
                Triple(fieldName, intType, byteOffset * 8)
            })

        struct("task_struct", 4096, listOf(
            "prio" to 132, "normal_prio" to 140, "sched_task_group" to 840,
            "pi_lock" to 2316, "pi_waiters" to 2336, "pi_top_task" to 2352,
            "pi_blocked_on" to 2360, "pid" to 1560, "tgid" to 1564,
            "atomic_flags" to 1496, "real_cred" to 2072, "cred" to 2080,
            "comm" to 2096, "tasks" to 1360, "seccomp" to 2280,
        ))
        struct("cred", 136, listOf(
            "uid" to 4, "securebits" to 36, "cap_inheritable" to 48, "security" to 128,
        ))
        struct("seccomp", 16, listOf("mode" to 0, "filter_count" to 4, "filter" to 8))
        struct("rt_mutex_waiter", 64, listOf("tree" to 0, "pi_tree" to 16, "task" to 48, "lock" to 56))
        struct("page", 64, listOf("compound_head" to 8, "page_type" to 24))
        struct("mm_struct", 0x3C0, emptyList())
        struct("slab", 64, listOf("slab_cache" to 8))

        val typeBytes = types.toByteArray()
        val stringBytes = strings.toByteArray()
        val header = ByteArray(24)
        putU16(header, 0, 0xEB9F)
        header[2] = 1
        header[3] = 0
        putU32(header, 4, 24)
        putU32(header, 8, 0)
        putU32(header, 12, typeBytes.size)
        putU32(header, 16, typeBytes.size)
        putU32(header, 20, stringBytes.size)
        return header + typeBytes + stringBytes
    }

    private fun leU32(value: Int): ByteArray = ByteArray(4) { ((value ushr (8 * it)) and 0xFF).toByte() }

    private fun putU16(destination: ByteArray, offset: Int, value: Int) {
        destination[offset] = (value and 0xFF).toByte()
        destination[offset + 1] = ((value ushr 8) and 0xFF).toByte()
    }

    private fun putU32(destination: ByteArray, offset: Int, value: Int) {
        destination[offset] = (value and 0xFF).toByte()
        destination[offset + 1] = ((value ushr 8) and 0xFF).toByte()
        destination[offset + 2] = ((value ushr 16) and 0xFF).toByte()
        destination[offset + 3] = ((value ushr 24) and 0xFF).toByte()
    }
}
