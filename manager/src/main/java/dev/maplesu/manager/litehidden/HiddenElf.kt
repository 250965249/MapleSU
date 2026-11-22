package dev.maplesu.manager.litehidden

import dev.maplesu.manager.workmode.Hashes
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** 一个 ELF 文件的静态事实（只读解析，不执行任何东西）。 */
data class ElfInspection(
    val type: Int,
    val machine: Int,
    val needed: List<String>,
    val soname: String?,
    val programHeaderCount: Int,
    val hasSectionTable: Boolean,
) {
    val isSharedObject: Boolean get() = type == HiddenElf.ET_DYN
    val isAarch64: Boolean get() = machine == HiddenElf.EM_AARCH64
}

/** 注入结果：成功带回新字节 + 结构事实；失败必须给结构化码（调用方不得猜）。 */
sealed interface ElfPatchResult {
    data class Ok(
        val bytes: ByteArray,
        val sha256: String,
        val inserted: Boolean,
        val neededBefore: List<String>,
        val neededAfter: List<String>,
        val loaderVaddr: Long,
        val loaderOffset: Long,
        val loaderSize: Long,
        val spareProgramHeader: Int,
    ) : ElfPatchResult

    data class Failed(val code: String, val detail: String) : ElfPatchResult
}

/**
 * 最小 ELF64 小端 `DT_NEEDED` 注入器 —— **纯 Kotlin 移植**，逻辑逐条对应
 * `.analysis/parasite-spike-20261030/patcher/elf_dt_needed.py`（R&D spike 已在真机验证）。
 *
 * 变换（完整陈述，没有隐含副作用）：
 * 1. 解析 ELF64 program headers，要求 `ET_DYN`；
 * 2. 读既有 dynamic 数组与字符串表（`DT_STRTAB` / `DT_STRSZ`）；
 * 3. 字符串表**原样复制**到文件尾并追加新库名；因为复制体逐字节相同、只在尾部增长，
 *    所有既有 `st_name` / `DT_NEEDED` / `DT_SONAME` 偏移继续有效；
 * 4. 组装新 dynamic 数组：原有条目（`DT_STRTAB`/`DT_STRSZ` 重新指向新副本）+ 一条新
 *    `DT_NEEDED` + `DT_NULL`；
 * 5. 复用一条空 program header（`PT_NULL` 优先，其次 `PT_NOTE`）改成只读 `PT_LOAD`
 *    映射追加区，并把 `PT_DYNAMIC` 指向新数组；
 * 6. 若存在 section table，同步 `SHT_DYNAMIC`/`SHT_STRTAB` 的地址/偏移/大小，让
 *    `readelf`/`objdump` 与 program header 不打架（bionic 只用 program header）。
 *
 * 宿主自己的代码/数据/重定位**零改动**：唯一的语义差异是加载顺序里多一个共享库。
 * 这是寄生方案的硬前提，也是回滚可以做到 sha 级复原的原因。
 */
object HiddenElf {

    const val EM_AARCH64 = 183
    const val ET_DYN = 3

    private const val ELF_MAGIC_0 = 0x7f
    private const val ELF_MAGIC_1 = 'E'.code
    private const val ELF_MAGIC_2 = 'L'.code
    private const val ELF_MAGIC_3 = 'F'.code
    private const val ELFCLASS64 = 2
    private const val ELFDATA2LSB = 1

    private const val PT_NULL = 0
    private const val PT_LOAD = 1
    private const val PT_DYNAMIC = 2
    private const val PT_NOTE = 4

    private const val DT_NULL = 0L
    private const val DT_NEEDED = 1L
    private const val DT_STRTAB = 5L
    private const val DT_STRSZ = 10L
    private const val DT_SONAME = 14L

    private const val SHT_STRTAB = 3L
    private const val SHT_DYNAMIC = 6L

    const val PHDR_SIZE = 56
    const val DYN_SIZE = 16
    const val SHDR_SIZE = 64

    private const val PF_R = 0x4L

    /** 结构问题的失败码（后端直接把这些码写进步骤 detail）。 */
    object Codes {
        const val NOT_ELF64_LE = "ELF_UNSUPPORTED_FORMAT"
        const val NOT_SHARED_OBJECT = "ELF_NOT_SHARED_OBJECT"
        const val TRUNCATED = "ELF_TRUNCATED"
        const val NO_DYNAMIC = "ELF_NO_DYNAMIC"
        const val NO_STRTAB = "ELF_NO_STRTAB"
        const val NO_SPARE_PHDR = "ELF_NO_SPARE_PHDR"
        const val INVALID_NAME = "ELF_INVALID_NEEDED_NAME"
        const val VERIFY_FAILED = "ELF_VERIFY_FAILED"
    }

    private class Load(val offset: Long, val vaddr: Long, val filesz: Long, val memsz: Long)

    private class Parsed(
        val data: ByteArray,
        val phoff: Long,
        val phentsize: Int,
        val phnum: Int,
        val shoff: Long,
        val shentsize: Int,
        val shnum: Int,
        val phdrs: List<ByteArray>,
        val loads: List<Load>,
    )

    /** 只读解析：非 ELF64LE 返回 null（调用方按「不是我们的目标」处理，不猜）。 */
    fun inspect(bytes: ByteArray): ElfInspection? {
        val parsed = parse(bytes) ?: return null
        val dynamicIndex = dynamicIndex(parsed.phdrs) ?: return null
        val entries = dynamicEntries(parsed, dynamicIndex)
        val (needed, soname) = neededNames(parsed, entries)
        return ElfInspection(
            type = readU16(bytes, 16),
            machine = readU16(bytes, 18),
            needed = needed,
            soname = soname,
            programHeaderCount = parsed.phnum,
            hasSectionTable = parsed.shnum > 0,
        )
    }

    /** 读 `DT_NEEDED` 列表（不做注入）；不是可解析 ELF64LE → 空列表。 */
    fun neededLibraries(bytes: ByteArray): List<String> = inspect(bytes)?.needed.orEmpty()

    /**
     * 注入一条 `DT_NEEDED`。已存在同名条目 → `inserted=false`（幂等，不重写字节）。
     * 任何结构不确定（无 spare phdr / 无 strtab / 越界）都返回 `Failed`，绝不猜测。
     */
    fun addNeeded(bytes: ByteArray, needed: String, align: Int = 0x4000): ElfPatchResult {
        if (needed.isEmpty() || needed.contains('/') || needed.contains('\u0000')) {
            return ElfPatchResult.Failed(Codes.INVALID_NAME, needed)
        }
        val parsed = parse(bytes)
            ?: return ElfPatchResult.Failed(Codes.NOT_ELF64_LE, "magic/class/data")
        val type = readU16(bytes, 16)
        if (type != ET_DYN) return ElfPatchResult.Failed(Codes.NOT_SHARED_OBJECT, "type=$type")
        val alignment = align.coerceAtLeast(0x1000)

        val dynamicIndex = dynamicIndex(parsed.phdrs)
            ?: return ElfPatchResult.Failed(Codes.NO_DYNAMIC, "no PT_DYNAMIC")
        val entries = dynamicEntries(parsed, dynamicIndex)
        val (neededBefore, _) = neededNames(parsed, entries)
        if (needed in neededBefore) {
            return ElfPatchResult.Ok(
                bytes = bytes,
                sha256 = Hashes.sha256(bytes),
                inserted = false,
                neededBefore = neededBefore,
                neededAfter = neededBefore,
                loaderVaddr = 0,
                loaderOffset = 0,
                loaderSize = 0,
                spareProgramHeader = -1,
            )
        }

        val strtabVaddr = entries.firstOrNull { it.first == DT_STRTAB }?.second
            ?: return ElfPatchResult.Failed(Codes.NO_STRTAB, "no DT_STRTAB")
        val strsz = entries.firstOrNull { it.first == DT_STRSZ }?.second
            ?: return ElfPatchResult.Failed(Codes.NO_STRTAB, "no DT_STRSZ")
        val strtabOffset = vaddrToOffset(parsed.loads, strtabVaddr, strsz)
            ?: return ElfPatchResult.Failed(Codes.NO_STRTAB, "strtab not mapped")
        if (strtabOffset + strsz > bytes.size) {
            return ElfPatchResult.Failed(Codes.TRUNCATED, "strtab past eof")
        }
        val oldStrings = bytes.copyOfRange(strtabOffset.toInt(), (strtabOffset + strsz).toInt())

        // 1. 新字符串表 = 原样副本 + 新名字（放在第一个空闲偏移）。
        val nameBytes = needed.toByteArray(Charsets.UTF_8) + byteArrayOf(0)
        val newNameOffset = oldStrings.size.toLong()
        val newStrings = oldStrings + nameBytes + ByteArray((8 - (oldStrings.size + nameBytes.size) % 8) % 8)

        // 2. 新 dynamic 数组：本注入器拥有的三个 tag 丢掉重写，其余按原顺序原样复制。
        val rewritten = entries.filter { it.first != DT_NULL && it.first != DT_STRTAB && it.first != DT_STRSZ }
        val dynamicSize = (rewritten.size + 4L) * DYN_SIZE

        // 3. 字符串表与 dynamic 数组一起放进文件尾新追加的只读 PT_LOAD。
        val fileEnd = bytes.size.toLong()
        val segmentOffset = alignUp(fileEnd, alignment.toLong())
        val segmentVaddr = alignUp(parsed.loads.maxOfOrNull { it.vaddr + it.memsz } ?: 0L, alignment.toLong())
        val stringsOffset = segmentOffset
        val dynamicOffset = alignUp(stringsOffset + newStrings.size, 8)
        val segmentFilesz = dynamicOffset + dynamicSize - segmentOffset
        val newStrtabVaddr = segmentVaddr + (stringsOffset - segmentOffset)
        val newDynVaddr = segmentVaddr + (dynamicOffset - segmentOffset)

        // 4. 组装 dynamic 字节。
        val finalEntries = buildList {
            add(DT_STRTAB to newStrtabVaddr)
            add(DT_STRSZ to newStrings.size.toLong())
            addAll(rewritten)
            add(DT_NEEDED to newNameOffset)
            add(DT_NULL to 0L)
        }
        val dynamicBytes = ByteArray(finalEntries.size * DYN_SIZE)
        val dynBuffer = ByteBuffer.wrap(dynamicBytes).order(ByteOrder.LITTLE_ENDIAN)
        for ((tag, value) in finalEntries) {
            dynBuffer.putLong(tag)
            dynBuffer.putLong(value)
        }

        // 5. 写出追加段。
        val out = ByteArray((dynamicOffset + dynamicSize).toInt())
        System.arraycopy(bytes, 0, out, 0, bytes.size)
        System.arraycopy(newStrings, 0, out, stringsOffset.toInt(), newStrings.size)
        System.arraycopy(dynamicBytes, 0, out, dynamicOffset.toInt(), dynamicBytes.size)

        // 6. 复用一条 spare phdr 作为新 PT_LOAD，并重指 PT_DYNAMIC。
        val spare = pickSpareProgramHeader(parsed.phdrs)
            ?: return ElfPatchResult.Failed(Codes.NO_SPARE_PHDR, "no PT_NULL/PT_NOTE")
        writeProgramHeader(
            out, parsed.phoff + spare.toLong() * parsed.phentsize,
            type = PT_LOAD, flags = PF_R, offset = segmentOffset, vaddr = segmentVaddr,
            filesz = segmentFilesz, memsz = segmentFilesz, align = alignment.toLong(),
        )
        writeProgramHeader(
            out, parsed.phoff + dynamicIndex.toLong() * parsed.phentsize,
            type = PT_DYNAMIC, flags = PF_R, offset = dynamicOffset, vaddr = newDynVaddr,
            filesz = dynamicSize, memsz = dynamicSize, align = 8,
        )

        // 7. section table 同步（没有 section table 就跳过：bionic 不需要它）。
        if (parsed.shnum > 0 && parsed.shoff > 0) {
            val oldDynVaddr = programHeader(parsed.phdrs[dynamicIndex]).vaddr
            for (index in 0 until parsed.shnum) {
                val base = parsed.shoff + index.toLong() * parsed.shentsize
                if (base + SHDR_SIZE > out.size) break
                val shType = readU32(out, base.toInt() + 4)
                val shAddr = readU64(out, base.toInt() + 16)
                when {
                    shType == SHT_DYNAMIC && shAddr == oldDynVaddr -> writeU64(
                        out, base.toInt() + 16, newDynVaddr,
                    ).also { writeU64(out, base.toInt() + 24, dynamicOffset) }
                        .also { writeU64(out, base.toInt() + 32, dynamicSize) }

                    shType == SHT_STRTAB && shAddr == strtabVaddr -> writeU64(
                        out, base.toInt() + 16, newStrtabVaddr,
                    ).also { writeU64(out, base.toInt() + 24, stringsOffset) }
                        .also { writeU64(out, base.toInt() + 32, newStrings.size.toLong()) }
                }
            }
        }

        val after = inspect(out)
            ?: return ElfPatchResult.Failed(Codes.VERIFY_FAILED, "patched file is not readable")
        if (needed !in after.needed) {
            return ElfPatchResult.Failed(Codes.VERIFY_FAILED, "new DT_NEEDED unreadable")
        }
        neededBefore.filter { it !in after.needed }.forEach { lost ->
            return ElfPatchResult.Failed(Codes.VERIFY_FAILED, "lost $lost")
        }
        return ElfPatchResult.Ok(
            bytes = out,
            sha256 = Hashes.sha256(out),
            inserted = true,
            neededBefore = neededBefore,
            neededAfter = after.needed,
            loaderVaddr = newStrtabVaddr,
            loaderOffset = stringsOffset,
            loaderSize = newStrings.size.toLong(),
            spareProgramHeader = spare,
        )
    }

    // ── 解析 ────────────────────────────────────────────────────────────────

    private fun parse(bytes: ByteArray): Parsed? {
        if (bytes.size < 64) return null
        if (bytes[0].toInt() and 0xff != ELF_MAGIC_0 ||
            bytes[1].toInt() and 0xff != ELF_MAGIC_1 ||
            bytes[2].toInt() and 0xff != ELF_MAGIC_2 ||
            bytes[3].toInt() and 0xff != ELF_MAGIC_3
        ) {
            return null
        }
        if (bytes[4].toInt() and 0xff != ELFCLASS64 || bytes[5].toInt() and 0xff != ELFDATA2LSB) return null
        val phoff = readU64(bytes, 32)
        val shoff = readU64(bytes, 40)
        val phentsize = readU16(bytes, 54)
        val phnum = readU16(bytes, 56)
        val shentsize = readU16(bytes, 58)
        val shnum = readU16(bytes, 60)
        if (phentsize != PHDR_SIZE) return null
        if (phoff <= 0 || phnum <= 0) return null
        if (phoff + phnum.toLong() * phentsize > bytes.size) return null
        val phdrs = (0 until phnum).map { index ->
            bytes.copyOfRange(
                (phoff + index.toLong() * phentsize).toInt(),
                (phoff + (index + 1).toLong() * phentsize).toInt(),
            )
        }
        val loads = phdrs.map { programHeader(it) }.filter { it.type == PT_LOAD }
            .map { Load(it.offset, it.vaddr, it.filesz, it.memsz) }
        if (loads.isEmpty()) return null
        val sectionTableOk = shentsize == SHDR_SIZE && shnum > 0 && shoff > 0 &&
            shoff + shnum.toLong() * shentsize <= bytes.size
        return Parsed(
            data = bytes,
            phoff = phoff,
            phentsize = phentsize,
            phnum = phnum,
            shoff = if (sectionTableOk) shoff else 0,
            shentsize = if (sectionTableOk) shentsize else 0,
            shnum = if (sectionTableOk) shnum else 0,
            phdrs = phdrs,
            loads = loads,
        )
    }

    private class ProgramHeader(
        val type: Int,
        val flags: Long,
        val offset: Long,
        val vaddr: Long,
        val filesz: Long,
        val memsz: Long,
        val align: Long,
    )

    private fun programHeader(raw: ByteArray): ProgramHeader {
        val buffer = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN)
        val type = buffer.getInt(0)
        val flags = buffer.getInt(4).toLong() and 0xffffffffL
        val offset = buffer.getLong(8)
        val vaddr = buffer.getLong(16)
        val filesz = buffer.getLong(32)
        val memsz = buffer.getLong(40)
        val align = buffer.getLong(48)
        return ProgramHeader(type, flags, offset, vaddr, filesz, memsz, align)
    }

    private fun dynamicIndex(phdrs: List<ByteArray>): Int? {
        phdrs.forEachIndexed { index, raw ->
            if (programHeader(raw).type == PT_DYNAMIC) return index
        }
        return null
    }

    private fun dynamicEntries(parsed: Parsed, index: Int): List<Pair<Long, Long>> {
        val header = programHeader(parsed.phdrs[index])
        if (header.offset < 0 || header.offset + header.filesz > parsed.data.size.toLong()) return emptyList()
        val out = mutableListOf<Pair<Long, Long>>()
        var cursor = header.offset
        while (cursor + DYN_SIZE <= header.offset + header.filesz) {
            val tag = readU64(parsed.data, cursor.toInt())
            val value = readU64(parsed.data, cursor.toInt() + 8)
            out += tag to value
            if (tag == DT_NULL) break
            cursor += DYN_SIZE
        }
        return out
    }

    private fun neededNames(parsed: Parsed, entries: List<Pair<Long, Long>>): Pair<List<String>, String?> {
        val strtabVaddr = entries.firstOrNull { it.first == DT_STRTAB }?.second ?: return emptyList<String>() to null
        val strsz = entries.firstOrNull { it.first == DT_STRSZ }?.second ?: return emptyList<String>() to null
        val offset = vaddrToOffset(parsed.loads, strtabVaddr, strsz) ?: return emptyList<String>() to null
        if (offset + strsz > parsed.data.size) return emptyList<String>() to null
        val strings = parsed.data.copyOfRange(offset.toInt(), (offset + strsz).toInt())
        fun stringAt(at: Long): String? {
            if (at < 0 || at >= strings.size) return null
            var end = at.toInt()
            while (end < strings.size && strings[end] != 0.toByte()) end++
            if (end >= strings.size) return null
            return String(strings, at.toInt(), end - at.toInt(), Charsets.UTF_8)
        }
        val needed = entries.filter { it.first == DT_NEEDED }.mapNotNull { stringAt(it.second) }
        val soname = entries.firstOrNull { it.first == DT_SONAME }?.let { stringAt(it.second) }
        return needed to soname
    }

    private fun vaddrToOffset(loads: List<Load>, vaddr: Long, size: Long): Long? {
        for (load in loads) {
            if (vaddr >= load.vaddr && vaddr + size <= load.vaddr + load.filesz) {
                return load.offset + (vaddr - load.vaddr)
            }
        }
        return null
    }

    private fun pickSpareProgramHeader(phdrs: List<ByteArray>): Int? {
        phdrs.forEachIndexed { index, raw -> if (programHeader(raw).type == PT_NULL) return index }
        phdrs.forEachIndexed { index, raw -> if (programHeader(raw).type == PT_NOTE) return index }
        return null
    }

    private fun writeProgramHeader(
        target: ByteArray,
        at: Long,
        type: Int,
        flags: Long,
        offset: Long,
        vaddr: Long,
        filesz: Long,
        memsz: Long,
        align: Long,
    ) {
        val buffer = ByteBuffer.wrap(target).order(ByteOrder.LITTLE_ENDIAN)
        val base = at.toInt()
        buffer.putInt(base, type)
        buffer.putInt(base + 4, flags.toInt())
        buffer.putLong(base + 8, offset)
        buffer.putLong(base + 16, vaddr)
        buffer.putLong(base + 24, vaddr)
        buffer.putLong(base + 32, filesz)
        buffer.putLong(base + 40, memsz)
        buffer.putLong(base + 48, align)
    }

    private fun alignUp(value: Long, alignment: Long): Long =
        if (alignment <= 1) value else (value + alignment - 1) / alignment * alignment

    private fun readU16(bytes: ByteArray, at: Int): Int =
        (bytes[at].toInt() and 0xff) or ((bytes[at + 1].toInt() and 0xff) shl 8)

    private fun readU32(bytes: ByteArray, at: Int): Long {
        var value = 0L
        for (index in 0 until 4) value = value or ((bytes[at + index].toLong() and 0xff) shl (8 * index))
        return value
    }

    private fun readU64(bytes: ByteArray, at: Int): Long {
        var value = 0L
        for (index in 0 until 8) value = value or ((bytes[at + index].toLong() and 0xff) shl (8 * index))
        return value
    }

    private fun writeU64(target: ByteArray, at: Int, value: Long) {
        for (index in 0 until 8) target[at + index] = ((value ushr (8 * index)) and 0xff).toByte()
    }
}
