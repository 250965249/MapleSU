package dev.maplesu.manager.ultrakernel

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Target linker facts for a publication slot; this does not activate a carrier. */
internal object UltraKernelResidentStorage {
    const val SLOT_BYTES = 64

    data class Candidate(
        val slotOffset: Int,
        val gapStart: Int,
        val gapEnd: Int,
        val pageShift: Int,
        val imageMemoryBytes: Int,
        val dataStart: Int,
        val bssStart: Int,
        val bssStop: Int,
        val pageDirectoryEnd: Int,
        val bootInitializerOffset: Int,
    ) {
        // A file-external alignment gap is not implicitly zero. The boot wrapper must
        // initialize this slot once before any request can discover the host.
        val requiresBootInitialization: Boolean get() = true
        // Symbol boundaries describe the gap, but do not attest a vendor's page tables.
        val requiresTargetMappingProof: Boolean get() = true
    }

    fun candidate(kernel: ByteArray, symbols: UltraKernelSymbols): Candidate {
        fun fact(valid: Boolean, reason: String) {
            if (!valid) throw UltraKernelGenerateException(
                "ULTRA_KERNEL_GENERATE_RESIDENT_STORAGE", reason)
        }
        fun boundary(vararg names: String): Int {
            val offsets = names.flatMap(symbols::memoryOffsetsOf).distinct()
            fact(offsets.size == 1, "BOUNDARY_MISSING_OR_AMBIGUOUS:${names.joinToString("/")}")
            return offsets.single()
        }
        fact(kernel.size >= 64 && symbols.imageSize == kernel.size, "IMAGE_BOUNDS")
        fact(symbols is UltraKernelKallsymsTable, "MEMORY_SYMBOL_TABLE_INCOMPLETE")
        fact(kernel[56] == 'A'.code.toByte() && kernel[57] == 'R'.code.toByte() &&
            kernel[58] == 'M'.code.toByte() && kernel[59] == 'd'.code.toByte(), "IMAGE_MAGIC")
        val header = ByteBuffer.wrap(kernel, 0, 64).order(ByteOrder.LITTLE_ENDIAN)
        val memoryBytes = header.getLong(16)
        val flags = header.getLong(24)
        fact(memoryBytes in 64L..Int.MAX_VALUE.toLong(), "IMAGE_MEMORY_SIZE")
        fact(flags and 1L == 0L, "IMAGE_ENDIAN")
        val pageShift = when ((flags ushr 1).toInt() and 3) {
            1 -> 12
            2 -> 14
            3 -> 16
            else -> { fact(false, "IMAGE_PAGE_SIZE"); error("unreachable") }
        }
        val text = boundary("_text")
        val textEnd = boundary("_etext")
        val initBegin = boundary("__init_begin")
        val initEnd = boundary("__init_end")
        val data = boundary("_data")
        val bss = boundary("__bss_start")
        val bssStop = boundary("__bss_stop")
        val directory = boundary("init_pg_dir", "__pi_init_pg_dir")
        val directoryEnd = boundary("init_pg_end", "__pi_init_pg_end")
        val end = boundary("_end")
        fact(text == 0 && end.toLong() == memoryBytes, "IMAGE_RESERVED_BOUNDARY")
        fact(textEnd > 0 && textEnd <= initBegin && initBegin < initEnd &&
            initEnd <= data && data <= bss && bss < bssStop && bssStop < directory &&
            directory < directoryEnd && directoryEnd <= end, "SECTION_ORDER")
        val pageMask = (1L shl pageShift) - 1
        fact(data.toLong() and pageMask == 0L && initBegin.toLong() and pageMask == 0L &&
            initEnd.toLong() and pageMask == 0L, "SECTION_ALIGNMENT")
        fact((bssStop.toLong() + pageMask) and pageMask.inv() == directory.toLong(),
            "PAGE_DIRECTORY_ALIGNMENT_GAP")
        fact(directoryEnd.toLong() and pageMask == 0L, "PAGE_DIRECTORY_END_ALIGNMENT")
        fact(!symbols.hasMemorySymbolIn(bssStop + 1, directory), "GAP_SYMBOL_OCCUPIED")
        val slot = (bssStop.toLong() + SLOT_BYTES - 1) and -(SLOT_BYTES.toLong())
        fact(slot + SLOT_BYTES <= directory, "GAP_CAPACITY")
        val initializer = symbols.offsetsOf("kernel_init_freeable").singleOrNull()
        fact(initializer != null && initializer % 4 == 0 &&
            initializer >= initBegin && initializer < initEnd, "BOOT_INITIALIZER_MISSING_OR_AMBIGUOUS")
        return Candidate(slot.toInt(), bssStop, directory, pageShift, memoryBytes.toInt(),
            data, bss, bssStop, directoryEnd, initializer!!)
    }

    /** Select the actual boot call; this alone does not prove initcall readiness. */
    fun bootCallsite(kernel: ByteArray, symbols: UltraKernelSymbols, storage: Candidate): Int {
        fun requireBoot(valid: Boolean, reason: String) {
            if (!valid) throw UltraKernelGenerateException(
                "ULTRA_KERNEL_GENERATE_RESIDENT_BOOT", reason)
        }
        val callers = symbols.offsetsOf("kernel_init").distinct()
        requireBoot(callers.size == 1, "KERNEL_INIT_MISSING_OR_AMBIGUOUS")
        val begin = callers.single()
        val end = symbols.nextOffset(begin)
        requireBoot(begin >= 0 && begin % 4 == 0 && end != null && end > begin &&
            end <= kernel.size && end % 4 == 0, "KERNEL_INIT_BOUNDS")
        requireBoot(UltraKernelBtf.functionSignature(kernel, symbols, "kernel_init") ==
            "fi4:16777248(*v;)" && UltraKernelBtf.functionSignature(kernel, symbols,
            "kernel_init_freeable") == "fv()", "BOOT_FUNCTION_ABI")
        val calls = (begin until end!! step 4).filter { at ->
            UltraKernelA64.le32Bits(kernel, at) == UltraKernelA64.encodeBl(
                at.toLong(), storage.bootInitializerOffset.toLong())
        }
        requireBoot(calls.size == 1, "FREEABLE_CALL_MISSING_OR_AMBIGUOUS")
        return calls.single()
    }
}
