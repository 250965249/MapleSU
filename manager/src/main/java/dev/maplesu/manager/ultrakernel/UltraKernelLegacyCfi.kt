package dev.maplesu.manager.ultrakernel

/** Cross-DSO CFI canonical entry identity from this image's own symbols/code.
 * This establishes identity only; it never invents a legacy 64-bit CFI type ID
 * or represents a copied arena as a registered module. */
internal object UltraKernelLegacyCfi {
    data class ImageFacts(
        val kernelSha256: String,
        val canonicalEntries: Map<String, CanonicalEntry>,
        val slowpathCallsites: Map<String, List<SlowpathCallsite>>,
    )

    /** Production entry: symbols are decoded from the very bytes being read. */
    fun inspectImage(kernel: ByteArray, names: Set<String>,
                     callers: Set<String>): ImageFacts {
        val symbols = UltraKernelKallsymsTable.decode(kernel)
        return ImageFacts(UltraKernelSpec.sha256(kernel),
            canonicalEntries(kernel, symbols, names),
            callers.sorted().associateWith { caller ->
                slowpathCallsites(kernel, symbols, caller).also {
                    require(it.isNotEmpty()) { "LEGACY_CFI_TYPEIDS_MISSING:$caller" }
                }
            })
    }
    data class CanonicalEntry(
        val symbol: String,
        val bodyOffset: Int,
        val canonicalOffset: Int,
        val instruction: Int,
    )

    fun canonicalEntry(kernel: ByteArray, symbols: UltraKernelSymbols,
                       name: String): CanonicalEntry {
        require(kernel.size == symbols.imageSize) { "LEGACY_CFI_IMAGE_IDENTITY" }
        require(name.isNotEmpty() && !name.endsWith(".cfi_jt")) { "LEGACY_CFI_BODY_NAME" }
        val body = symbols.offsetsOf(name).distinct().singleOrNull()
            ?: error("LEGACY_CFI_BODY_AMBIGUOUS:$name")
        val canonical = symbols.offsetsOf("$name.cfi_jt").distinct().singleOrNull()
            ?: error("LEGACY_CFI_CANONICAL_AMBIGUOUS:$name")
        require(body >= 0 && body and 3 == 0 && body <= kernel.size - 4) {
            "LEGACY_CFI_BODY_BOUNDS:$name"
        }
        require(canonical >= 0 && canonical and 3 == 0 && canonical <= kernel.size - 4) {
            "LEGACY_CFI_CANONICAL_BOUNDS:$name"
        }
        val prefix = word(kernel, canonical)
        val branchAt = if (prefix == 0xd503245f.toInt() || prefix == 0xd50324df.toInt()) canonical + 4 else canonical
        require(branchAt <= kernel.size - 4) { "LEGACY_CFI_CANONICAL_TRUNCATED:$name" }
        val word = word(kernel, branchAt)
        require(word and 0xfc000000.toInt() == 0x14000000) {
            "LEGACY_CFI_CANONICAL_BRANCH:$name"
        }
        // Sign extension before scaling: this also handles backwards branches.
        val displacement = (word shl 6 shr 4).toLong()
        require(branchAt.toLong() + displacement == body.toLong()) {
            "LEGACY_CFI_CANONICAL_TARGET:$name"
        }
        return CanonicalEntry(name, body, canonical, word)
    }

    fun canonicalEntries(kernel: ByteArray, symbols: UltraKernelSymbols,
                         names: Set<String>): Map<String, CanonicalEntry> =
        names.sorted().associateWith { canonicalEntry(kernel, symbols, it) }

    data class SlowpathCallsite(
        val caller: String,
        val callOffset: Int,
        val slowpathOffset: Int,
        val typeIdHex: String,
        val materializationOffsets: List<Int>,
    )

    /** Recover the actual 64-bit cross-DSO type argument at direct slowpath
     * calls. This is deliberately distinct from KCFI's 32-bit entry prefix.
     * An unrecognized materialization is an error, never an inferred ID. */
    fun slowpathCallsites(kernel: ByteArray, symbols: UltraKernelSymbols,
                          caller: String): List<SlowpathCallsite> {
        require(kernel.size == symbols.imageSize) { "LEGACY_CFI_IMAGE_IDENTITY" }
        val start = symbols.offsetsOf(caller).distinct().singleOrNull()
            ?: error("LEGACY_CFI_CALLER_AMBIGUOUS:$caller")
        val stop = symbols.nextOffset(start) ?: kernel.size
        require(start >= 0 && start and 3 == 0 && stop <= kernel.size && stop >= start &&
            stop - start <= 256 * 1024) { "LEGACY_CFI_CALLER_BOUNDS:$caller" }
        val targets = listOf("__cfi_slowpath", "__cfi_slowpath_diag").flatMap { name ->
            symbols.offsetsOf(name) + symbols.offsetsOf("$name.cfi_jt")
        }.map { it.toLong() }.toSet()
        require(targets.isNotEmpty()) { "LEGACY_CFI_SLOWPATH_MISSING" }
        val result = mutableListOf<SlowpathCallsite>()
        for (at in start until stop - 3 step 4) {
            val instruction = word(kernel, at)
            if (instruction and 0xfc000000.toInt() != 0x94000000.toInt()) continue
            val target = at.toLong() + (instruction shl 6 shr 4).toLong()
            if (target !in targets) continue
            val (id, origins) = constantArgument(kernel, start, at)
                ?: error("LEGACY_CFI_TYPE_ARGUMENT_UNPROVEN:$caller:$at")
            result += SlowpathCallsite(caller, at, target.toInt(),
                java.lang.Long.toUnsignedString(id, 16).padStart(16, '0'), origins)
        }
        return result
    }

    private fun constantArgument(kernel: ByteArray, start: Int,
                                 call: Int): Pair<Long, List<Int>>? {
        var register = 0 // first AAPCS64 argument is the 64-bit type ID
        var lanes = 0L
        var values = 0L
        val origins = mutableListOf<Int>()
        for (at in call - 4 downTo maxOf(start, call - 128) step 4) {
            val instruction = word(kernel, at)
            // Do not cross a control-flow boundary or another call.
            if (instruction and 0x7c000000 == 0x14000000 ||
                instruction and 0xff000010.toInt() == 0x54000000 ||
                instruction and 0x7e000000 == 0x34000000 ||
                instruction and 0x7e000000 == 0x36000000 ||
                instruction and 0xfe000000.toInt() == 0xd6000000.toInt()) return null
            if (instruction and 31 != register) continue
            val opcode = instruction and 0xff800000.toInt()
            if (opcode == 0xd2800000.toInt() || opcode == 0x92800000.toInt() ||
                opcode == 0xf2800000.toInt()) {
                origins += at
                val shift = ((instruction ushr 21) and 3) * 16
                val immediate = ((instruction ushr 5) and 0xffff).toLong() shl shift
                val mask = 0xffffL shl shift
                if (opcode == 0xf2800000.toInt()) {
                    // Backward walk: the closest write to a lane wins.
                    val fresh = mask and lanes.inv()
                    values = values or (immediate and fresh)
                    lanes = lanes or mask
                    if (lanes == -1L) return values to origins.reversed()
                    continue
                }
                val base = if (opcode == 0x92800000.toInt()) immediate.inv() else immediate
                return ((base and lanes.inv()) or values) to origins.reversed()
            }
            // MOV Xd, Xm (ORR Xd, XZR, Xm), with no shift.
            if (instruction and 0xffe0ffe0.toInt() == 0xaa0003e0.toInt()) {
                origins += at
                register = (instruction ushr 16) and 31
                if (register == 31) return values to origins.reversed()
                continue
            }
            // LDR Xt, literal: read the constant from this same bound image.
            if (instruction and 0xff000000.toInt() == 0x58000000) {
                val literal = at.toLong() + (instruction shl 8 shr 11).toLong()
                if (literal < 0 || literal > kernel.size.toLong() - 8) return null
                val where = literal.toInt()
                val value = (word(kernel, where).toLong() and 0xffffffffL) or
                    (word(kernel, where + 4).toLong() shl 32)
                origins += at
                return ((value and lanes.inv()) or values) to origins.reversed()
            }
            // Conservatively reject every other possible write to the tracked
            // register, including unsupported forms that may actually be stores.
            return null
        }
        return null
    }
    private fun word(kernel: ByteArray, offset: Int): Int =
        (kernel[offset].toInt() and 255) or
            ((kernel[offset + 1].toInt() and 255) shl 8) or
            ((kernel[offset + 2].toInt() and 255) shl 16) or
            ((kernel[offset + 3].toInt() and 255) shl 24)
}



