package dev.maplesu.manager.ultrakernel

/** A boot-only filter at the common init_module/finit_module loader, including first-stage init. */
internal object UltraKernelVivoFilter {
    const val ROLE = "vivo-vr-filter"

    fun records(kernel: ByteArray, occupied: List<UltraKernelPlan.PatchRecord> = emptyList()): List<UltraKernelPlan.PatchRecord> {
        val symbols = UltraKernelKallsymsTable.decode(kernel)
        val layout = layout(kernel, symbols)
        val body = UltraKernelVivoPayload.bytes()
        val cave = padding(kernel, symbols, body.size, occupied)
        return listOf(
            UltraKernelPlan.PatchRecord("$ROLE-body", cave.toLong(), kernel.copyOfRange(cave, cave + body.size),
                render(layout, cave)),
            UltraKernelPlan.PatchRecord("$ROLE-entry", layout.site.toLong(), kernel.copyOfRange(layout.site, layout.site + 4),
                ByteArray(4).also { UltraKernelA64.writeLe32(it, 0,
                    UltraKernelA64.encodeB(layout.site.toLong(), cave.toLong()).toLong() and 0xffffffffL) }),
        )
    }

    private data class Layout(val site: Int, val displaced: Int, val returnSite: Int,
        val hdr: Int, val len: Int, val vfree: Int, val decompress: Int?)

    private fun layout(kernel: ByteArray, symbols: UltraKernelSymbols, original: Int? = null): Layout {
        val start = required(symbols, "load_module")
        val end = requireNotNull(symbols.nextOffset(start)) { "INSTALLER_VR_LOADER_UNSUPPORTED" }
        val first = word(kernel, start)
        val pac = first == 0xd503233f.toInt() || first == 0xd503231f.toInt()
        val site = start + if (pac || first == 0xd503245f.toInt()) 4 else 0
        val displaced = original ?: word(kernel, site)
        // Relocate only a stack allocation or preindexed FP/LR pair. PC-relative instructions
        // and runtime PAC/SCS words must stay at their original unwind addresses.
        check(displaced and 0xffc003ff.toInt() == 0xd10003ff.toInt() ||
            displaced and 0xffc07fff.toInt() == 0xa9807bfd.toInt()) { "INSTALLER_VR_LOADER_PROLOGUE" }
        val returns = (start until end - 3 step 4).filter { word(kernel, it) == UltraKernelA64.RET }
        val returnSite = if (pac) returns.firstOrNull {
            it >= 4 && word(kernel, it - 4) in setOf(0xd50323bf.toInt(), 0xd503239f.toInt())
        }?.minus(4) else returns.firstOrNull()
        check(returnSite != null) { "INSTALLER_VR_LOADER_EPILOGUE" }
        // The embedded displaced instruction must restore the loader's real stack layout.
        // This also detects tampering of that relocation when inspecting an existing filter.
        val restore = word(kernel, returnSite - 4)
        check(if (displaced and 0xffc003ff.toInt() == 0xd10003ff.toInt()) {
            restore == (displaced xor 0x40000000)
        } else {
            val allocation = -(UltraKernelA64.signExtend((displaced ushr 15 and 127).toLong(), 7) * 8).toInt()
            allocation > 0 && restore == (0xa8c07bfd.toInt() or (allocation / 8 shl 15))
        }) { "INSTALLER_VR_LOADER_STACK" }

        // Prove load_info's layout from the loader's own length/header validation. No version
        // table or hardcoded OEM struct offset is used.
        val layouts = (start until minOf(end - 32, start + 384) step 4).mapNotNull { at ->
            val len = word(kernel, at)
            val cmp = word(kernel, at + 4)
            val condition = word(kernel, at + 8)
            if (len and 0xffc00000.toInt() != 0xf9400000.toInt() ||
                cmp ushr 5 and 31 != len and 31 ||
                condition and 0xff000010.toInt() != 0x54000000 ||
                !(cmp and 0xfffffc1f.toInt() == 0xf100fc1f.toInt() && condition and 15 == 9 ||
                    cmp and 0xfffffc1f.toInt() == 0xf101001f.toInt() && condition and 15 == 3)) return@mapNotNull null
            val lenOffset = inputOffset(kernel, start, at, len ushr 5 and 31)?.plus((len ushr 10 and 4095) * 8)
                ?: return@mapNotNull null
            val headers = (at + 12..at + 20 step 4).mapNotNull { headerAt ->
                val hdr = word(kernel, headerAt)
                val unsigned = hdr and 0xffc00000.toInt() == 0xf9400000.toInt()
                val preindexed = hdr and 0xffe00c00.toInt() == 0xf8400c00.toInt()
                if ((!unsigned && !preindexed) ||
                    word(kernel, headerAt + 4) and 0xffffffe0.toInt() != 0x5288afe0 ||
                    word(kernel, headerAt + 8) and 0xffffffe0.toInt() != 0x72a8c980 ||
                    word(kernel, headerAt + 12) and 0xffffffe0.toInt() != (0xb9400000.toInt() or ((hdr and 31) shl 5))) null
                else inputOffset(kernel, start, headerAt, hdr ushr 5 and 31)?.plus(
                    if (unsigned) (hdr ushr 10 and 4095) * 8 else UltraKernelA64.signExtend((hdr ushr 12 and 511).toLong(), 9).toInt())
            }.distinct()
            headers.singleOrNull()?.let { it to lenOffset }
        }.distinct()
        check(layouts.size == 1) { "INSTALLER_VR_LOADER_LAYOUT" }
        val (hdr, len) = layouts.single()
        check(hdr in 0..256 && len == hdr + 8) { "INSTALLER_VR_LOADER_LAYOUT" }
        val vfree = required(symbols, "vfree")
        val decompress = symbols.offsetOf("module_decompress_cleanup")
        // A real loader-owned vfree call must use this same header offset.
        val directCleanup = (start until end - 7 step 4).any { at ->
            val ins = word(kernel, at)
            ins and 0xffc0001f.toInt() == 0xf9400000.toInt() &&
                (ins ushr 10 and 4095) * 8 == hdr && branch(kernel, at + 4) == vfree
        }
        // Older LTO kernels inline vfree's wrapper; prove the same __vunmap(..., 1)
        // call exists in both vfree and the loader, rather than guessing a free function.
        val vunmap = symbols.offsetOf("__vunmap")
        val inlineCleanup = vunmap != null && (vfree until minOf(vfree + 512, kernel.size - 4) step 4).any {
            branch(kernel, it) == vunmap
        } && (start + 4 until end - 7 step 4).any { at ->
            val move = word(kernel, at - 4)
            if (word(kernel, at) != 0x52800021 || branch(kernel, at + 4) != vunmap ||
                move and 0xffe0ffff.toInt() != 0xaa0003e0.toInt()) return@any false
            val rt = move ushr 16 and 31
            (maxOf(start, at - 68) until at - 4 step 4).any { loadAt ->
                val load = word(kernel, loadAt)
                load and 0xffc0001f.toInt() == (0xf9400000.toInt() or rt) &&
                    (loadAt + 4 until at - 4 step 4).all { gap ->
                        val w = word(kernel, gap)
                        w and 31 != rt || conditionalTarget(kernel, gap) != null
                    } && inputOffset(kernel, start, loadAt, load ushr 5 and 31)
                        ?.plus((load ushr 10 and 4095) * 8) == hdr
            }
        }
        check(directCleanup || inlineCleanup) { "INSTALLER_VR_LOADER_CLEANUP" }
        return Layout(site, displaced, returnSite, hdr, len, vfree, decompress)
    }

    private fun render(layout: Layout, cave: Int): ByteArray {
        val body = UltraKernelVivoPayload.bytes()
        fun put(at: Int, value: Int) = UltraKernelA64.writeLe32(body, at, value.toLong() and 0xffffffffL)
        fun jump(at: Int, target: Int) = put(at, UltraKernelA64.encodeB((cave + at).toLong(), target.toLong()))
        put(UltraKernelVivoPayload.HDR, 0x52800002 or (layout.hdr shl 5))
        put(UltraKernelVivoPayload.LEN, 0x52800003 or (layout.len shl 5))
        put(UltraKernelVivoPayload.COMPRESSED, 0x52800004 or (if (layout.decompress != null) 32 else 0))
        put(UltraKernelVivoPayload.RELEASE_HDR, 0xf9400000.toInt() or ((layout.hdr / 8) shl 10))
        put(UltraKernelVivoPayload.DISPLACED, layout.displaced)
        jump(UltraKernelVivoPayload.CONTINUE, layout.site + 4)
        jump(UltraKernelVivoPayload.RETURN, layout.returnSite)
        jump(UltraKernelVivoPayload.VFREE, layout.vfree)
        // When no decompressor exists the parser forwards compressed input unchanged.
        jump(UltraKernelVivoPayload.DECOMPRESS, layout.decompress ?: layout.vfree)
        return body
    }

    fun present(kernel: ByteArray): Boolean = runCatching {
        val s = UltraKernelKallsymsTable.decode(kernel)
        val start = required(s, "load_module")
        val site = if (word(kernel, start) in setOf(0xd503233f.toInt(), 0xd503231f.toInt(), 0xd503245f.toInt())) start + 4 else start
        val target = branch(kernel, site, link = false) ?: return false
        val expected = UltraKernelVivoPayload.bytes()
        if (target < 0 || target + expected.size > kernel.size) return false
        if (target < required(s, "_stext") || target + expected.size > required(s, "_etext") ||
            s.hasSymbolIn(target, target + expected.size)) return false
        val body = render(layout(kernel, s, word(kernel, target + UltraKernelVivoPayload.DISPLACED)), target)
        body.contentEquals(kernel.copyOfRange(target, target + body.size))
    }.getOrDefault(false)

    private fun required(s: UltraKernelSymbols, name: String) = s.offsetOf(name) ?: error("INSTALLER_VR_LOADER_UNSUPPORTED")

    /** Trace only proven MOV/ADD/writeback aliases of the entry's load_info pointer. */
    private fun inputOffset(b: ByteArray, start: Int, before: Int, register: Int): Int? {
        var reg = register
        var offset = 0
        var at = before - 4
        while (at >= start) {
            val w = word(b, at)
            // An early-return block is not on the path to the following validation block.
            if (w == UltraKernelA64.RET) {
                val incoming = (start until at step 4).filter { conditionalTarget(b, it) == at + 4 }
                if (incoming.size != 1) return null
                at = incoming.single() - 4
                continue
            }
            val rd = w and 31
            val rn = w ushr 5 and 31
            when {
                w and 0xffe0ffe0.toInt() == 0xaa0003e0.toInt() && rd == reg -> reg = w ushr 16 and 31
                w and 0xffc00000.toInt() == 0x91000000.toInt() && rd == reg -> {
                    offset += w ushr 10 and 4095; reg = rn
                }
                w and 0xfc000000.toInt() == 0x94000000.toInt() -> if (reg < 19) return null
                w and 0x0a000000 == 0x08000000 -> {
                    val pair = w and 0x3a000000 == 0x28000000
                    if (w and 0x00400000 != 0 && (rd == reg || pair && w ushr 10 and 31 == reg)) return null
                    if (rn == reg && w and 0xffe00c00.toInt() == 0xf8400c00.toInt()) {
                        offset += UltraKernelA64.signExtend((w ushr 12 and 511).toLong(), 9).toInt()
                    } else if (rn == reg && (pair && w and 0x01800000 != 0x01000000 ||
                            !pair && w and 0x01000000 == 0 && w and 0x400 != 0)) return null
                }
                w and 0x7c000000 == 0x14000000 || w and 0xff000010.toInt() == 0x54000000 ||
                    w and 0x7e000000 in setOf(0x34000000, 0x36000000) -> Unit
                rd == reg -> return null
            }
            at -= 4
        }
        return offset.takeIf { reg == 0 && it in 0..256 }
    }
    private fun word(b: ByteArray, at: Int) = UltraKernelA64.le32Bits(b, at)
    private fun conditionalTarget(b: ByteArray, at: Int): Int? {
        val w = word(b, at)
        val bits = when {
            w and 0xff000010.toInt() == 0x54000000 || w and 0x7e000000 == 0x34000000 -> 19
            w and 0x7e000000 == 0x36000000 -> 14
            else -> return null
        }
        return at + (UltraKernelA64.signExtend((w ushr 5 and ((1 shl bits) - 1)).toLong(), bits) * 4).toInt()
    }
    private fun branch(b: ByteArray, at: Int, link: Boolean = true): Int? {
        val w = word(b, at)
        if (w and 0xfc000000.toInt() != if (link) 0x94000000.toInt() else 0x14000000) return null
        return at + (UltraKernelA64.signExtend((w and 0x3ffffff).toLong(), 26) * 4).toInt()
    }

    private fun padding(b: ByteArray, s: UltraKernelSymbols, size: Int,
                        occupied: List<UltraKernelPlan.PatchRecord>): Int {
        val start = required(s, "_stext")
        val end = required(s, "_etext")
        val blocked = UltraKernelCaveAllocator.runtimePatchSites(s, b) + occupied.map {
            UltraKernelCaveAllocator.Span(it.offset.toInt(), (it.offset + it.length).toInt())
        }
        var run = 0
        for (at in start until end - 3 step 4) {
            run = if (word(b, at) == 0 || word(b, at) == UltraKernelA64.NOP) run + 4 else 0
            if (run < size) continue
            val candidate = at + 4 - size
            if (s.hasSymbolIn(candidate, candidate + size) ||
                blocked.any { it.start < candidate + size && candidate < it.end }) continue
            val prev = s.nameBefore(candidate).orEmpty()
            if (listOf("__init", "_init", "__exception", "__entry", "__meminit").any(prev::startsWith)) continue
            return candidate
        }
        error("INSTALLER_VR_KERNEL_SPACE_REQUIRED")
    }
}
