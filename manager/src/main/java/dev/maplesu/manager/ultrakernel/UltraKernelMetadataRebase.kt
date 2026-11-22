package dev.maplesu.manager.ultrakernel

/** Compatibility for the SDK's complete, standalone LR-to-metadata callback ABI. */
internal object UltraKernelMetadataRebase {
    private const val BODY_OFFSET = 116

    fun generate(a: UltraKernelAsm, _r: UltraKernelSymbolResolver, f: UltraKernelFields) {
        val legacy = requireNotNull(f.legacyMetadataDisplacement)
        val actual = requireNotNull(f.actualMetadataDisplacement)
        val oldBody = locator(legacy)
        val expected = words(PREFIX) + marker(BEGIN) + oldBody + words(SUFFIX)
        val rewritten = intArrayOf(
            UltraKernelA64.addImm(11, 30, 4, sub = true),
            if (actual < 0) UltraKernelA64.movn(12, actual.inv() and 0xffff)
            else UltraKernelA64.movz(12, actual and 0xffff),
            UltraKernelA64.movk(12, actual ushr 16, 16),
            UltraKernelA64.addReg(11, 11, 12),
        ).toMutableList()
        while (rewritten.size * 4 < oldBody.size) rewritten += UltraKernelA64.NOP

        // Replays the instruction displaced by the fallback executor's BL. Only
        // caller-saved scratch registers are used; x11, LR and SP are retained.
        a.emit(UltraKernelA64.addImm(17, 17, f.requireOffset(f.credSuid, UltraKernelStructOffsets.SUID)))
        a.emit(UltraKernelA64.ldAuto("ldr", 1, 11, 76, 4))
        a.emit(UltraKernelA64.cmpImm(1, expected.size, sf = 0))
        a.bCond(UltraKernelA64.CC, "out")
        a.cbz(0, "out")
        a.adr(2, "expected")
        a.emit(UltraKernelA64.movReg(3, 0))
        a.emit(UltraKernelA64.movz(4, expected.size / 4, sf = 0))
        a.mark("compare")
        a.emit(UltraKernelA64.ldImm9("ldr", 5, 2, 4, 4, 1))
        a.emit(UltraKernelA64.ldImm9("ldr", 6, 3, 4, 4, 1))
        a.emit(UltraKernelA64.cmpReg(5, 6, sf = 0))
        a.bCond(UltraKernelA64.NE, "out")
        a.emit(UltraKernelA64.addImm(4, 4, 1, sf = 0, setFlags = true, sub = true))
        a.bCond(UltraKernelA64.NE, "compare")
        a.emit(UltraKernelA64.addImm(3, 0, BODY_OFFSET))
        a.adr(2, "rebased")
        a.emit(UltraKernelA64.movz(4, rewritten.size, sf = 0))
        a.mark("copy")
        a.emit(UltraKernelA64.ldImm9("ldr", 5, 2, 4, 4, 1))
        a.emit(UltraKernelA64.ldAuto("str", 5, 3, 0, 4))
        // The SDK's earlier byte-copy flush precedes these new stores. Clean
        // every changed address before the executor publishes its RO/X pages.
        a.emit(UltraKernelA64.dcCvac(3))
        a.emit(UltraKernelA64.addImm(3, 3, 4))
        a.emit(UltraKernelA64.addImm(4, 4, 1, sf = 0, setFlags = true, sub = true))
        a.bCond(UltraKernelA64.NE, "copy")
        a.emit(UltraKernelA64.DSB_ISH)
        a.mark("out")
        a.emit(UltraKernelA64.RET)
        a.mark("expected")
        a.embed(expected)
        a.mark("rebased")
        a.embed(words(rewritten.map(Int::toLong).toLongArray()))
    }

    private fun locator(delta: Int): ByteArray {
        val result = mutableListOf(UltraKernelA64.movReg(11, 30), UltraKernelA64.addImm(11, 11, 4, sub = true))
        var initialised = false
        for (shift in 0..48 step 16) {
            val part = ((delta.toLong() ushr shift) and 0xffff).toInt()
            if (part == 0) continue
            result += if (initialised) UltraKernelA64.movk(12, part, shift) else UltraKernelA64.movz(12, part, shift)
            initialised = true
        }
        if (!initialised) result += UltraKernelA64.movz(12, 0)
        result += UltraKernelA64.addReg(11, 11, 12)
        return words(result.map(Int::toLong).toLongArray())
    }

    private fun words(values: LongArray): ByteArray = ByteArray(values.size * 4).also { bytes ->
        values.forEachIndexed { index, value -> UltraKernelA64.writeLe32(bytes, index * 4, value) }
    }

    private fun marker(value: String): ByteArray = value.toByteArray(Charsets.US_ASCII) + byteArrayOf(0)

    private const val BEGIN = "05YWtaGvdCvO80RRK5wuYlPiP5khll8YcJ4P2zGL53FIK9VG3EJGBY20vkCz1kO"
    private const val END = "7Cj4G79IYh5P9GpIBTMeLZsN1YBaylVD77IsAPgfnEhuWn8MGqEd8eBpEcmDoo5"
    private val PREFIX = longArrayOf(
        0xD503245F, 0xA9BF53F3, 0xA9BF5BF5, 0xA9BF63F7, 0xA9BF6BF9, 0xA9BF73FB,
        0xF844416A, 0xB9404D6C, 0xB940516D, 0xA9BF33EA, 0xA9BF47ED, 0xA9BF7BFD, 0x14000011,
    )
    private val SUFFIX = longArrayOf(0x14000011) +
        marker(END).let { bytes -> LongArray(bytes.size / 4) { UltraKernelA64.le32(bytes, it * 4) } } +
        longArrayOf(
            0xAA0B03E0, 0xA8C17BFD, 0xA8C147ED, 0xA8C133EA, 0xF900023F, 0xB8001220,
            0xD360FC01, 0x78005221, 0x91006231, 0xB900023F, 0xD370FC01, 0x79000221,
            0xA8C173FB, 0xA8C16BF9, 0xA8C163F7, 0xA8C15BF5, 0xA8C153F3, 0xD65F03C0,
        )
}
