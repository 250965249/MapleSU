package dev.maplesu.manager.ultrakernel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

/** Real r9 opcode/liveness pattern plus live-conflict and exact-width guards. */
class UltraKernelSavedIdOpcodeLivenessTest {
    private fun symbols(image: ByteArray, entries: Map<String, Int>) = object : UltraKernelSymbols {
        override val imageSize = image.size
        override fun offsetOf(name: String) = entries[name]
        override fun isSymbolStart(value: Int) = value in entries.values
        override fun nameAt(offset: Int) = entries.entries.firstOrNull { it.value == offset }?.key
        override fun nextOffset(offset: Int) = entries.values.filter { it > offset }.minOrNull()
        override val summary = "synthetic-inline-accessor"
    }

    private fun word(image: ByteArray, at: Int, value: Int) {
        for (byte in 0..3) image[at + byte] = (value ushr (byte * 8)).toByte()
    }

    private fun savedIdImage(ambiguous: Boolean = false, wrongWidth: Boolean = false, tailWord: Int? = null):
        Pair<ByteArray, UltraKernelSymbols> {
        val image = ByteArray(0x2000)
        val entries = linkedMapOf<String, Int>()
        fun emit(name: String, start: Int, words: List<Int>) {
            entries[name] = start
            entries["after_" + name] = start + words.size * 4
            words.forEachIndexed { index, value -> word(image, start + index * 4, value) }
        }
        val code = mutableListOf(UltraKernelA64.MRS_SP_EL0 or 3,
            UltraKernelA64.ldAuto("ldr", 3, 3, 64, 8), UltraKernelA64.ldAuto("ldr", 3, 3, 12, 4))
        for (temporary in 4..17) {
            val at = 0x100 + code.size * 4
            code += UltraKernelA64.encodeCbz(28, at.toLong(), (at + 8).toLong(), sf = true, nonZero = false)
            code += UltraKernelA64.movz(temporary, temporary)
        }
        tailWord?.let { code += it }
        if (ambiguous) {
            code += UltraKernelA64.MRS_SP_EL0 or 8
            code += UltraKernelA64.ldAuto("ldr", 8, 8, 64, 8)
            val at = 0x100 + code.size * 4
            code += UltraKernelA64.encodeCbz(28, at.toLong(), (at + 8).toLong(), sf = true, nonZero = false)
            code += UltraKernelA64.ldAuto("ldr", 3, 8, 16, 4)
        }
        code += UltraKernelA64.ldAuto("str", 3, 2, 0, if (wrongWidth) 1 else 4)
        code += UltraKernelA64.movz(0, 0, sf = 0)
        code += UltraKernelA64.RET
        emit("__do_sys_getresuid", 0x100, code)
        emit("__do_sys_getresgid", 0x800, listOf(UltraKernelA64.MRS_SP_EL0 or 3,
            UltraKernelA64.ldAuto("ldr", 3, 3, 64, 8), UltraKernelA64.ldAuto("ldr", 3, 3, 16, 4),
            UltraKernelA64.ldAuto("str", 3, 2, 0, 4), UltraKernelA64.movz(0, 0, sf = 0), UltraKernelA64.RET))
        for ((index, pair) in listOf("__arm64_sys_getuid" to 4, "__arm64_sys_geteuid" to 20,
            "__arm64_sys_getgid" to 8, "__arm64_sys_getegid" to 24).withIndex()) {
            emit(pair.first, 0x1000 + index * 0x40, listOf(UltraKernelA64.MRS_SP_EL0 or 8,
                UltraKernelA64.ldAuto("ldr", 8, 8, 64, 8), UltraKernelA64.ldAuto("ldr", 0, 8, pair.second, 4),
                UltraKernelA64.RET))
        }
        return image to symbols(image, entries)
    }

    @Test fun `actual saved-ID opcode families do not keep unrelated scratch histories`() {
        for (word in listOf(0xda9f31ce.toInt(), 0xfa0a01df.toInt(), 0x9a9f87ee.toInt(),
            0x1219018f, 0x521b098f, 0x9240bdce.toInt())) {
            val (kernel, symbols) = savedIdImage(tailWord = word)
            assertEquals("word=" + word.toUInt().toString(16), 12,
                UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "cred.suid").offsetBytes)
        }
    }

    private fun live(words: List<Int>): Long {
        val image = ByteArray(words.size * 4)
        words.forEachIndexed { index, value -> word(image, index * 4, value) }
        val method = UltraKernelStructOffsets::class.java.getDeclaredMethod("accessorLiveness",
            ByteArray::class.java, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType, Map::class.java)
        method.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val result = method.invoke(UltraKernelStructOffsets, image, 0, image.size, emptyMap<Any, Any>()) as Map<Int, Long>
        return result.getValue(0)
    }

    @Test fun `precise opcode masks retain operands carry and conditional flags`() {
        val nzcv = 1L shl 32
        fun reg(index: Int) = if (index == 31) 0L else 1L shl index
        for ((word, expected) in listOf(
            0xda9f31ce.toInt() to (reg(0) or reg(14) or nzcv),
            0xfa0a01df.toInt() to (reg(0) or reg(14) or reg(10) or nzcv),
            0x9a9f87ee.toInt() to (reg(0) or nzcv),
            0x1219018f to (reg(0) or reg(12)),
            0x521b098f to (reg(0) or reg(12)),
            0x9240bdce.toInt() to (reg(0) or reg(14))))
            assertEquals("word=" + word.toUInt().toString(16), expected, live(listOf(word, UltraKernelA64.RET)))
        // ANDS defines the flags consumed by CSET; plain AND preserves the incoming flags.
        assertEquals(reg(0) or reg(12), live(listOf(0x7219018f, 0x9a9f87ee.toInt(), UltraKernelA64.RET)))
        assertEquals(reg(0) or reg(12) or nzcv, live(listOf(0x1219018f, 0x9a9f87ee.toInt(), UltraKernelA64.RET)))
        // Unknown opcodes still retain every register and NZCV.
        assertEquals((1L shl 33) - 1, live(listOf(0xffffffff.toInt(), UltraKernelA64.RET)))
    }

    @Test fun `live saved-ID branch alternatives retain conflicting evidence`() {
        val (kernel, symbols) = savedIdImage(ambiguous = true)
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "cred.suid")
        }
        assertTrue(error.message.orEmpty().contains("STRUCT_OFFSET_AMBIGUOUS"))
    }

    @Test fun `dead-state merging does not accept a narrowed saved-ID output`() {
        val (kernel, symbols) = savedIdImage(wrongWidth = true)
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "cred.suid")
        }
        assertTrue(error.message.orEmpty().contains("STRUCT_OUTPUT_UNRESOLVED"))
    }
}
