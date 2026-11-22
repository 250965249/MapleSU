package dev.maplesu.manager.ultrakernel

import java.io.File
import org.junit.Assert.*
import org.junit.Test

class UltraKernelSecurebitsTest {
    private class Symbols(val names: Map<String, List<Int>>, override val imageSize: Int,
        private val withoutBtf: Boolean = true) : UltraKernelSymbols {
        override val summary = "securebits-target"
        override fun offsetOf(name: String) = offsetsOf(name).minOrNull()
        override fun offsetsOf(name: String) = if (withoutBtf && name in setOf("__start_BTF", "__stop_BTF"))
            emptyList() else names[name].orEmpty()
        override fun isSymbolStart(value: Int) = names.values.any { value in it }
        override fun nextOffset(offset: Int) = names.values.flatten().filter { it > offset }.minOrNull()
    }
    private fun emit(raw: ByteArray, at: Int, vararg words: Int) = words.forEachIndexed { index, word ->
        UltraKernelA64.writeLe32(raw, at + index * 4, word.toLong() and 0xffffffffL) }
    private fun describe(raw: ByteArray, symbols: UltraKernelSymbols) = UltraKernelStructOffsets.describe(
        symbols, raw, setOf("task_struct.cred"), emptyMap(), setOf("cred.securebits"))
    private fun fixture(switch: Boolean = false): Pair<ByteArray, Symbols> {
        val raw = ByteArray(0x1000)
        for (at in raw.indices step 4) emit(raw, at, UltraKernelA64.NOP)
        emit(raw, 0x100, UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0),
            UltraKernelA64.ldImm("ldr", 8, 8, 0x780, 8), UltraKernelA64.ldImm("ldr", 0, 8, 4, 4), UltraKernelA64.RET)
        if (switch) {
            emit(raw, 0x200, 0x51001c09, 0x7100a13f, UltraKernelA64.encodeBCond(8, 0x208, 0x240),
                UltraKernelA64.encodeAdr(0x20c, 0x800, 10), UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0),
                UltraKernelA64.ldImm("ldr", 8, 8, 0x780, 8), UltraKernelA64.encodeAdr(0x218, 0x218, 11),
                0xb8a9794c.toInt(), 0x8b0c016b.toInt(), 0xd61f0160.toInt())
            emit(raw, 0x230, UltraKernelA64.ldImm("ldr", 0, 8, 100, 4), UltraKernelA64.RET)
            emit(raw, 0x850, 0x230 - 0x218)
        } else {
            emit(raw, 0x200, 0x71006c1f, UltraKernelA64.encodeBCond(1, 0x204, 0x240),
                UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0), UltraKernelA64.ldImm("ldr", 8, 8, 0x780, 8),
                UltraKernelA64.ldImm("ldr", 0, 8, 100, 4), UltraKernelA64.RET)
        }
        emit(raw, 0x240, UltraKernelA64.movz(0, 0), UltraKernelA64.RET)
        return raw to Symbols(mapOf("__arm64_sys_getuid" to listOf(0x100), "uid_end" to listOf(0x180),
            "cap_task_prctl" to listOf(0x200), "cap_end" to listOf(0x300),
            "__start_rodata" to listOf(0x800), "__end_rodata" to listOf(0xa00)), raw.size)
    }
    private fun rejected(switch: Boolean = false, mutate: (ByteArray, Symbols) -> Symbols) {
        val (raw, symbols) = fixture(switch)
        val changed = mutate(raw, symbols)
        val error = assertThrows(UltraKernelGenerateException::class.java) { describe(raw, changed) }
        assertTrue(error.detail, error.detail.startsWith("STRUCT_"))
    }
    @Test fun `comparison tree selects option 27 without neighbouring credential fields`() {
        val (raw, symbols) = fixture()
        assertEquals(UltraKernelLayoutField(100, 4, null, "accessor:cap_task_prctl(27)"),
            describe(raw, symbols).fields["cred.securebits"])
    }
    @Test fun `switch follows only the selected signed table entry`() {
        val (raw, symbols) = fixture(true)
        assertEquals(100, describe(raw, symbols).offset("cred.securebits"))
    }
    private fun byteSwitch(): Pair<ByteArray, Symbols> {
        val (raw, symbols) = fixture(true)
        emit(raw, 0x21c, 0x3869694c, 0x8b0c096b.toInt()) // LDRB W12,[X10,X9]; ADD X11,X11,X12,LSL #2.
        raw[0x814] = 6 // (0x230 - 0x218) / 4; option 27 selected index 20.
        return raw to symbols
    }
    private fun byteRejected(reason: String, mutate: (ByteArray, Symbols) -> Symbols) {
        val (raw, symbols) = byteSwitch()
        val changed = mutate(raw, symbols)
        val error = assertThrows(UltraKernelGenerateException::class.java) { describe(raw, changed) }
        assertTrue(error.detail, error.detail.contains(reason))
    }
    @Test fun `byte switch selects the proven option and branch`() {
        val (raw, symbols) = byteSwitch()
        assertEquals(100, describe(raw, symbols).offset("cred.securebits"))
    }
    @Test fun `byte switch entry remains unsigned`() {
        val (raw, symbols) = byteSwitch()
        raw[0x814] = 0xf9.toByte()
        emit(raw, 0x5fc, UltraKernelA64.ldImm("ldr", 0, 8, 100, 4), UltraKernelA64.RET)
        val wider = Symbols(symbols.names + ("cap_end" to listOf(0x700)), raw.size)
        assertEquals(100, describe(raw, wider).offset("cred.securebits"))
    }
    @Test fun `byte switch unknown index stays unknown`() = byteRejected("STRUCT_SWITCH_INDEX") { raw, s ->
        emit(raw, 0x200, 0x51001c29); s
    }
    @Test fun `byte switch does not cross its component`() = byteRejected("STRUCT_SWITCH_BOUNDS") { _, s ->
        Symbols(s.names + ("switch_table_end" to listOf(0x814)), s.imageSize)
    }
    @Test fun `byte switch does not cross rodata`() = byteRejected("STRUCT_SWITCH_BOUNDS") { _, s ->
        Symbols(s.names + ("__end_rodata" to listOf(0x814)), s.imageSize)
    }
    @Test fun `byte switch requires immutable section evidence`() = byteRejected("STRUCT_READONLY_RODATA") { _, s ->
        Symbols(s.names - "__start_rodata", s.imageSize)
    }
    @Test fun `byte switch branch stays inside the current function`() = byteRejected("STRUCT_SWITCH_TARGET") { raw, s ->
        raw[0x814] = 0xf9.toByte(); s
    }
    @Test fun `byte switch branch cannot truncate its address`() = byteRejected("STRUCT_SWITCH_TARGET") { raw, s ->
        emit(raw, 0x220, 0x0b0c096b); s
    }
    @Test fun `byte switch does not ignore the selected unknown call`() = byteRejected("STRUCT_SUBJECT_CALL") { raw, s ->
        emit(raw, 0x230, UltraKernelA64.encodeBl(0x230, 0x500)); s
    }
    @Test fun `byte switch rejects writes before consuming the table`() = byteRejected("STRUCT_READONLY_WRITE") { raw, s ->
        emit(raw, 0x214, UltraKernelA64.ldImm("str", 31, 10, 20, 1)); s
    }
    @Test fun `negative table displacement remains signed`() {
        val (raw, symbols) = fixture(true)
        emit(raw, 0x230, UltraKernelA64.encodeB(0x230, 0x210))
        // Place the return before the dispatch ADR without executing it on entry.
        emit(raw, 0x200, UltraKernelA64.encodeB(0x200, 0x220))
        emit(raw, 0x204, UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0),
            UltraKernelA64.ldImm("ldr", 8, 8, 0x780, 8), UltraKernelA64.ldImm("ldr", 0, 8, 100, 4), UltraKernelA64.RET)
        emit(raw, 0x220, 0x51001c09, UltraKernelA64.encodeAdr(0x224, 0x800, 10),
            UltraKernelA64.encodeAdr(0x228, 0x228, 11), 0xb8a9794c.toInt(), 0x8b0c016b.toInt(), 0xd61f0160.toInt())
        emit(raw, 0x850, 0x204 - 0x228)
        assertEquals(100, describe(raw, symbols).offset("cred.securebits"))
    }
    @Test fun `wrong option does not become a direct securebits return`() = rejected { raw, s ->
        emit(raw, 0x200, 0x71001c1f); s }
    @Test fun `CMN does not acquire subtraction equality flags`() = rejected { raw, s ->
        emit(raw, 0x200, 0x31006c1f); s }
    @Test fun `CMN overflow idiom replaces preceding comparison flags`() = rejected { raw, s ->
        emit(raw, 0x204, 0x3100041f, UltraKernelA64.encodeBCond(1, 0x208, 0x240),
            UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0), UltraKernelA64.ldImm("ldr", 8, 8, 0x780, 8),
            UltraKernelA64.ldImm("ldr", 0, 8, 100, 4), UltraKernelA64.RET); s }
    @Test fun `CMN register does not acquire subtraction equality flags`() = rejected { raw, s ->
        emit(raw, 0x200, UltraKernelA64.movz(9, 27), 0x2b09001f,
            UltraKernelA64.encodeBCond(1, 0x208, 0x240),
            UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0), UltraKernelA64.ldImm("ldr", 8, 8, 0x780, 8),
            UltraKernelA64.ldImm("ldr", 0, 8, 100, 4), UltraKernelA64.RET); s }
    @Test fun `CBZ W observes only the low word of a known X value`() = rejected { raw, s ->
        emit(raw, 0x200, 0xd2c00029.toInt(), 0x340001e9); s }
    @Test fun `CBNZ W observes only the low word of a known X value`() {
        val (raw, symbols) = fixture()
        emit(raw, 0x200, 0xd2c00029.toInt(), 0x350001e9)
        assertEquals(100, describe(raw, symbols).offset("cred.securebits"))
    }
    @Test fun `CBZ X retains the complete known value`() {
        val (raw, symbols) = fixture()
        emit(raw, 0x200, 0xd2c00029.toInt(), 0xb40001e9.toInt())
        assertEquals(100, describe(raw, symbols).offset("cred.securebits"))
    }
    @Test fun `CBNZ X retains the complete known value`() = rejected { raw, s ->
        emit(raw, 0x200, 0xd2c00029.toInt(), 0xb50001e9.toInt()); s }
    @Test fun `constant NZCV follows add and subtract at both register widths`() {
        data class Case(val left: Long, val right: Long, val wide: Boolean, val subtract: Boolean, val taken: Set<Int>)
        val cases = listOf(
            Case(0x7fffffff, 1, false, false, setOf(1, 3, 4, 6, 9, 10, 12)),
            Case(0xffffffff, 1, false, false, setOf(0, 2, 5, 7, 9, 10, 13)),
            Case(0x80000000, 1, false, true, setOf(1, 2, 5, 6, 8, 11, 13)),
            Case(0, 1, false, true, setOf(1, 3, 4, 7, 9, 11, 13)),
            Case(Long.MAX_VALUE, 1, true, false, setOf(1, 3, 4, 6, 9, 10, 12)),
            Case(-1, 1, true, false, setOf(0, 2, 5, 7, 9, 10, 13)),
            Case(Long.MIN_VALUE, 1, true, true, setOf(1, 2, 5, 6, 8, 11, 13)),
            Case(0, 1, true, true, setOf(1, 3, 4, 7, 9, 11, 13)))
        for ((index, case) in cases.withIndex()) for (condition in 0..13) {
            val (raw, symbols) = fixture()
            for (at in 0x200 until 0x300 step 4) emit(raw, at, UltraKernelA64.NOP)
            var at = 0x200
            for ((register, value) in listOf(0 to case.left, 9 to case.right)) {
                repeat(if (case.wide) 4 else 2) { half ->
                    val opcode = if (half == 0) 0x52800000 else 0x72800000
                    emit(raw, at, opcode or (if (case.wide) Int.MIN_VALUE else 0) or (half shl 21) or
                        (((value ushr (half * 16)).toInt() and 0xffff) shl 5) or register)
                    at += 4
                }
            }
            emit(raw, at, 0x2b09001f or (if (case.wide) Int.MIN_VALUE else 0) or
                (if (case.subtract) 1 shl 30 else 0), UltraKernelA64.encodeBCond(condition, (at + 4).toLong(), 0x2c0),
                UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0), UltraKernelA64.ldImm("ldr", 8, 8, 0x780, 8),
                UltraKernelA64.ldImm("ldr", 0, 8, 100, 4), UltraKernelA64.RET)
            emit(raw, 0x2c0, UltraKernelA64.movz(0, 0), UltraKernelA64.RET)
            val label = "case=$index condition=$condition"
            if (condition in case.taken) assertThrows(label, UltraKernelGenerateException::class.java) { describe(raw, symbols) }
            else assertEquals(label, 100, describe(raw, symbols).offset("cred.securebits"))
        }
    }
    @Test fun `byte load is not a full securebits field`() = rejected { raw, s ->
        emit(raw, 0x210, UltraKernelA64.ldImm("ldr", 0, 8, 100, 1)); s }
    @Test fun `wide load is not a four byte field`() = rejected { raw, s ->
        emit(raw, 0x210, UltraKernelA64.ldImm("ldr", 0, 8, 104, 8)); s }
    @Test fun `different task pointer is not the proven cred`() = rejected { raw, s ->
        emit(raw, 0x20c, UltraKernelA64.ldImm("ldr", 8, 8, 0x788, 8)); s }
    @Test fun `word pointer truncation destroys credential provenance`() = rejected { raw, s ->
        emit(raw, 0x210, 0x2a0803e8, UltraKernelA64.ldImm("ldr", 0, 8, 100, 4), UltraKernelA64.RET); s }
    @Test fun `unknown register index is not an immediate field offset`() = rejected { raw, s ->
        emit(raw, 0x210, 0xb8696900.toInt()); s }
    @Test fun `negative unscaled credential field is not published`() = rejected { raw, s ->
        emit(raw, 0x210, 0xb85fc100.toInt()); s }
    @Test fun `unaligned unscaled credential field is not published`() = rejected { raw, s ->
        emit(raw, 0x210, 0xb8465100.toInt()); s }
    @Test fun `PRFUM preserves the task address instead of manufacturing a cred pointer`() = rejected { raw, s ->
        emit(raw, 0x208, UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0), 0x911e0108.toInt(),
            0xf8800108.toInt(), UltraKernelA64.ldImm("ldr", 0, 8, 100, 4), UltraKernelA64.RET); s }
    @Test fun `PRFUM leaves an already proven credential pointer intact`() {
        val (raw, symbols) = fixture()
        emit(raw, 0x210, 0xf8800108.toInt(), UltraKernelA64.ldImm("ldr", 0, 8, 100, 4), UltraKernelA64.RET)
        assertEquals(100, describe(raw, symbols).offset("cred.securebits"))
    }
    @Test fun `reserved unsigned load opcode never supplies a credential field`() = rejected { raw, s ->
        emit(raw, 0x210, 0xb9c06500.toInt()); s }
    @Test fun `reserved unscaled load opcode never supplies a credential field`() = rejected { raw, s ->
        emit(raw, 0x210, 0xb8c00100.toInt()); s }
    @Test fun `prefetch writeback and unprivileged encodings are reserved`() {
        for (mode in 1..3) rejected { raw, s ->
            emit(raw, 0x210, 0xf8800108.toInt() or (mode shl 10),
                UltraKernelA64.ldImm("ldr", 0, 8, 100, 4), UltraKernelA64.RET); s }
    }
    @Test fun `writeback cannot restore an overwritten credential pointer`() = rejected { raw, s ->
        emit(raw, 0x210, 0xb8404d08.toInt(), UltraKernelA64.ldImm("ldr", 0, 8, 96, 4), UltraKernelA64.RET); s }
    private fun signedComparison(wordCompare: Boolean): Pair<ByteArray, Symbols> {
        val (raw, symbols) = fixture()
        emit(raw, 0x210, 0xb9406509.toInt(), 0xb980650a.toInt(),
            if (wordCompare) 0x6b0a013f else 0xeb0a013f.toInt(), UltraKernelA64.encodeBCond(1, 0x21c, 0x240),
            UltraKernelA64.ldImm("ldr", 0, 8, 100, 4), UltraKernelA64.RET)
        emit(raw, 0x240, UltraKernelA64.ldImm("ldr", 0, 8, 104, 4), UltraKernelA64.RET)
        return raw to symbols
    }
    @Test fun `signed and unsigned X loads do not prove value equality`() {
        val (raw, symbols) = signedComparison(false)
        assertThrows(UltraKernelGenerateException::class.java) { describe(raw, symbols) }
    }
    @Test fun `W comparison discards only the high extension bits`() {
        val (raw, symbols) = signedComparison(true)
        assertEquals(100, describe(raw, symbols).offset("cred.securebits"))
    }
    @Test fun `direct LDRSW still proves the same four byte memory field`() {
        val (raw, symbols) = fixture()
        emit(raw, 0x210, 0xb9806500.toInt())
        assertEquals(100, describe(raw, symbols).offset("cred.securebits"))
    }
    @Test fun `return clobber is not a field`() = rejected { raw, s ->
        emit(raw, 0x214, UltraKernelA64.movz(0, 0), UltraKernelA64.RET); s }
    @Test fun `unknown call is not ignored`() = rejected { raw, s ->
        emit(raw, 0x210, UltraKernelA64.encodeBl(0x210, 0x500), UltraKernelA64.ldImm("ldr", 0, 8, 100, 4), UltraKernelA64.RET); s }
    @Test fun `all same name candidates must agree`() = rejected { raw, s ->
        raw.copyInto(raw, 0x400, 0x200, 0x218)
        emit(raw, 0x410, UltraKernelA64.ldImm("ldr", 0, 8, 104, 4))
        Symbols(s.names + ("cap_task_prctl" to listOf(0x200, 0x400)) + ("other_end" to listOf(0x500)), raw.size) }
    @Test fun `unknown option index does not read a guessed table entry`() = rejected(true) { raw, s ->
        emit(raw, 0x200, 0x51001c29); s }
    @Test fun `table entry outside rodata is not consumed`() = rejected(true) { _, s ->
        Symbols(s.names + ("__end_rodata" to listOf(0x850)), s.imageSize) }
    @Test fun `mutable table bytes are not treated as immutable facts`() = rejected(true) { _, s ->
        Symbols(s.names - "__start_rodata", s.imageSize) }
    @Test fun `unaligned branch target is not followed`() = rejected(true) { raw, s ->
        emit(raw, 0x850, 0x232 - 0x218); s }
    @Test fun `out of function branch target is not followed`() = rejected(true) { raw, s ->
        emit(raw, 0x850, 0x400 - 0x218); s }
    @Test fun `truncated table is not read`() = rejected(true) { raw, s ->
        emit(raw, 0x20c, UltraKernelA64.encodeAdr(0x20c, 0xffc, 10)); s }
    @Test fun `branch arithmetic cannot truncate a proven address`() = rejected(true) { raw, s ->
        emit(raw, 0x220, 0x0b0c016b); s }
    private fun actual(name: String, expected: Int, hasBtf: Boolean) {
        val directory = File("native-inputs/kernels/$name")
        val raw = File(directory, "Image").readBytes()
        val names = linkedMapOf<String, MutableList<Int>>()
        File(directory, "symbols.tsv").useLines { lines -> lines.forEach { line ->
            val parts = line.split('\t')
            if (parts.size == 3) parts[0].toIntOrNull()?.let { names.getOrPut(parts[2]) { arrayListOf() }.add(it) }
        } }
        val code = describe(raw, Symbols(names, raw.size))
        assertEquals(expected, code.offset("cred.securebits"))
        assertEquals(4, code.fields.getValue("cred.securebits").widthBytes)
        if (hasBtf) {
            val btf = describe(raw, Symbols(names, raw.size, false))
            assertEquals(expected, btf.offset("cred.securebits"))
            assertEquals("btf", btf.fields.getValue("cred.securebits").source)
            code.fields.getValue("cred.securebits").ownerSizeBytes?.let {
                assertEquals(btf.fields.getValue("cred.securebits").ownerSizeBytes, it)
            }
        }
    }
    @Test fun actual_510() = actual("android12-5.10-9465fbb7", 36, false)
    @Test fun actual_515() = actual("android13-5.15-2f109982", 36, true)
    @Test fun actual_61() = actual("android14-6.1-71c55acc", 36, true)
    @Test fun actual_66() = actual("android15-6.6-346d51ea", 40, true)
    @Test fun actual_66_other() = actual("android15-6.6-ddd760da", 40, true)
    @Test fun actual_612() = actual("android16-6.12-6679e3fb", 40, true)
    @Test fun actual_618() = actual("android17-6.18-4f47635b", 40, true)
}
