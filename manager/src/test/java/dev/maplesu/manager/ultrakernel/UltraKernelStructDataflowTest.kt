package dev.maplesu.manager.ultrakernel

import org.junit.Assert.*
import org.junit.Test

class UltraKernelStructDataflowTest {
    private class Symbols(private val names: Map<String, Int>, override val imageSize: Int) : UltraKernelSymbols {
        override val summary = "struct-dataflow-fixture"
        override fun offsetOf(name: String) = names[name]
        override fun isSymbolStart(value: Int) = value in names.values
        override fun nextOffset(offset: Int) = names.values.filter { it > offset }.minOrNull()
    }

    private val getterNames = mapOf("__arm64_sys_getuid" to 0x100, "__arm64_sys_geteuid" to 0x200,
        "__do_sys_getresuid" to 0x600, "__do_sys_getresgid" to 0x700)
    private fun image() = ByteArray(2048).also { raw ->
        for (at in raw.indices step 4) UltraKernelA64.writeLe32(raw, at, UltraKernelA64.NOP.toLong())
        saved(raw, 0x600, 16); saved(raw, 0x700, 20)
    }
    private fun emit(raw: ByteArray, at: Int, vararg words: Int) {
        words.forEachIndexed { index, word -> UltraKernelA64.writeLe32(raw, at + index * 4, word.toLong()) }
    }
    private fun getter(raw: ByteArray, at: Int, member: Int, taskCred: Int = 0x780, preceding: Int? = null) {
        val words = mutableListOf(UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0),
            UltraKernelA64.ldImm("ldr", 8, 8, taskCred, 8))
        preceding?.let { words += UltraKernelA64.ldImm("ldr", 9, 8, it, 4) }
        words += UltraKernelA64.ldImm("ldr", 0, 8, member, 4)
        words += UltraKernelA64.RET
        emit(raw, at, *words.toIntArray())
    }
    private fun saved(raw: ByteArray, at: Int, member: Int, taskCred: Int = 0x780) = emit(raw, at,
        UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0), UltraKernelA64.ldImm("ldr", 8, 8, taskCred, 8),
        UltraKernelA64.ldImm("ldr", 8, 8, member, 4), UltraKernelA64.ldImm("str", 8, 2, 0, 4), UltraKernelA64.RET)
    private fun resolve(raw: ByteArray, field: String, names: Map<String, Int> = getterNames): Int =
        UltraKernelStructOffsets.resolve(Symbols(names, raw.size), raw, setOf(field), emptyMap(), null).getValue(field)

    @Test fun `unrelated credential loads never become UID or EUID fields`() {
        val raw = image()
        getter(raw, 0x100, 8, preceding = 4)
        getter(raw, 0x200, 24, preceding = 20)
        val cred = resolve(raw, UltraKernelStructOffsets.CRED)
        val members = UltraKernelStructOffsets.credentialLayout(Symbols(getterNames, raw.size), raw, cred, null)
        assertEquals(0x780, cred)
        assertEquals(16, members.suid)
        assertEquals(24, members.euid)
    }

    @Test fun `layout describes independent saved ID accessor evidence`() {
        val raw = image()
        getter(raw, 0x100, 8)
        getter(raw, 0x200, 24)
        val layout = UltraKernelStructOffsets.describe(Symbols(getterNames, raw.size), raw,
            setOf(UltraKernelStructOffsets.CRED), emptyMap(),
            setOf(UltraKernelStructOffsets.SUID, UltraKernelStructOffsets.CRED_EUID), null)
        assertEquals(UltraKernelLayoutField(0x780, 8, null, "accessor"), layout.fields["task_struct.cred"])
        assertEquals(UltraKernelLayoutField(16, 4, null, "accessor"), layout.fields["cred.suid"])
        assertEquals(UltraKernelLayoutField(20, 4, null, "accessor"), layout.fields["cred.sgid"])
        assertEquals(UltraKernelLayoutField(24, 4, null, "accessor"), layout.fields["cred.euid"])
        assertFalse(layout.fields.containsKey("task_struct.comm"))
        assertTrue(layout.fields.values.all { it.parserVersion == 1 })
    }

    @Test fun `an euid only consumer does not require a saved UID reply layout`() {
        val raw = image()
        getter(raw, 0x200, 88)
        val names = mapOf("__arm64_sys_geteuid" to 0x200)
        val layout = UltraKernelStructOffsets.describe(Symbols(names, raw.size), raw,
            setOf(UltraKernelStructOffsets.CRED), emptyMap(), setOf(UltraKernelStructOffsets.CRED_EUID), null)
        assertEquals(UltraKernelLayoutField(88, 4, null, "accessor"), layout.fields["cred.euid"])
        assertFalse(layout.fields.containsKey("cred.suid"))
    }

    @Test fun `unrelated task pointer load never becomes cred`() {
        val raw = image()
        emit(raw, 0x100, UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0),
            UltraKernelA64.ldImm("ldr", 9, 8, 32, 8),
            UltraKernelA64.ldImm("ldr", 8, 8, 0x780, 8),
            UltraKernelA64.ldImm("ldr", 0, 8, 8, 4), UltraKernelA64.RET)
        getter(raw, 0x200, 24)
        assertEquals(0x780, resolve(raw, UltraKernelStructOffsets.CRED))
    }

    @Test fun `real getter CSEL keeps the converted credential value`() {
        val raw = image()
        saved(raw, 0x600, 12, 0x798); saved(raw, 0x700, 16, 0x798)
        val names = getterNames + ("overflowuid" to 0x500)
        for ((at, member) in listOf(0x100 to 4, 0x200 to 20)) {
            emit(raw, at, UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0),
                UltraKernelA64.ldImm("ldr", 8, 8, 0x798, 8),
                UltraKernelA64.encodeAdrp(at.toLong() + 8, 0x500, 9),
                UltraKernelA64.ldImm("ldr", 9, 9, 0x500, 4),
                UltraKernelA64.ldImm("ldr", 8, 8, member, 4),
                0x3100051f, // CMN W8, #1
                UltraKernelA64.csel(0, 9, 8, 0, sf = 0), UltraKernelA64.RET)
        }
        val cred = resolve(raw, UltraKernelStructOffsets.CRED, names)
        val members = UltraKernelStructOffsets.credentialLayout(Symbols(names, raw.size), raw, cred, null)
        assertEquals(0x798, cred)
        assertEquals(12, members.suid)
        assertEquals(20, members.euid)
    }

    @Test fun `both CFG branches preserve evidence through unrelated loads`() {
        val raw = image()
        emit(raw, 0x100, UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0),
            UltraKernelA64.ldImm("ldr", 8, 8, 0x780, 8),
            UltraKernelA64.encodeBCond(0, 0x108, 0x114),
            UltraKernelA64.ldImm("ldr", 9, 8, 4, 4), UltraKernelA64.encodeB(0x110, 0x118),
            UltraKernelA64.movz(9, 7), UltraKernelA64.ldImm("ldr", 0, 8, 8, 4), UltraKernelA64.RET)
        getter(raw, 0x200, 24)
        val members = UltraKernelStructOffsets.credentialLayout(Symbols(getterNames, raw.size), raw, 0x780, null)
        assertEquals(16, members.suid)
        assertEquals(24, members.euid)
    }

    @Test fun `different fields reaching two return paths report a conflict`() {
        val raw = image()
        getter(raw, 0x100, 8)
        emit(raw, 0x200, UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0),
            UltraKernelA64.ldImm("ldr", 8, 8, 0x780, 8),
            UltraKernelA64.encodeBCond(0, 0x208, 0x214),
            UltraKernelA64.ldImm("ldr", 0, 8, 20, 4), UltraKernelA64.RET,
            UltraKernelA64.ldImm("ldr", 0, 8, 24, 4), UltraKernelA64.RET)
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelStructOffsets.credentialLayout(Symbols(getterNames, raw.size), raw, 0x780, null)
        }
        assertTrue(error.detail.contains("STRUCT_OFFSET_AMBIGUOUS"))
    }

    @Test fun `comm follows the task parameter rather than current`() {
        val raw = image()
        val names = mapOf("__get_task_comm" to 0x300, "memcpy" to 0x500)
        emit(raw, 0x300, UltraKernelA64.movReg(19, 2),
            UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0), UltraKernelA64.addImm(1, 8, 0x100),
            UltraKernelA64.encodeBl(0x30c, 0x500),
            UltraKernelA64.addImm(1, 19, 0x7a8), UltraKernelA64.encodeBl(0x314, 0x500), UltraKernelA64.RET)
        assertEquals(0x7a8, resolve(raw, UltraKernelStructOffsets.COMM, names))
    }

    @Test fun `current alone is not evidence for a task argument copier`() {
        val raw = image()
        val names = mapOf("__get_task_comm" to 0x300, "memcpy" to 0x500)
        emit(raw, 0x300, UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0),
            UltraKernelA64.addImm(1, 8, 0x100), UltraKernelA64.encodeBl(0x308, 0x500), UltraKernelA64.RET)
        assertThrows(UltraKernelGenerateException::class.java) { resolve(raw, UltraKernelStructOffsets.COMM, names) }
    }

    @Test fun `sized strscpy variants use the same observed task copy arguments`() {
        val raw = image()
        val names = mapOf("__get_task_comm" to 0x300, "sized_strscpy" to 0x500)
        emit(raw, 0x300, UltraKernelA64.movReg(20, 2), UltraKernelA64.addImm(1, 20, 0x910),
            UltraKernelA64.movz(2, 16), UltraKernelA64.encodeBl(0x30c, 0x500), UltraKernelA64.RET)
        assertEquals(0x910, resolve(raw, UltraKernelStructOffsets.COMM, names))
    }

    @Test fun `calls invalidate caller registers but retain saved task registers`() {
        for (register in listOf(8, 19)) {
            val raw = image()
            getter(raw, 0x200, 24)
            val names = getterNames + ("unrelated_call" to 0x500)
            emit(raw, 0x100, UltraKernelA64.mrs(register, UltraKernelA64.MRS_SP_EL0),
                UltraKernelA64.encodeBl(0x104, 0x500), UltraKernelA64.ldImm("ldr", 8, register, 0x780, 8),
                UltraKernelA64.ldImm("ldr", 0, 8, 8, 4), UltraKernelA64.RET)
            if (register == 19) assertEquals(0x780, resolve(raw, UltraKernelStructOffsets.CRED, names))
            else assertThrows(UltraKernelGenerateException::class.java) { resolve(raw, UltraKernelStructOffsets.CRED, names) }
        }
    }

    @Test fun `writeback memory operations invalidate the changed task address`() {
        val raw = image()
        emit(raw, 0x100, UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0),
            UltraKernelA64.ldImm9("str", 9, 8, 8, 8, 1),
            UltraKernelA64.ldImm("ldr", 8, 8, 0x780, 8),
            UltraKernelA64.ldImm("ldr", 0, 8, 8, 4), UltraKernelA64.RET)
        assertThrows(UltraKernelGenerateException::class.java) { resolve(raw, UltraKernelStructOffsets.CRED) }
    }
}
