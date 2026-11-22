package dev.maplesu.manager.ultrakernel

import java.io.File
import org.junit.Assert.*
import org.junit.Test

class UltraKernelSavedIdDataflowTest {
    private class Symbols(private val names: Map<String, Int>, override val imageSize: Int) : UltraKernelSymbols {
        override val summary = "saved-id-dataflow-fixture"
        override fun offsetOf(name: String) = names[name]
        override fun isSymbolStart(value: Int) = value in names.values
        override fun nextOffset(offset: Int) = names.values.filter { it > offset }.minOrNull()
    }
    private val names = mapOf("__arm64_sys_getuid" to 0x100, "__arm64_sys_geteuid" to 0x200,
        "__do_sys_getresuid" to 0x400, "__do_sys_getresgid" to 0x600)
    private fun emit(raw: ByteArray, at: Int, vararg words: Int) {
        words.forEachIndexed { index, word -> UltraKernelA64.writeLe32(raw, at + index * 4, word.toLong()) }
    }
    private fun getter(raw: ByteArray, at: Int, member: Int) = emit(raw, at,
        UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0), UltraKernelA64.ldImm("ldr", 8, 8, 0x780, 8),
        UltraKernelA64.ldImm("ldr", 0, 8, member, 4), UltraKernelA64.RET)
    private fun saved(raw: ByteArray, at: Int, member: Int, output: Int = 2, width: Int = 4,
        taskCred: Int = 0x780) = emit(raw, at,
        UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0), UltraKernelA64.ldImm("ldr", 8, 8, taskCred, 8),
        UltraKernelA64.ldImm("ldr", 8, 8, member, width),
        UltraKernelA64.ldImm("str", 8, output, 0, width), UltraKernelA64.RET)
    private fun image(suid: Int = 40, sgid: Int = 44, euid: Int = 24) = ByteArray(2048).also {
        getter(it, 0x100, 8); getter(it, 0x200, euid)
        saved(it, 0x400, suid); saved(it, 0x600, sgid)
    }
    private fun layout(raw: ByteArray, symbols: Map<String, Int> = names) =
        UltraKernelStructOffsets.describe(Symbols(symbols, raw.size), raw,
            setOf(UltraKernelStructOffsets.CRED), emptyMap(),
            setOf(UltraKernelStructOffsets.SUID, UltraKernelStructOffsets.SGID, UltraKernelStructOffsets.CRED_EUID), null)
    private fun rejected(raw: ByteArray, symbols: Map<String, Int> = names): UltraKernelGenerateException =
        assertThrows(UltraKernelGenerateException::class.java) { layout(raw, symbols) }

    @Test fun `saved IDs come from separate third output stores rather than UID arithmetic`() {
        val result = layout(image(euid = 120))
        assertEquals(UltraKernelLayoutField(40, 4, null, "accessor"), result.fields["cred.suid"])
        assertEquals(UltraKernelLayoutField(44, 4, null, "accessor"), result.fields["cred.sgid"])
        assertEquals(UltraKernelLayoutField(120, 4, null, "accessor"), result.fields["cred.euid"])
    }

    @Test fun `a non adjacent saved GID is observed and rejected by the old reply contract`() {
        val raw = image(sgid = 48)
        val identified = UltraKernelStructOffsets.credentialLayout(Symbols(names, raw.size), raw, 0x780, null)
        assertEquals(40, identified.suid)
        assertEquals(48, identified.sgid)
        assertTrue(rejected(raw).detail.contains("CRED_LAYOUT"))
    }

    @Test fun `the real UID output is not a saved UID output`() {
        val raw = image()
        saved(raw, 0x400, 40, output = 0)
        rejected(raw)
    }

    @Test fun `a wide credential load and store is not a 32 bit saved ID`() {
        val raw = image()
        saved(raw, 0x400, 40, width = 8)
        rejected(raw)
    }

    @Test fun `a saved GID from a different task credential is rejected`() {
        val raw = image()
        saved(raw, 0x600, 44, taskCred = 0x788)
        rejected(raw)
    }

    @Test fun `a missing saved store is not replaced by a nearby credential load`() {
        val raw = image()
        emit(raw, 0x40c, UltraKernelA64.RET)
        rejected(raw)
    }

    @Test fun `an unknown CSEL alternative is not assumed to be an ID conversion`() {
        val raw = image()
        emit(raw, 0x40c, UltraKernelA64.movz(9, 7), UltraKernelA64.csel(8, 8, 9, 0, sf = 0),
            UltraKernelA64.ldImm("str", 8, 2, 0, 4), UltraKernelA64.RET)
        rejected(raw)
    }

    @Test fun `a proved overflow conversion retains the saved ID source`() {
        val raw = image()
        overflowConversion(raw)
        assertEquals(40, layout(raw, names + ("overflowuid" to 0x700)).offset("cred.suid"))
    }

    @Test fun `an overflow CSEL requires the matching invalid ID comparison and condition`() {
        for ((at, replacement) in listOf(0x414 to UltraKernelA64.NOP,
            0x418 to UltraKernelA64.csel(8, 9, 8, 1, sf = 0))) {
            val raw = image()
            overflowConversion(raw)
            emit(raw, at, replacement)
            rejected(raw, names + ("overflowuid" to 0x700))
        }
    }

    @Test fun `the other ID domain overflow value does not prove a saved UID conversion`() {
        val raw = image()
        overflowConversion(raw)
        rejected(raw, names + ("overflowgid" to 0x700))
    }

    private fun overflowConversion(raw: ByteArray) = emit(raw, 0x400,
        UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0), UltraKernelA64.ldImm("ldr", 8, 8, 0x780, 8),
        UltraKernelA64.ldImm("ldr", 8, 8, 40, 4), UltraKernelA64.encodeAdrp(0x40c, 0x700, 9),
        UltraKernelA64.ldImm("ldr", 9, 9, 0x700, 4), 0x3100051f,
        UltraKernelA64.csel(8, 9, 8, 0, sf = 0), UltraKernelA64.ldImm("str", 8, 2, 0, 4), UltraKernelA64.RET)

    @Test fun `two different credential fields in CSEL are not one saved ID`() {
        val raw = image()
        emit(raw, 0x408, UltraKernelA64.ldImm("ldr", 9, 8, 32, 4),
            UltraKernelA64.ldImm("ldr", 8, 8, 40, 4), UltraKernelA64.csel(8, 8, 9, 0, sf = 0),
            UltraKernelA64.ldImm("str", 8, 2, 0, 4), UltraKernelA64.RET)
        rejected(raw)
    }

    @Test fun `two branches writing different saved fields report ambiguity`() {
        val raw = image()
        emit(raw, 0x400, UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0),
            UltraKernelA64.ldImm("ldr", 8, 8, 0x780, 8), UltraKernelA64.encodeBCond(0, 0x408, 0x418),
            UltraKernelA64.ldImm("ldr", 9, 8, 40, 4), UltraKernelA64.ldImm("str", 9, 2, 0, 4),
            UltraKernelA64.RET, UltraKernelA64.ldImm("ldr", 9, 8, 48, 4),
            UltraKernelA64.ldImm("str", 9, 2, 0, 4), UltraKernelA64.RET)
        assertTrue(rejected(raw).detail.contains("STRUCT_OFFSET_AMBIGUOUS"))
    }

    @Test fun `a next symbol boundary before the saved store prevents borrowing another function`() {
        rejected(image(), names + ("another_function" to 0x40c))
    }

    @Test fun `truncated saved accessor bytes are rejected`() {
        rejected(image().copyOf(0x40e))
    }

    @Test fun `one valid saved store does not hide an escaped reachable branch`() {
        for (target in listOf(0x610, 0x900)) {
            val raw = image()
            emit(raw, 0x40c, UltraKernelA64.encodeBCond(0, 0x40c, target.toLong()),
                UltraKernelA64.ldImm("str", 8, 2, 0, 4), UltraKernelA64.RET)
            rejected(raw)
        }
    }

    @Test fun `the EUID getter also rejects an unknown CSEL alternative`() {
        val raw = image()
        emit(raw, 0x208, UltraKernelA64.ldImm("ldr", 8, 8, 24, 4), UltraKernelA64.movz(9, 7),
            UltraKernelA64.csel(0, 8, 9, 0, sf = 0), UltraKernelA64.RET)
        rejected(raw)
    }

    @Test fun `one known EUID return does not hide another unresolved return`() {
        val raw = image()
        emit(raw, 0x208, UltraKernelA64.encodeBCond(0, 0x208, 0x214),
            UltraKernelA64.ldImm("ldr", 0, 8, 24, 4), UltraKernelA64.RET,
            UltraKernelA64.movz(0, 7), UltraKernelA64.RET)
        rejected(raw)
    }

    @Test fun `real Android 12 five ten bytes identify both saved outputs`() {
        val fixture = File("src/test/resources/ultrakernel/android12-5.10-saved-id")
        val raw = ByteArray(48045172)
        val anchors = mapOf("__do_sys_getresuid" to 0x164008, "uid_end" to 0x164480,
            "__do_sys_getresgid" to 0x1644b0, "gid_end" to 0x164914,
            "__arm64_sys_geteuid" to 0x16540c, "euid_end" to 0x165434,
            "overflowuid" to 0x27cfee0, "overflowgid" to 0x27cfee4)
        for (name in listOf("__do_sys_getresuid", "__do_sys_getresgid", "__arm64_sys_geteuid")) {
            val bytes = File(fixture, "$name.hex").readText().filterNot(Char::isWhitespace)
                .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            bytes.copyInto(raw, anchors.getValue(name))
        }
        val result = layout(raw, anchors)
        assertEquals(UltraKernelLayoutField(0x780, 8, null, "accessor"), result.fields["task_struct.cred"])
        assertEquals(UltraKernelLayoutField(12, 4, null, "accessor"), result.fields["cred.suid"])
        assertEquals(UltraKernelLayoutField(16, 4, null, "accessor"), result.fields["cred.sgid"])
        assertEquals(UltraKernelLayoutField(20, 4, null, "accessor"), result.fields["cred.euid"])
    }
}
