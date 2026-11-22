package dev.maplesu.manager.ultrakernel

import java.io.ByteArrayOutputStream
import org.junit.Assert.*
import org.junit.Test

class UltraKernelBtfGraphTest {
    private class Symbols(override val imageSize: Int) : UltraKernelSymbols {
        override val summary = "btf-type-graph-fixture"
        override fun offsetOf(name: String) = if (name == "__start_BTF") 0 else null
        override fun isSymbolStart(value: Int) = false
        override fun nextOffset(offset: Int): Int? = null
    }
    private fun layout(raw: ByteArray) = UltraKernelBtf.layout(raw, Symbols(raw.size))
    private fun invalid(raw: ByteArray, detail: String) {
        val error = assertThrows(UltraKernelGenerateException::class.java) { layout(raw) }
        assertEquals(UltraKernelGenerateCodes.STRUCT_OFFSET, error.code)
        assertTrue(error.detail, error.detail.contains(detail))
    }

    @Test fun `equivalent task and cred compilation unit copies agree`() {
        assertEquals(mapOf("task_struct.cred" to 1944, "task_struct.comm" to 1960,
            "task_struct.seccomp.mode" to 2144, "cred.suid" to 12, "cred.sgid" to 16, "cred.euid" to 20),
            layout(fixture())!!.fields.mapValues { it.value.offsetBytes })
    }
    @Test fun `different valid task copies expose a layout conflict`() {
        invalid(fixture(secondComm = 2040), "STRUCT_AMBIGUOUS:task_struct")
    }
    @Test fun `credential interpretation follows each tasks actual pointer graph`() {
        // The first unrelated cred tag has different member locations. Both tasks point to ID 9.
        assertEquals(layout(fixture()), layout(fixture(firstCredSuid = 24, firstPointerTarget = 9)))
    }
    @Test fun `different reachable credential copies expose a layout conflict`() {
        invalid(fixture(secondCredSuid = 16), "STRUCT_AMBIGUOUS:task_struct")
    }
    @Test fun `unrelated anonymous zero length trailing arrays do not obscure members`() {
        assertEquals(1960, layout(fixture(anonymousTail = true))!!.offset("task_struct.comm"))
    }
    @Test fun `declared BTF requires a complete task owner for its consumers`() {
        val raw = fixture(completeTasks = false)
        invalid(raw, "STRUCT_MISSING:task_struct")
        assertEquals(UltraKernelLayout(emptyMap()), UltraKernelBtf.layout(raw, Symbols(raw.size), emptySet()))
    }
    @Test fun `a same width nonpointer cred member is rejected`() {
        invalid(fixture(taskCredType = 14), "CRED_POINTER")
    }
    @Test fun `comm requires sixteen one byte integers rather than four words`() {
        invalid(fixture(commElement = 2, commCount = 4), "COMM_TYPE")
    }
    @Test fun `optional seccomp mode follows its actual nested member offset`() {
        assertNull(layout(fixture(withSeccomp = false))!!.offset("task_struct.seccomp.mode"))
        assertEquals(UltraKernelLayoutField(2148, 4, 4608, "btf"),
            layout(fixture(modeOffset = 4))!!.fields["task_struct.seccomp.mode"])
        invalid(fixture(modeOffset = 14), "MEMBER_BOUNDS")
    }
    @Test fun `saved credential reply never overlaps euid`() {
        invalid(fixture(euidOffset = 12), "CRED_LAYOUT")
        invalid(fixture(euidOffset = 16), "CRED_LAYOUT")
    }

    private fun fixture(secondComm: Int = 1960, firstCredSuid: Int = 12,
        secondCredSuid: Int = 12, firstPointerTarget: Int = 5, anonymousTail: Boolean = false,
        completeTasks: Boolean = true, taskCredType: Int = 6, commElement: Int = 1,
        commCount: Int = 16, withSeccomp: Boolean = true, modeOffset: Int = 0,
        euidOffset: Int? = null): ByteArray {
        val strings = ByteArrayOutputStream().also { it.write(0) }
        val names = HashMap<String, Int>()
        fun name(value: String): Int = if (value.isEmpty()) 0 else names.getOrPut(value) {
            val at = strings.size(); strings.write(value.toByteArray(Charsets.US_ASCII)); strings.write(0); at
        }
        val types = ByteArrayOutputStream()
        fun word(value: Int) { repeat(4) { types.write(value ushr (it * 8) and 255) } }
        fun type(value: String, kind: Int, size: Int, count: Int = 0) {
            word(name(value)); word((kind shl 24) or count); word(size)
        }
        fun member(value: String, id: Int, bytes: Int) { word(name(value)); word(id); word(bytes * 8) }
        fun cred(suid: Int) {
            type("cred", 4, 64, 3)
            member("suid", 4, suid); member("sgid", 4, suid + 4); member("euid", 4, euidOffset ?: (suid + 8))
        }
        fun task(pointer: Int, comm: Int) {
            if (!completeTasks) { type("task_struct", 4, 0); return }
            type("task_struct", 4, 4608, 2 + (if (withSeccomp) 1 else 0) + (if (anonymousTail) 1 else 0))
            member("cred", pointer, 1944); member("comm", 3, comm)
            if (withSeccomp) member("seccomp", 7, 2144)
            if (anonymousTail) member("", 12, 4608)
        }
        type("char", 1, 1); word(8) // 1
        type("unsigned int", 1, 4); word(32) // 2
        type("", 3, 0); word(commElement); word(2); word(commCount) // 3
        type("kuid_t", 4, 4, 1); member("val", 2, 0) // 4
        cred(firstCredSuid) // 5
        type("", 2, firstPointerTarget) // 6
        type("seccomp", 4, 16, 1); member("mode", 2, modeOffset) // 7
        task(taskCredType, 1960) // 8
        cred(secondCredSuid) // 9
        type("", 2, 9) // 10
        task(if (taskCredType == 6) 10 else taskCredType, secondComm) // 11
        type("", 4, 0, 1); member("tail", 13, 0) // 12 zero-length anonymous tail
        type("", 3, 0); word(1); word(2); word(0) // 13 char[0]
        type("pointer_sized_value", 4, 8) // 14 nonpointer, exactly pointer width
        type("task_struct", 7, 0) // 15 FWD
        val body = types.toByteArray(); val text = strings.toByteArray()
        return ByteArray(24 + body.size + text.size).also { raw ->
            listOf(0x0001EB9F, 24, 0, body.size, body.size, text.size).forEachIndexed { index, value ->
                UltraKernelA64.writeLe32(raw, index * 4, value.toLong())
            }
            body.copyInto(raw, 24); text.copyInto(raw, 24 + body.size)
        }
    }
}
