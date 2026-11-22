package dev.maplesu.manager.ultrakernel

import java.io.ByteArrayOutputStream
import org.junit.Assert.*
import org.junit.Test

class UltraKernelBtfRequestedFieldsTest {
    private class Symbols(override val imageSize: Int, val names: Map<String, Int> = emptyMap()) : UltraKernelSymbols {
        override val summary = "requested-btf-fields"
        override fun offsetOf(name: String) = if (name == "__start_BTF") 0 else names[name]
        override fun isSymbolStart(value: Int) = false
        override fun nextOffset(offset: Int): Int? = null
    }

    private fun describe(raw: ByteArray, needed: Set<String>, members: Set<String> = emptySet()) =
        UltraKernelStructOffsets.describe(Symbols(raw.size), raw, needed, emptyMap(), members)

    @Test fun `cred pointer alone does not require comm or credential words`() {
        val layout = describe(fixture(omit = setOf("comm", "suid", "sgid", "euid")), setOf("task_struct.cred"))
        assertEquals(mapOf("task_struct.cred" to UltraKernelLayoutField(64, 8, 256, "btf")), layout.fields)
    }

    @Test fun `seccomp alone follows its actual nested mode without a cred pointer`() {
        val layout = describe(fixture(omit = setOf("cred", "comm", "suid", "sgid", "euid")),
            setOf(UltraKernelStructOffsets.SECCOMP))
        assertEquals(mapOf("task_struct.seccomp.mode" to UltraKernelLayoutField(132, 4, 256, "btf")), layout.fields)
    }

    @Test fun `comm alone does not require any credential graph`() {
        val layout = describe(fixture(omit = setOf("cred", "suid", "sgid", "euid", "seccomp")),
            setOf("task_struct.comm"))
        assertEquals(setOf("task_struct.comm"), layout.fields.keys)
        assertEquals(96, layout.offset("task_struct.comm"))
    }

    @Test fun `euid consumer does not require a saved id reply slot`() {
        val layout = describe(fixture(omit = setOf("comm", "suid", "sgid")),
            setOf("task_struct.cred"), setOf("cred.euid"))
        assertEquals(setOf("task_struct.cred", "cred.euid"), layout.fields.keys)
        assertEquals(20, layout.offset("cred.euid"))
    }

    @Test fun `unrequested malformed mode does not block cred recognition`() {
        val layout = describe(fixture(modeBits = 16), setOf("task_struct.cred"))
        assertEquals(setOf("task_struct.cred"), layout.fields.keys)
    }

    @Test fun `nonadjacent saved ids only constrain their actual legacy consumer`() {
        assertEquals(64, describe(fixture(sgid = 28), setOf("task_struct.cred")).offset("task_struct.cred"))
        val raw = fixture(sgid = 28)
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            describe(raw, setOf("task_struct.cred"), setOf("cred.suid", "cred.sgid"))
        }
        assertTrue(error.detail, error.detail.contains("CRED_LAYOUT"))
    }

    @Test fun `missing requested fields and incomplete mode words remain errors`() {
        for ((raw, name) in listOf(fixture(omit = setOf("comm")) to "task_struct.comm",
            fixture(modeBits = 16) to UltraKernelStructOffsets.SECCOMP)) {
            assertThrows(UltraKernelGenerateException::class.java) { describe(raw, setOf(name)) }
        }
    }

    @Test fun `records with no field consumers do not force a full layout`() {
        val raw = fixture(omit = setOf("comm", "suid", "sgid", "euid"))
        val recipe = UltraKernelRecipe("no-field-consumer", "diagnostic-only", 48,
            "/data/{key16}/init", emptyList())
        val result = recipe.renderDetailed(Symbols(raw.size), raw, UltraKernelCredential.of("Aa1".repeat(16)))
        assertTrue(result.layout.fields.isEmpty())
        assertTrue(result.records.isEmpty())
    }

    @Test fun `declared BTF missing a requested mode does not fall back to an accessor`() {
        val btf = fixture(omit = setOf("seccomp"))
        val entry = (btf.size + 3) and -4
        val raw = btf.copyOf(entry + 12)
        val code = listOf(UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0),
            UltraKernelA64.ldImm("ldr", 0, 8, 168, 4), UltraKernelA64.RET)
        code.forEachIndexed { index, word -> UltraKernelA64.writeLe32(raw, entry + index * 4, word.toLong()) }
        val symbols = Symbols(raw.size, mapOf("prctl_get_seccomp" to entry))
        assertEquals(168, UltraKernelStructOffsets.resolve(symbols, raw,
            setOf(UltraKernelStructOffsets.SECCOMP), emptyMap(), null)[UltraKernelStructOffsets.SECCOMP])
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelStructOffsets.resolve(symbols, raw, setOf(UltraKernelStructOffsets.SECCOMP), emptyMap())
        }
        assertTrue(error.detail, error.detail.contains("BTF_MEMBER_MISSING:seccomp"))
    }

    @Test fun `declared BTF without a complete task owner does not use an accessor`() {
        for (btf in listOf(fixture(taskName = "unrelated_task"), fixture(taskSize = 0),
            fixture(omit = setOf("cred", "comm", "seccomp")))) {
            val entry = (btf.size + 3) and -4
            val raw = btf.copyOf(entry + 12)
            val code = listOf(UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0),
                UltraKernelA64.ldImm("ldr", 0, 8, 168, 4), UltraKernelA64.RET)
            code.forEachIndexed { index, word ->
                UltraKernelA64.writeLe32(raw, entry + index * 4, word.toLong())
            }
            val symbols = Symbols(raw.size, mapOf("prctl_get_seccomp" to entry))
            assertEquals(168, UltraKernelStructOffsets.resolve(symbols, raw,
                setOf(UltraKernelStructOffsets.SECCOMP), emptyMap(), null)[UltraKernelStructOffsets.SECCOMP])
            val error = assertThrows(UltraKernelGenerateException::class.java) {
                UltraKernelStructOffsets.resolve(symbols, raw, setOf(UltraKernelStructOffsets.SECCOMP), emptyMap())
            }
            assertTrue(error.detail, error.detail.contains("BTF_STRUCT_MISSING:task_struct"))
        }
    }

    private fun fixture(omit: Set<String> = emptySet(), sgid: Int = 16, modeBits: Int = 32,
        taskName: String = "task_struct", taskSize: Int = 256): ByteArray {
        val strings = ByteArrayOutputStream().also { it.write(0) }
        val names = HashMap<String, Int>()
        fun name(value: String): Int = names.getOrPut(value) {
            if (value.isEmpty()) 0 else strings.size().also {
                strings.write(value.toByteArray(Charsets.US_ASCII)); strings.write(0)
            }
        }
        val types = ByteArrayOutputStream()
        fun word(value: Int) { repeat(4) { types.write(value ushr (it * 8) and 255) } }
        fun type(value: String, kind: Int, size: Int, count: Int = 0) {
            word(name(value)); word(kind shl 24 or count); word(size)
        }
        fun member(value: String, id: Int, bytes: Int) {
            if (value !in omit) { word(name(value)); word(id); word(bytes * 8) }
        }
        fun count(vararg values: String) = values.count { it !in omit }
        type("char", 1, 1); word(8) // 1
        type("unsigned int", 1, 4); word(32) // 2
        type("", 3, 0); word(1); word(2); word(16) // 3
        type("kuid_t", 4, 4, 1); member("val", 2, 0) // 4
        type("cred", 4, 64, count("suid", "sgid", "euid")) // 5
        member("suid", 4, 12); member("sgid", 4, sgid); member("euid", 4, 20)
        type("", 2, 5) // 6
        type("mode_word", 1, 4); word(modeBits) // 7
        type("seccomp", 4, 16, 1); member("mode", 7, 4) // 8
        type(taskName, 4, taskSize, count("cred", "comm", "seccomp")) // 9
        member("cred", 6, 64); member("comm", 3, 96); member("seccomp", 8, 128)
        val body = types.toByteArray()
        val text = strings.toByteArray()
        return ByteArray(24 + body.size + text.size).also { raw ->
            listOf(0x0001EB9F, 24, 0, body.size, body.size, text.size).forEachIndexed { index, value ->
                UltraKernelA64.writeLe32(raw, index * 4, value.toLong())
            }
            body.copyInto(raw, 24); text.copyInto(raw, 24 + body.size)
        }
    }
}
