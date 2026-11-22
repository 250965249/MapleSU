package dev.maplesu.manager.ultrakernel

import java.io.ByteArrayOutputStream
import org.junit.Assert.*
import org.junit.Test

class UltraKernelSubjectBtfTest {
    private class Symbols(override val imageSize: Int) : UltraKernelSymbols {
        override val summary = "subject-btf-graph"
        override fun offsetOf(name: String) = if (name == "__start_BTF") 0 else null
        override fun isSymbolStart(value: Int) = false
        override fun nextOffset(offset: Int): Int? = null
    }
    private class Btf {
        private val strings = ByteArrayOutputStream().also { it.write(0) }
        private val names = hashMapOf<String, Int>()
        private val types = ByteArrayOutputStream()
        private var count = 0
        private fun word(value: Int) { repeat(4) { types.write(value ushr (it * 8) and 255) } }
        private fun name(value: String) = names.getOrPut(value) {
            if (value.isEmpty()) 0 else strings.size().also { strings.write(value.toByteArray()); strings.write(0) }
        }
        fun integer(bytes: Int, encoding: Int = bytes * 8): Int {
            word(name("u${bytes * 8}")); word(1 shl 24); word(bytes); word(encoding)
            return ++count
        }
        fun leaf(kind: Int, value: Int): Int { word(0); word(kind shl 24); word(value); return ++count }
        fun array(type: Int): Int { word(0); word(3 shl 24); word(0); word(type); word(type); word(1); return ++count }
        fun union(type: Int): Int {
            word(0); word((5 shl 24) or 1); word(4); word(name("val")); word(type); word(0); return ++count
        }
        fun record(name: String, bytes: Int, vararg members: Triple<String, Int, Int>): Int {
            word(name(name)); word((4 shl 24) or members.size); word(bytes)
            for ((member, type, offset) in members) { word(name(member)); word(type); word(offset * 8) }
            return ++count
        }
        fun pointer(type: Int): Int { word(0); word(2 shl 24); word(type); return ++count }
        fun raw(): ByteArray {
            val body = types.toByteArray(); val text = strings.toByteArray()
            return ByteArray(24 + body.size + text.size).also { raw ->
                listOf(0x0001eb9f, 24, 0, body.size, body.size, text.size).forEachIndexed { at, value ->
                    UltraKernelA64.writeLe32(raw, at * 4, value.toLong()) }
                body.copyInto(raw, 24); text.copyInto(raw, 24 + body.size)
            }
        }
    }
    private fun fixture(credWidth: Int = 8, groupWidth: Int = 4, counterOffset: Int = 0,
        omit: Set<String> = emptySet(), badGroupPointer: Boolean = false,
        conflictingTask: Boolean = false, securebitsWidth: Int = 4, securebitsOffset: Int = 44,
        securebitsType: String = "integer"): ByteArray {
        val b = Btf()
        val word = b.integer(4); val wide = b.integer(8)
        val uid = b.record("kuid_t", 4, Triple("val", word, 0))
        val securebits = when (securebitsType) {
            "record" -> uid
            "union" -> b.union(word)
            "array" -> b.array(word)
            "float" -> b.leaf(16, 4)
            "signed" -> b.integer(4, (1 shl 24) or 32)
            "bool" -> b.integer(4, (4 shl 24) or 32)
            "partial" -> b.integer(4, 24)
            "shifted" -> b.integer(8, (8 shl 16) or 32)
            "qualified" -> b.leaf(10, b.leaf(8, word))
            else -> if (securebitsWidth == 4) word else wide
        }
        val atomic = b.record("atomic_t", groupWidth, Triple("counter", if (groupWidth == 4) word else wide, 0))
        val refs = b.record("refcount_struct", groupWidth, Triple("refs", atomic, 0))
        val credCounter = b.record("atomic_long_t", credWidth + counterOffset,
            Triple("counter", if (credWidth == 4) word else wide, counterOffset))
        val group = b.record("group_info", 32, *listOf(Triple("usage", refs, 8)).filter { it.first !in omit }.toTypedArray())
        val groupPointer = if (badGroupPointer) wide else b.pointer(group)
        // Deliberately incompatible same-name globals must never replace pointer targets.
        b.record("group_info", 256, Triple("usage", wide, 96))
        b.record("cred", 512, Triple("uid", uid, 128), Triple("usage", word, 64))
        val cred = b.record("cred", 128, *listOf(Triple("uid", uid, 24), Triple("euid", uid, 36),
            Triple("securebits", securebits, securebitsOffset),
            Triple("usage", credCounter, 0), Triple("group_info", groupPointer, 80))
            .filter { it.first !in omit }.toTypedArray())
        val pointer = b.pointer(cred)
        b.record("task_struct", 512, Triple("cred", pointer, 160))
        if (conflictingTask) b.record("task_struct", 512, Triple("cred", pointer, 168))
        return b.raw()
    }
    private val members = setOf("cred.uid", "cred.euid", "cred.group_info", "group_info.usage", "cred.usage")
    private fun describe(raw: ByteArray, requested: Set<String> = members) = UltraKernelStructOffsets.describe(
        Symbols(raw.size), raw, setOf("task_struct.cred"), emptyMap(), requested)
    private fun rejected(raw: ByteArray, detail: String) {
        val error = assertThrows(UltraKernelGenerateException::class.java) { describe(raw) }
        assertTrue(error.detail, error.detail.contains(detail))
    }
    @Test fun `subject follows actual pointer graph and scalar counter wrappers`() {
        val layout = describe(fixture())
        assertEquals(members + "task_struct.cred", layout.fields.keys)
        assertEquals(UltraKernelLayoutField(24, 4, 128, "btf"), layout.fields["cred.uid"])
        assertEquals(UltraKernelLayoutField(80, 8, 128, "btf"), layout.fields["cred.group_info"])
        assertEquals(UltraKernelLayoutField(8, 4, 32, "btf"), layout.fields["group_info.usage"])
        assertEquals(UltraKernelLayoutField(0, 8, 128, "btf"), layout.fields["cred.usage"])
    }
    @Test fun `counter storage follows target type widths and nested offsets`() {
        assertEquals(UltraKernelLayoutField(8, 8, 128, "btf"), describe(fixture(counterOffset = 8)).fields["cred.usage"])
        assertEquals(4, describe(fixture(credWidth = 4)).fields.getValue("cred.usage").widthBytes)
        assertEquals(8, describe(fixture(groupWidth = 8)).fields.getValue("group_info.usage").widthBytes)
    }
    @Test fun `unrequested broken group graph does not constrain UID consumers`() {
        val layout = describe(fixture(omit = setOf("usage", "group_info")), setOf("cred.uid"))
        assertEquals(setOf("task_struct.cred", "cred.uid"), layout.fields.keys)
    }
    @Test fun `group usage request resolves its actual pointer dependencies`() {
        val layout = describe(fixture(), setOf("group_info.usage"))
        assertEquals(setOf("task_struct.cred", "cred.group_info", "group_info.usage"), layout.fields.keys)
        assertEquals(8, layout.offset("group_info.usage"))
    }
    @Test fun `requested missing fields do not borrow same name decoys`() {
        for (name in listOf("uid", "usage", "group_info")) rejected(fixture(omit = setOf(name)), "MEMBER_MISSING")
    }
    @Test fun `group pointer and complete task graph conflicts are explicit`() {
        rejected(fixture(badGroupPointer = true), "GROUP_POINTER")
        rejected(fixture(conflictingTask = true), "STRUCT_AMBIGUOUS")
    }
    @Test fun `requested securebits follows the actual credential owner without saved IDs`() {
        val layout = describe(fixture(), setOf("cred.securebits"))
        assertEquals(setOf("task_struct.cred", "cred.securebits"), layout.fields.keys)
        assertEquals(UltraKernelLayoutField(44, 4, 128, "btf"), layout.fields["cred.securebits"])
    }
    @Test fun `securebits width and owner boundaries are enforced`() {
        for (raw in listOf(fixture(securebitsWidth = 8), fixture(securebitsOffset = 126), fixture(securebitsOffset = 45))) {
            val error = assertThrows(UltraKernelGenerateException::class.java) { describe(raw, setOf("cred.securebits")) }
            assertTrue(error.detail, error.detail.startsWith("BTF_"))
        }
        assertEquals(124, describe(fixture(securebitsOffset = 124), setOf("cred.securebits")).offset("cred.securebits"))
    }
    @Test fun `securebits requires a complete unsigned integer scalar`() {
        for (kind in listOf("record", "union", "array", "float", "signed", "bool", "partial", "shifted")) {
            val error = assertThrows(kind, UltraKernelGenerateException::class.java) {
                describe(fixture(securebitsType = kind), setOf("cred.securebits"))
            }
            assertTrue(error.detail, error.detail.startsWith("BTF_"))
        }
        assertEquals(44, describe(fixture(securebitsType = "qualified"), setOf("cred.securebits")).offset("cred.securebits"))
    }
    @Test fun `missing securebits in existing BTF never falls through to code`() {
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            describe(fixture(omit = setOf("securebits")), setOf("cred.securebits"))
        }
        assertTrue(error.detail, error.detail.contains("BTF_MEMBER_MISSING:securebits"))
    }
}
