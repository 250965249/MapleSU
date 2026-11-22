package dev.maplesu.manager.ultrakernel

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream

class UltraKernelBtfTest {
    private class Symbols(override val imageSize: Int, val start: Int? = 0) : UltraKernelSymbols {
        override val summary = "btf-fixture"
        override fun offsetOf(name: String) = if (name == "__start_BTF") start else null
        override fun isSymbolStart(value: Int) = false
        override fun nextOffset(offset: Int): Int? = null
    }

    @Test fun `target type data locates nonadjacent comm and credential words`() {
        val raw = fixture(comm = 2040)
        val fields = UltraKernelBtf.layout(raw, Symbols(raw.size))!!.fields
        assertEquals(mapOf(
            "task_struct.cred" to UltraKernelLayoutField(1944, 8, 4608, "btf"),
            "task_struct.comm" to UltraKernelLayoutField(2040, 16, 4608, "btf"),
            "task_struct.seccomp.mode" to UltraKernelLayoutField(2144, 4, 4608, "btf"),
            "cred.suid" to UltraKernelLayoutField(12, 4, 64, "btf"),
            "cred.sgid" to UltraKernelLayoutField(16, 4, 64, "btf"),
            "cred.euid" to UltraKernelLayoutField(20, 4, 64, "btf"),
        ), fields)
    }

    @Test fun `absence leaves instruction based recognition available`() {
        assertNull(UltraKernelBtf.layout(ByteArray(32), Symbols(32, null)))
    }

    @Test fun `described overrides retain target widths and owner bounds`() {
        val raw = fixture()
        val symbols = Symbols(raw.size)
        val described = UltraKernelStructOffsets.describe(symbols, raw,
            setOf(UltraKernelStructOffsets.COMM, UltraKernelStructOffsets.SECCOMP),
            mapOf(UltraKernelStructOffsets.COMM to 2040), emptySet())
        assertEquals(UltraKernelLayoutField(2040, 16, 4608, "override"), described.fields["task_struct.comm"])
        assertEquals(UltraKernelLayoutField(2144, 4, 4608, "btf"), described.fields["task_struct.seccomp.mode"])
        assertFalse(described.fields.containsKey(UltraKernelStructOffsets.SECCOMP))
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelStructOffsets.describe(symbols, raw, setOf(UltraKernelStructOffsets.COMM),
                mapOf(UltraKernelStructOffsets.COMM to 4600), emptySet())
        }
        assertTrue(error.detail.contains("STRUCT_MEMBER_BOUNDS:task_struct.comm"))
    }

    @Test fun `malformed declared BTF is a layout error`() {
        val raw = fixture()
        raw[0] = 0
        invalid(raw, "HEADER")
    }

    @Test fun `unsigned section arithmetic stays inside the declared image`() {
        for (at in listOf(4, 8, 12, 16, 20)) {
            val raw = fixture()
            UltraKernelA64.writeLe32(raw, at, 0xFFFFFFF0L)
            invalid(raw)
        }
    }

    @Test fun `a truncated table never supplies a partial layout`() {
        val raw = fixture()
        for (cut in listOf(0, 4, 23, 24, 27, 39, raw.size - 1)) invalid(raw.copyOf(cut))
    }

    @Test fun `saved UID and GID must occupy the actual eight byte reply slot`() {
        invalid(fixture(sgid = 28), "CRED_LAYOUT")
    }

    @Test fun `comm must be a complete character array within task bounds`() {
        invalid(fixture(comm = 4600), "MEMBER_BOUNDS")
        invalid(fixture(commCount = 8), "MEMBER_SIZE:comm")
    }

    @Test fun `member offset is not confused with bitfield width`() {
        invalid(fixture(commBits = (1 shl 24) or (1960 * 8)), "MEMBER_BITS")
    }

    @Test fun `unrelated anonymous bitfields do not invalidate a normal field`() {
        val raw = fixture(anonymousBits = true)
        assertEquals(1960, UltraKernelBtf.layout(raw, Symbols(raw.size))!!.offset("task_struct.comm"))
    }

    @Test fun `credential pointer must reference the declared cred type`() {
        invalid(fixture(pointerTarget = 8), "CRED_POINTER")
    }

    @Test fun `modifier cycles are bounded`() {
        invalid(fixture(pointerTarget = 10, cycle = true), "TYPE_CYCLE")
    }

    @Test fun `legacy integer effective width cannot impersonate a full mode word`() {
        invalid(fixture(modeEncoding = 16), "MEMBER_SIZE:mode")
        invalid(fixture(modeEncoding = 16, anonymousMode = true), "MEMBER_SIZE:mode")
    }

    @Test fun `legacy integer internal offset contributes to its actual byte location`() {
        val raw = fixture(modeSize = 8, modeEncoding = (32 shl 16) or 32)
        assertEquals(2148, UltraKernelBtf.layout(raw, Symbols(raw.size))!!.offset("task_struct.seccomp.mode"))
        val nested = fixture(modeSize = 8, modeEncoding = (32 shl 16) or 32, anonymousMode = true)
        assertEquals(2152, UltraKernelBtf.layout(nested, Symbols(nested.size))!!.offset("task_struct.seccomp.mode"))
    }

    @Test fun `legacy integer effective bits must describe a byte addressable word`() {
        invalid(fixture(modeSize = 8, modeEncoding = (1 shl 16) or 32), "MEMBER_BITS")
        invalid(fixture(modeEncoding = 31), "MEMBER_BITS")
    }

    @Test fun `consumed integer encodings stay within their storage and BTF integer range`() {
        for (encoding in listOf(0, 40, (16 shl 16) or 32, (127 shl 16) or 2))
            invalid(fixture(modeEncoding = encoding), "MEMBER_INT")
    }

    @Test fun `modern plain integers retain complete word semantics through modifiers`() {
        val raw = fixture(modeModern = true, modeConst = true)
        assertEquals(2144, UltraKernelBtf.layout(raw, Symbols(raw.size))!!.offset("task_struct.seccomp.mode"))
        val legacy = fixture(modeSize = 8, modeEncoding = (32 shl 16) or 32, modeConst = true)
        assertEquals(2148, UltraKernelBtf.layout(legacy, Symbols(legacy.size))!!.offset("task_struct.seccomp.mode"))
    }

    @Test fun `modern integers reject legacy offsets and unsupported base widths`() {
        invalid(fixture(modeModern = true, modeSize = 8, modeEncoding = (8 shl 16) or 32), "MEMBER_INT")
        invalid(fixture(modeModern = true, modeEncoding = 24), "MEMBER_INT")
    }

    @Test fun `modern selected bitfield width cannot exceed its base or the mode contract`() {
        invalid(fixture(modeModern = true, modeOffsetBits = 64 shl 24), "MEMBER_BITS")
        invalid(fixture(modeModern = true, modeOffsetBits = 16 shl 24), "MEMBER_SIZE:mode")
    }

    @Test fun `modern full mode slice uses the member offset and effective width`() {
        val raw = fixture(modeModern = true, modeSize = 8, modeEncoding = 64,
            modeOffsetBits = (32 shl 24) or 32)
        assertEquals(UltraKernelLayoutField(2148, 4, 4608, "btf"),
            UltraKernelBtf.layout(raw, Symbols(raw.size))!!.fields["task_struct.seccomp.mode"])
    }

    @Test fun `integer owner bounds use the effective end without arithmetic wraparound`() {
        val raw = fixture(modeSize = 8, modeOffsetBits = 12 * 8)
        assertEquals(2156, UltraKernelBtf.layout(raw, Symbols(raw.size))!!.offset("task_struct.seccomp.mode"))
        invalid(fixture(modeSize = 8, modeEncoding = (32 shl 16) or 32,
            modeOffsetBits = 12 * 8), "MEMBER_BOUNDS")
        invalid(fixture(modeOffsetBits = -8), "MEMBER_BOUNDS")
    }

    private fun invalid(raw: ByteArray, detail: String? = null) {
        try {
            UltraKernelBtf.layout(raw, Symbols(raw.size))
            fail("invalid BTF was accepted")
        } catch (error: UltraKernelGenerateException) {
            assertEquals(UltraKernelGenerateCodes.STRUCT_OFFSET, error.code)
            if (detail != null) assertTrue(error.detail, error.detail.contains(detail))
        }
    }

    private fun fixture(comm: Int = 1960, sgid: Int = 16, commCount: Int = 16,
                        commBits: Int? = null, anonymousBits: Boolean = false,
                        pointerTarget: Int = 6, cycle: Boolean = false,
                        modeEncoding: Int = 32, modeSize: Int = 4, modeModern: Boolean = false,
                        modeOffsetBits: Int = 0, modeConst: Boolean = false,
                        anonymousMode: Boolean = false): ByteArray {
        val strings = ByteArrayOutputStream()
        strings.write(0)
        val names = HashMap<String, Int>()
        fun name(value: String): Int = if (value.isEmpty()) 0 else names.getOrPut(value) {
            val at = strings.size()
            strings.write(value.toByteArray(Charsets.US_ASCII)); strings.write(0)
            at
        }
        val types = ByteArrayOutputStream()
        fun word(value: Int) { repeat(4) { types.write(value ushr (it * 8) and 255) } }
        fun type(value: String, kind: Int, size: Int, count: Int = 0, bits: Boolean = false) {
            word(name(value)); word((kind shl 24) or count or if (bits) Int.MIN_VALUE else 0); word(size)
        }
        fun member(value: String, id: Int, offset: Int) { word(name(value)); word(id); word(offset) }
        type("char", 1, 1); word(8) // 1
        type("", 3, 0); word(1); word(3); word(commCount) // 2 char[]
        type("unsigned int", 1, 4); word(32) // 3
        type("kuid_t", 4, 4, 1); member("val", 3, 0) // 4
        type("kgid_t", 4, 4, 1); member("val", 3, 0) // 5
        type("cred", 4, 64, 3) // 6
        member("suid", 4, 12 * 8); member("sgid", 5, sgid * 8); member("euid", 4, 20 * 8)
        type("", 2, pointerTarget) // 7
        type("seccomp", 4, 16, 1, modeModern && !anonymousMode) // 8
        member(if (anonymousMode) "" else "mode", if (anonymousMode) 11 else 12,
            if (anonymousMode) 32 else modeOffsetBits)
        type("task_struct", 4, 4608, if (anonymousBits) 4 else 3, commBits != null || anonymousBits) // 9
        member("cred", 7, 1944 * 8); member("comm", 2, commBits ?: (comm * 8))
        member("seccomp", 8, 2144 * 8)
        if (anonymousBits) member("", 3, (1 shl 24) or 16)
        type("", 10, if (cycle) 10 else 13) // 10 const, optionally self-referencing
        type("", 4, 8, 1, modeModern); member("mode", 12, modeOffsetBits) // 11 anonymous owner
        type("", 10, if (modeConst) 10 else 13) // 12 mode, optionally with an extra modifier
        type("mode_integer", 1, modeSize); word(modeEncoding) // 13
        val body = types.toByteArray()
        val text = strings.toByteArray()
        val raw = ByteArray(24 + body.size + text.size)
        listOf(0x0001EB9F, 24, 0, body.size, body.size, text.size).forEachIndexed { index, value ->
            UltraKernelA64.writeLe32(raw, index * 4, value.toLong())
        }
        body.copyInto(raw, 24); text.copyInto(raw, 24 + body.size)
        return raw
    }
}
