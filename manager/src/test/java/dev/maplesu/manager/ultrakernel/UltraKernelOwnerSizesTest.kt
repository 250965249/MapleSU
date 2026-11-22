package dev.maplesu.manager.ultrakernel

import java.io.File
import org.junit.Assert.*
import org.junit.Test

class UltraKernelOwnerSizesTest {
    private class Symbols(private val names: Map<String, Int>, override val imageSize: Int) : UltraKernelSymbols {
        override val summary = "owner-size-fixture"
        override fun offsetOf(name: String) = names[name]
        override fun isSymbolStart(value: Int) = value in names.values
        override fun nextOffset(offset: Int) = names.values.filter { it > offset }.minOrNull()
    }

    private fun real(target: String): Pair<ByteArray, UltraKernelSymbols> {
        val directory = File("native-inputs/kernels/$target")
        val image = File(directory, "Image").readBytes()
        val names = linkedMapOf<String, Int>()
        File(directory, "symbols.tsv").useLines { lines -> lines.forEach { line ->
            val parts = line.split('\t')
            if (parts.size == 3) parts[0].toIntOrNull()?.let { value ->
                names[parts[2]] = minOf(names[parts[2]] ?: value, value)
            }
        } }
        return image to Symbols(names, image.size)
    }

    @Test fun `real no BTF 510 describe carries target task and cred owner sizes`() {
        val (image, symbols) = real("android12-5.10-9465fbb7")
        val layout = UltraKernelStructOffsets.describe(symbols, image,
            setOf(UltraKernelStructOffsets.CRED), emptyMap(), setOf(UltraKernelStructOffsets.CRED_EUID))
        assertEquals(4736, layout.fields.getValue(UltraKernelStructOffsets.CRED).ownerSizeBytes)
        assertEquals(168, layout.fields.getValue(UltraKernelStructOffsets.CRED_EUID).ownerSizeBytes)
    }

    private data class Fixture(val raw: ByteArray, val names: MutableMap<String, Int>) {
        fun symbols() = Symbols(names, raw.size)
    }
    private fun emit(raw: ByteArray, start: Int, vararg words: Int) = words.forEachIndexed { index, word ->
        UltraKernelA64.writeLe32(raw, start + index * 4, word.toLong())
    }
    private fun fixture(taskSize: Int = 256, credSize: Int = 128): Fixture {
        val raw = ByteArray(2048)
        for (at in raw.indices step 4) UltraKernelA64.writeLe32(raw, at, UltraKernelA64.NOP.toLong())
        val names = linkedMapOf("fork_init" to 0x100, "fork_end" to 0x180,
            "cred_init" to 0x200, "cred_end" to 0x280,
            "__arm64_sys_getuid" to 0x300, "uid_end" to 0x320,
            "__arm64_sys_geteuid" to 0x340, "euid_end" to 0x360,
            "__do_sys_getresuid" to 0x380, "resuid_end" to 0x3a0,
            "__do_sys_getresgid" to 0x3c0, "resgid_end" to 0x3e0,
            "unrelated" to 0x500, "task_struct_cachep" to 0x680, "cred_jar" to 0x688,
            "kmem_cache_create_usercopy" to 0x700, "kmem_cache_create" to 0x740)
        "task_struct\u0000".toByteArray().copyInto(raw, 0x600)
        "cred_jar\u0000".toByteArray().copyInto(raw, 0x620)
        for ((start, size, name, cache) in listOf(listOf(0x100, taskSize, 0x600, 0x680), listOf(0x200, credSize, 0x620, 0x688))) {
            emit(raw, start, UltraKernelA64.encodeAdrp(start.toLong(), name.toLong(), 0),
                UltraKernelA64.addImm(0, 0, name), UltraKernelA64.movz(1, size, sf = 0),
                UltraKernelA64.encodeBl(start.toLong() + 12, 0x700),
                UltraKernelA64.encodeAdrp(start.toLong() + 16, cache.toLong(), 8),
                UltraKernelA64.ldImm("str", 0, 8, cache, 8), UltraKernelA64.RET)
        }
        for ((start, member) in listOf(0x300 to 4, 0x340 to 20)) emit(raw, start,
            UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0), UltraKernelA64.ldImm("ldr", 8, 8, 64, 8),
            UltraKernelA64.ldImm("ldr", 0, 8, member, 4), UltraKernelA64.RET)
        for ((start, member) in listOf(0x380 to 12, 0x3c0 to 16)) emit(raw, start,
            UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0), UltraKernelA64.ldImm("ldr", 8, 8, 64, 8),
            UltraKernelA64.ldImm("ldr", 8, 8, member, 4), UltraKernelA64.ldImm("str", 8, 2, 0, 4), UltraKernelA64.RET)
        return Fixture(raw, names)
    }
    private fun size(f: Fixture, owner: String = "task_struct") = UltraKernelOwnerSizes.size(f.symbols(), f.raw, owner)
    private fun describe(f: Fixture, members: Set<String> = emptySet(), overrides: Map<String, Int> = emptyMap()) =
        UltraKernelStructOffsets.describe(f.symbols(), f.raw, setOf(UltraKernelStructOffsets.CRED), overrides, members, null)
    private fun taskArguments(vararg words: Int): Fixture = fixture().also { f ->
        val call = 0x100 + words.size * 4
        emit(f.raw, 0x100, *words, UltraKernelA64.encodeBl(call.toLong(), 0x700),
            UltraKernelA64.encodeAdrp(call.toLong() + 4, 0x680, 8),
            UltraKernelA64.ldImm("str", 0, 8, 0x680, 8), UltraKernelA64.RET)
    }

    @Test fun `address provenance never survives W writes or wide immediate replacement`() {
        val rewrites = listOf(UltraKernelA64.movReg(0, 0, sf = 0), UltraKernelA64.addImm(0, 0, 0, sf = 0),
            UltraKernelA64.movk(0, 0x600, sf = 0), UltraKernelA64.movk(0, 0x600))
        assertEquals(List<Int?>(rewrites.size) { null }, rewrites.map { rewrite -> size(taskArguments(
            UltraKernelA64.encodeAdr(0x100, 0x600, 0), rewrite, UltraKernelA64.movz(1, 256, sf = 0))) })
    }

    @Test fun `numeric arguments remain known across legal W and X moves`() {
        val formations = listOf(
            intArrayOf(UltraKernelA64.movz(2, 256, sf = 0), UltraKernelA64.movReg(1, 2, sf = 0)),
            intArrayOf(UltraKernelA64.movz(1, 240, sf = 0), UltraKernelA64.addImm(1, 1, 16, sf = 0)),
            intArrayOf(UltraKernelA64.movz(1, 0xffff, shift = 32), UltraKernelA64.movk(1, 256, sf = 0)),
            intArrayOf(UltraKernelA64.movz(1, 256), UltraKernelA64.movk(1, 0, shift = 32), UltraKernelA64.movk(1, 0, shift = 48)),
        )
        assertEquals(List(formations.size) { 256 }, formations.map { words ->
            size(taskArguments(UltraKernelA64.encodeAdr(0x100, 0x600, 0), *words)) })
    }

    @Test fun `truncated addresses do not become numeric size evidence`() {
        val rewrites = listOf(UltraKernelA64.movReg(1, 1, sf = 0), UltraKernelA64.addImm(1, 1, 0, sf = 0),
            UltraKernelA64.movk(1, 256, sf = 0), UltraKernelA64.movk(1, 256))
        assertEquals(List<Int?>(rewrites.size) { null }, rewrites.map { rewrite -> size(taskArguments(
            UltraKernelA64.encodeAdr(0x100, 256, 1), rewrite, UltraKernelA64.encodeAdr(0x108, 0x600, 0))) })
    }

    @Test fun `register 31 is never an address or stack constant source`() {
        val formations = listOf(
            intArrayOf(UltraKernelA64.encodeAdr(0x100, 0x600, 31), UltraKernelA64.movReg(0, 31), UltraKernelA64.movz(1, 256, sf = 0)),
            intArrayOf(UltraKernelA64.encodeAdr(0x100, 0x600, 31), UltraKernelA64.addImm(0, 31, 0), UltraKernelA64.movz(1, 256, sf = 0)),
            intArrayOf(UltraKernelA64.movz(31, 256, sf = 0), UltraKernelA64.movReg(1, 31, sf = 0), UltraKernelA64.encodeAdr(0x108, 0x600, 0)),
            intArrayOf(UltraKernelA64.movz(31, 256), UltraKernelA64.addImm(1, 31, 0), UltraKernelA64.encodeAdr(0x108, 0x600, 0)),
        )
        assertEquals(List<Int?>(formations.size) { null }, formations.map { size(taskArguments(*it)) })
        assertEquals(256, size(taskArguments(UltraKernelA64.encodeAdr(0x100, 0x600, 0),
            UltraKernelA64.movReg(1, 31, sf = 0), UltraKernelA64.addImm(1, 1, 256, sf = 0))))
    }

    @Test fun `ADD flags and reserved encodings cannot prove an initializer`() {
        val rewrites = listOf(UltraKernelA64.addImm(0, 0, 0, setFlags = true),
            UltraKernelA64.addImm(0, 0, 0, sub = true), UltraKernelA64.addImm(0, 0, 0) or (1 shl 23))
        assertEquals(List<Int?>(rewrites.size) { null }, rewrites.map { rewrite -> size(taskArguments(
            UltraKernelA64.encodeAdr(0x100, 0x600, 0), rewrite, UltraKernelA64.movz(1, 256, sf = 0))) })
    }

    @Test fun `wide immediate reserved W shifts are rejected`() {
        val formations = listOf(UltraKernelA64.movz(1, 256, shift = 32, sf = 0),
            UltraKernelA64.movz(1, 256, shift = 48, sf = 0), UltraKernelA64.movk(1, 256, shift = 32, sf = 0),
            UltraKernelA64.movk(1, 256, shift = 48, sf = 0))
        assertEquals(List<Int?>(formations.size) { null }, formations.map { word -> size(taskArguments(
            UltraKernelA64.encodeAdr(0x100, 0x600, 0), UltraKernelA64.movz(1, 256, sf = 0), word)) })
    }

    @Test fun `unshifted X move and add preserve PC address provenance`() {
        assertEquals(256, size(taskArguments(UltraKernelA64.encodeAdr(0x100, 0x5f0, 19),
            UltraKernelA64.movReg(0, 19), UltraKernelA64.addImm(0, 0, 16), UltraKernelA64.movz(1, 256, sf = 0))))
    }

    @Test fun `real 66 code sizes equal independent BTF and normal describe retains BTF`() {
        val (image, symbols) = real("android15-6.6-346d51ea")
        val needed = setOf(UltraKernelStructOffsets.CRED, UltraKernelStructOffsets.CRED_EUID)
        val oracle = requireNotNull(UltraKernelBtf.layout(image, symbols, needed))
        assertEquals(oracle.fields.getValue(UltraKernelStructOffsets.CRED).ownerSizeBytes,
            UltraKernelOwnerSizes.size(symbols, image, "task_struct"))
        assertEquals(oracle.fields.getValue(UltraKernelStructOffsets.CRED_EUID).ownerSizeBytes,
            UltraKernelOwnerSizes.size(symbols, image, "cred"))
        val layout = UltraKernelStructOffsets.describe(symbols, image, setOf(UltraKernelStructOffsets.CRED), emptyMap(),
            setOf(UltraKernelStructOffsets.CRED_EUID))
        assertTrue(layout.fields.values.all { it.source == "btf" })
        assertEquals(4800, layout.fields.getValue(UltraKernelStructOffsets.CRED).ownerSizeBytes)
        assertEquals(184, layout.fields.getValue(UltraKernelStructOffsets.CRED_EUID).ownerSizeBytes)
    }

    @Test fun `known initializer owners flow to all actual saved ID fields`() {
        val f = fixture()
        val layout = describe(f, setOf(UltraKernelStructOffsets.SUID, UltraKernelStructOffsets.SGID, UltraKernelStructOffsets.CRED_EUID))
        assertEquals(256, layout.fields.getValue(UltraKernelStructOffsets.CRED).ownerSizeBytes)
        for (name in listOf("cred.suid", "cred.sgid", "cred.euid"))
            assertEquals(128, layout.fields.getValue(name).ownerSizeBytes)
    }

    @Test fun `only requested owners are queried and BTF never enters owner parser`() {
        val f = fixture()
        val base = f.symbols()
        val guarded = object : UltraKernelSymbols by base {
            override fun offsetOf(name: String): Int? {
                if (name == "cred_init") fail("unrequested cred owner queried")
                return base.offsetOf(name)
            }
        }
        val taskOnly = UltraKernelStructOffsets.describe(guarded, f.raw, setOf(UltraKernelStructOffsets.CRED), emptyMap(), emptySet(), null)
        assertEquals(256, taskOnly.fields.getValue(UltraKernelStructOffsets.CRED).ownerSizeBytes)
        val noInitializer = object : UltraKernelSymbols by base {
            override fun offsetOf(name: String): Int? {
                if (name in listOf("fork_init", "cred_init")) fail("BTF entered owner parser")
                return base.offsetOf(name)
            }
        }
        val btf = UltraKernelLayout(mapOf("task_struct.cred" to UltraKernelLayoutField(64, 8, 300, "btf")))
        assertEquals(btf, UltraKernelStructOffsets.describe(noInitializer, f.raw, setOf(UltraKernelStructOffsets.CRED), emptyMap(), emptySet(), btf))
    }

    @Test fun `unknown owners stay nullable without adding field restrictions`() {
        val f = fixture()
        f.raw[0x600] = 'x'.code.toByte()
        assertNull(size(f))
        assertNull(describe(f, overrides = mapOf(UltraKernelStructOffsets.CRED to 4096))
            .fields.getValue(UltraKernelStructOffsets.CRED).ownerSizeBytes)
    }

    @Test fun `exact owner boundaries pass and every described field is range checked`() {
        assertEquals(72, describe(fixture(taskSize = 72)).fields.getValue(UltraKernelStructOffsets.CRED).ownerSizeBytes)
        for (f in listOf(fixture(taskSize = 71), fixture(credSize = 23))) {
            val error = assertThrows(UltraKernelGenerateException::class.java) {
                describe(f, setOf(UltraKernelStructOffsets.CRED_EUID))
            }
            assertTrue(error.detail, error.detail.contains("STRUCT_MEMBER_BOUNDS"))
        }
        assertEquals(24, describe(fixture(credSize = 24), setOf(UltraKernelStructOffsets.CRED_EUID))
            .fields.getValue(UltraKernelStructOffsets.CRED_EUID).ownerSizeBytes)
    }

    @Test fun `cache name provenance and complete allocator size are required`() {
        val mutations: List<(Fixture) -> Unit> = listOf(
            { it.raw[0x600] = 'x'.code.toByte() },
            { emit(it.raw, 0x100, UltraKernelA64.movz(0, 0x600)) },
            { emit(it.raw, 0x108, UltraKernelA64.encodeAdr(0x108, 256, 1)) },
            { emit(it.raw, 0x108, UltraKernelA64.movz(1, 0)) },
            { emit(it.raw, 0x108, UltraKernelA64.movz(1, 1, shift = 32)) },
            { emit(it.raw, 0x108, UltraKernelA64.ldImm("ldr", 1, 2, 0, 8)) },
            { emit(it.raw, 0x10c, UltraKernelA64.encodeBl(0x10c, 0x500)) },
            { it.names.remove("kmem_cache_create_usercopy") },
            { it.names["kmem_cache_create_usercopy_lookalike"] = it.names.remove("kmem_cache_create_usercopy")!! },
            { it.names["task_struct_cachep"] = 0x690 },
            { emit(it.raw, 0x114, UltraKernelA64.ldImm("str", 1, 8, 0x680, 8)) },
            { emit(it.raw, 0x114, UltraKernelA64.ldImm("str", 0, 9, 0x680, 8)) },
            { emit(it.raw, 0x108, UltraKernelA64.ldImm("str", 1, 0, 0, 8)) },
        )
        mutations.forEachIndexed { index, mutate -> val f = fixture(); mutate(f); assertNull("mutation $index", size(f)) }
    }

    @Test fun `calls clobber arguments but saved values can independently rebuild them`() {
        val f = fixture()
        emit(f.raw, 0x108, UltraKernelA64.encodeBl(0x108, 0x500), UltraKernelA64.movz(1, 256, sf = 0),
            UltraKernelA64.encodeBl(0x110, 0x700), UltraKernelA64.encodeAdrp(0x114, 0x680, 8),
            UltraKernelA64.ldImm("str", 0, 8, 0x680, 8), UltraKernelA64.RET)
        assertNull(size(f))
        val saved = fixture()
        emit(saved.raw, 0x108, UltraKernelA64.movReg(19, 0), UltraKernelA64.encodeBl(0x10c, 0x500),
            UltraKernelA64.movReg(0, 19), UltraKernelA64.movz(1, 256, sf = 0), UltraKernelA64.encodeBl(0x118, 0x700),
            UltraKernelA64.encodeAdrp(0x11c, 0x680, 8), UltraKernelA64.ldImm("str", 0, 8, 0x680, 8), UltraKernelA64.RET)
        assertEquals(256, size(saved))
    }

    @Test fun `branches duplicate allocators and truncation preserve unknown`() {
        val mutations: List<(Fixture) -> Unit> = listOf(
            { emit(it.raw, 0x100, UltraKernelA64.encodeB(0x100, 0x104)) },
            { emit(it.raw, 0x100, UltraKernelA64.encodeBCond(0, 0x100, 0x108)) },
            { emit(it.raw, 0x100, UltraKernelA64.encodeCbz(3, 0x100, 0x108, false, false)) },
            { emit(it.raw, 0x130, UltraKernelA64.encodeBl(0x130, 0x740)) },
            { emit(it.raw, 0x130, UltraKernelA64.encodeB(0x130, 0x108)) },
            { it.names["fork_end"] = 0x110 },
            { it.names["fork_end"] = 0x119 },
            { it.names["fork_init"] = 0x101 },
            { emit(it.raw, 0x100, UltraKernelA64.encodeAdr(0x100, 0x7fc, 0), UltraKernelA64.NOP) },
            { emit(it.raw, 0x100, 0xffffffff.toInt()) },
        )
        mutations.forEachIndexed { index, mutate -> val f = fixture(); mutate(f); assertNull("mutation $index", size(f)) }
    }

    @Test fun `independent known copy length conflict removes owner and unknown copy proves nothing`() {
        fun copied(length: Int?): Fixture = fixture().also { f ->
            f.names += mapOf("arch_dup_task_struct" to 0x400, "copy_end" to 0x440, "memcpy" to 0x760)
            emit(f.raw, 0x400, length?.let { UltraKernelA64.movz(2, it, sf = 0) } ?: UltraKernelA64.movReg(2, 3),
                UltraKernelA64.encodeBl(0x404, 0x760), UltraKernelA64.RET)
        }
        assertEquals(256, size(copied(256)))
        assertNull(size(copied(257)))
        // This is allocator-only evidence: an unknown memcpy argument contributes no value.
        assertEquals(256, size(copied(null)))
    }
}
