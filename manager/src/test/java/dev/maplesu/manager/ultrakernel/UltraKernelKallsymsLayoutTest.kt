package dev.maplesu.manager.ultrakernel

import java.io.ByteArrayOutputStream
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class UltraKernelKallsymsLayoutTest {
    @Test
    fun `a unique LTO hash resolves the body while retaining its raw name and CFI jump table`() {
        val body = "filldir64\$" + "a".repeat(32)
        for (legacy in listOf(false, true)) {
            val table = UltraKernelKallsymsTable.decode(fixture(legacy, 1025, 0xf000, symbols = mapOf(
                1000 to (body to 0xe000), 1001 to ("$body.cfi_jt" to 0xe100))))
            assertEquals(0xe000, table.offsetOf("filldir64"))
            assertEquals(listOf(0xe000), table.offsetsOf("filldir64"))
            assertEquals(0xe000, table.offsetOf(body))
            assertEquals(0xe100, table.offsetOf("$body.cfi_jt"))
            assertEquals(body, table.nameAt(0xe000))
        }
    }

    @Test
    fun `different LTO bodies stay ambiguous and an exact name takes priority`() {
        val first = "filldir64\$" + "a".repeat(32)
        val second = "filldir64\$" + "b".repeat(32)
        for (legacy in listOf(false, true)) {
            val names = mapOf(1000 to (first to 0xe000), 1001 to (second to 0xe100))
            val ambiguous = UltraKernelKallsymsTable.decode(fixture(legacy, 1025, 0xf000, symbols = names))
            assertEquals(null, ambiguous.offsetOf("filldir64"))
            assertEquals(emptyList<Int>(), ambiguous.offsetsOf("filldir64"))
            val exact = UltraKernelKallsymsTable.decode(fixture(legacy, 1025, 0xf000,
                symbols = names + (1002 to ("filldir64" to 0xe200))))
            assertEquals(0xe200, exact.offsetOf("filldir64"))
        }
    }

    @Test
    fun `duplicate addresses behind a single LTO name stay ambiguous`() {
        val body = "filldir64\$" + "a".repeat(32)
        val table = UltraKernelKallsymsTable.decode(fixture(true, 1025, 0xf000, symbols = mapOf(
            1000 to (body to 0xe000), 1001 to (body to 0xe100))))
        assertEquals(null, table.offsetOf("filldir64"))
        assertEquals(listOf(0xe000, 0xe100), table.offsetsOf(body))
    }

    @Test
    fun `CFI jump tables and arbitrary suffixes never substitute for a missing body`() {
        val names = mapOf(1000 to (("filldir64\$" + "a".repeat(32) + ".cfi_jt") to 0xe000),
            1001 to ("other\$short" to 0xe100))
        val table = UltraKernelKallsymsTable.decode(fixture(true, 1025, 0xf000, symbols = names))
        assertEquals(null, table.offsetOf("filldir64"))
        assertEquals(null, table.offsetOf("other"))
    }

    @Test
    fun `shifted text symbol is rejected before a table can produce patch sites`() {
        for (legacy in listOf(false, true)) {
            val error = assertThrows(UltraKernelGenerateException::class.java) {
                UltraKernelKallsymsTable.decode(fixture(legacy, 1025, 0x5000, first = 0x10000))
            }
            assertEquals("ULTRA_KERNEL_GENERATE_KALLSYMS", error.code)
            assertEquals("KALLSYMS_TEXT_BASE_MISMATCH", error.detail)
        }
    }

    @Test
    fun `public decoder preserves zero offsets for both layouts and symbol count parities`() {
        for (legacy in listOf(false, true)) {
            for (count in listOf(1024, 1025)) {
                for (last in listOf(0, 0x5000)) {
                    val table = UltraKernelKallsymsTable.decode(fixture(legacy, count, last))
                    val label = "legacy=$legacy count=$count last=$last"
                    assertEquals(label, count, table.symbolCount)
                    assertEquals(label, 0, table.offsetOf("_text"))
                    assertEquals(label, 16, table.offsetOf("_s0001"))
                    assertEquals(label, (count - 2) * 16,
                        table.offsetOf("_s${(count - 2).toString().padStart(4, '0')}"))
                    assertEquals(label, last,
                        table.offsetOf("_s${(count - 1).toString().padStart(4, '0')}"))
                }
            }
        }
    }

    @Test
    fun `different layouts of the same getter are all checked`() {
        for (legacy in listOf(false, true)) {
            val raw = duplicateGetters(legacy, secondCred = 0x880)
            val error = assertThrows(UltraKernelGenerateException::class.java) { resolveCred(raw) }
            assertEquals("STRUCT_OFFSET_AMBIGUOUS:task_struct.cred", error.detail)
        }
    }

    @Test
    fun `same address aliases and same layout duplicate getters remain usable`() {
        for (legacy in listOf(false, true)) {
            assertEquals(0x780, resolveCred(duplicateGetters(legacy, secondAt = 0xe000)))
            assertEquals(0x780, resolveCred(duplicateGetters(legacy)))
        }
    }

    @Test
    fun `each duplicate getter is bounded by its own next symbol`() {
        for (legacy in listOf(false, true)) {
            val raw = duplicateGetters(legacy, secondEnd = 0xe108)
            val error = assertThrows(UltraKernelGenerateException::class.java) { resolveCred(raw) }
            assertEquals("STRUCT_ACCESSOR_UNRESOLVED:__arm64_sys_getuid", error.detail)
        }
    }

    @Test
    fun `different saved ID fields of the same getter are all checked`() {
        for (legacy in listOf(false, true)) {
            val raw = duplicateSavedIds(legacy, secondMember = 32)
            val error = assertThrows(UltraKernelGenerateException::class.java) {
                UltraKernelStructOffsets.credentialLayout(UltraKernelKallsymsTable.decode(raw), raw, 0x780, null)
            }
            assertEquals("STRUCT_OFFSET_AMBIGUOUS:cred.suid", error.detail)
        }
    }

    @Test
    fun `same layout saved ID duplicates remain usable`() {
        for (legacy in listOf(false, true)) {
            val raw = duplicateSavedIds(legacy)
            val layout = UltraKernelStructOffsets.credentialLayout(
                UltraKernelKallsymsTable.decode(raw), raw, 0x780, null)
            assertEquals(16, layout.suid)
            assertEquals(20, layout.sgid)
            assertEquals(24, layout.euid)
        }
    }

    @Test
    fun `each duplicate saved ID getter is bounded by its own next symbol`() {
        for (legacy in listOf(false, true)) {
            val raw = duplicateSavedIds(legacy, secondEnd = 0xe110)
            val error = assertThrows(UltraKernelGenerateException::class.java) {
                UltraKernelStructOffsets.credentialLayout(UltraKernelKallsymsTable.decode(raw), raw, 0x780, null)
            }
            assertEquals("STRUCT_ACCESSOR_UNRESOLVED:__do_sys_getresuid", error.detail)
        }
    }

    @Test
    fun `public decoder keeps sorted distinct candidates and the original minimum lookup`() {
        for (legacy in listOf(false, true)) {
            val raw = fixture(legacy, 1025, 0xf000, symbols = mapOf(
                1000 to ("same_name" to 0xe100), 1001 to ("same_name" to 0xe000),
                1002 to ("same_name" to 0xe100), 1003 to ("same_address" to 0xe200),
                1004 to ("same_address" to 0xe200)))
            val table = UltraKernelKallsymsTable.decode(raw)
            assertEquals(listOf(0xe000, 0xe100), table.offsetsOf("same_name"))
            assertEquals(0xe000, table.offsetOf("same_name"))
            assertEquals(listOf(0xe200), table.offsetsOf("same_address"))
            assertEquals(listOf(0), table.offsetsOf("_text"))
            assertEquals(emptyList<Int>(), table.offsetsOf("absent"))
        }
    }

    @Test
    fun `simple symbol providers retain their default single candidate contract`() {
        val symbols = object : UltraKernelSymbols {
            override val imageSize = 64
            override val summary = "single-candidate"
            override fun offsetOf(name: String): Int? = if (name == "zero") 0 else null
            override fun isSymbolStart(value: Int) = value == 0
            override fun nextOffset(offset: Int): Int? = null
        }
        assertEquals(listOf(0), symbols.offsetsOf("zero"))
        assertEquals(emptyList<Int>(), symbols.offsetsOf("absent"))
    }

    @Test
    fun `duplicate ID converters are recognized at every actual address`() {
        for (legacy in listOf(false, true)) {
            val raw = fixture(legacy, 1025, 0xf000, symbols = mapOf(
                1000 to ("__arm64_sys_getuid" to 0xe000), 1001 to ("getter_end" to 0xe014),
                1002 to ("from_kuid_munged" to 0xe400), 1003 to ("from_kuid_munged" to 0xe500)))
            emit(raw, 0xe000, UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0),
                UltraKernelA64.ldImm("ldr", 8, 8, 0x780, 8), UltraKernelA64.ldImm("ldr", 1, 8, 8, 4),
                UltraKernelA64.encodeBl(0xe00c, 0xe500), UltraKernelA64.RET)
            assertEquals(0x780, resolveCred(raw))
        }
    }

    @Test
    fun `real 6_6 decoder preserves every put_cred candidate from the captured symbol table`() {
        val root = File(System.getProperty("maplesu.repo", ".."))
        val folder = File(root, "native-inputs/kernels/android15-6.6-346d51ea")
        val expected = File(folder, "symbols.tsv").readText().replace("\\t", "\t").lineSequence()
            .map { it.split('\t') }.filter { it.size == 3 && it[2] == "put_cred" }
            .map { it[0].toInt() }.distinct().sorted().toList()
        assertTrue("The captured target must exercise multiple candidates", expected.size > 1)
        val symbols = UltraKernelKallsymsTable.decode(File(folder, "Image").readBytes())
        assertEquals(expected, symbols.offsetsOf("put_cred"))
        assertEquals(expected.first(), symbols.offsetOf("put_cred"))
    }

    private fun resolveCred(raw: ByteArray): Int = UltraKernelStructOffsets.resolve(
        UltraKernelKallsymsTable.decode(raw), raw, setOf(UltraKernelStructOffsets.CRED), emptyMap(), null)
        .getValue(UltraKernelStructOffsets.CRED)

    private fun emit(raw: ByteArray, at: Int, vararg words: Int) {
        words.forEachIndexed { index, word -> UltraKernelA64.writeLe32(raw, at + index * 4, word.toLong()) }
    }

    private fun getter(raw: ByteArray, at: Int, member: Int, taskCred: Int = 0x780) = emit(raw, at,
        UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0), UltraKernelA64.ldImm("ldr", 8, 8, taskCred, 8),
        UltraKernelA64.ldImm("ldr", 0, 8, member, 4), UltraKernelA64.RET)

    private fun saved(raw: ByteArray, at: Int, member: Int) = emit(raw, at,
        UltraKernelA64.mrs(8, UltraKernelA64.MRS_SP_EL0), UltraKernelA64.ldImm("ldr", 8, 8, 0x780, 8),
        UltraKernelA64.ldImm("ldr", 8, 8, member, 4), UltraKernelA64.ldImm("str", 8, 2, 0, 4), UltraKernelA64.RET)

    private fun duplicateGetters(legacy: Boolean, secondAt: Int = 0xe100,
        secondCred: Int = 0x780, secondEnd: Int = secondAt + 16): ByteArray = fixture(
            legacy, 1025, 0xf000, symbols = mapOf(
                1000 to ("__arm64_sys_getuid" to 0xe000),
                1001 to ("first_end" to 0xe010),
                1002 to ("__arm64_sys_getuid" to secondAt),
                1003 to ("second_end" to secondEnd))).also {
            getter(it, 0xe000, 8)
            getter(it, secondAt, 8, secondCred)
        }

    private fun duplicateSavedIds(legacy: Boolean, secondMember: Int = 16,
        secondEnd: Int = 0xe114): ByteArray = fixture(legacy, 1025, 0xf000, symbols = mapOf(
            1000 to ("__do_sys_getresuid" to 0xe000), 1001 to ("first_end" to 0xe014),
            1002 to ("__do_sys_getresuid" to 0xe100), 1003 to ("second_end" to secondEnd),
            1004 to ("__do_sys_getresgid" to 0xe200), 1005 to ("gid_end" to 0xe214),
            1006 to ("__arm64_sys_geteuid" to 0xe300), 1007 to ("euid_end" to 0xe310))).also {
            saved(it, 0xe000, 16)
            saved(it, 0xe100, secondMember)
            saved(it, 0xe200, 20)
            getter(it, 0xe300, 24)
        }

    /** Real label alignment and compressed names, without depending on private probe methods. */
    private fun fixture(legacy: Boolean, count: Int, last: Int, first: Int = 0,
        symbols: Map<Int, Pair<String, Int>> = emptyMap()): ByteArray {
        val out = ByteArrayOutputStream()
        val extraTokens = symbols.values.map { it.first }.distinct().withIndex().associate { it.value to it.index + 129 }
        fun align() { while (out.size() % 8 != 0) out.write(0) }
        fun word(value: Long, size: Int) {
            repeat(size) { out.write((value ushr (it * 8)).toInt() and 255) }
        }
        fun addresses() {
            align()
            repeat(count) {
                word((symbols[it]?.second ?: when (it) { 0 -> first; count - 1 -> last; else -> it * 16 }).toLong(), 4)
            }
            align()
            word(0xFFFFFFC080000000UL.toLong(), 8)
        }
        out.write(ByteArray(128))
        if (legacy) addresses()
        align()
        word(count.toLong(), 4)
        align()
        val namesStart = out.size()
        val markers = mutableListOf<Int>()
        repeat(count) { index ->
            if (index % 256 == 0) markers += out.size() - namesStart
            val tokens = symbols[index]?.let { byteArrayOf(84, extraTokens.getValue(it.first).toByte()) }
                ?: if (index == 0) byteArrayOf(84, 128.toByte()) else
                    byteArrayOf(84, 95) + index.toString().padStart(4, '0').toByteArray()
            out.write(tokens.size)
            out.write(tokens)
        }
        align()
        markers.forEach { word(it.toLong(), 4) }
        align()
        val tokenStart = out.size()
        val tokenIndex = mutableListOf<Int>()
        repeat(256) { index ->
            tokenIndex += out.size() - tokenStart
            val token = extraTokens.entries.firstOrNull { it.value == index }?.key ?: when (index) {
                in 48..57 -> index.toChar().toString()
                84 -> "T"
                95 -> "_s"
                128 -> "_text"
                else -> "z"
            }
            out.write(token.toByteArray())
            out.write(0)
        }
        align()
        tokenIndex.forEach { word(it.toLong(), 2) }
        if (!legacy) addresses()
        return out.toByteArray().copyOf(0x10000).apply {
            byteArrayOf(65, 82, 77, 100).copyInto(this, 56)
        }
    }
}
