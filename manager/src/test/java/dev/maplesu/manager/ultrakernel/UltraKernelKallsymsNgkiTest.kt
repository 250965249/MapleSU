package dev.maplesu.manager.ultrakernel

import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.InflaterInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class UltraKernelKallsymsNgkiTest {
    @Test
    fun `real 5_4 retained names addresses and tokens resolve the same image offsets`() {
        val raw = retainedKernel()
        val symbols = UltraKernelKallsymsTable.decode(raw)
        assertEquals(0, symbols.offsetOf("_text"))
        assertEquals(0x1000, symbols.offsetOf("_stext"))
        assertEquals(0x1640000, symbols.offsetOf("_etext"))
        assertEquals(0x32f888, symbols.offsetOf("kallsyms_lookup_name"))
        assertEquals(0L, symbols.textBase)
        assertEquals(0L, symbols.relativeBase)
        val directory = File(System.getProperty("maplesu.ngki.fixture"))
        InflaterInputStream(File(directory, "target-5.4-oracle.tsv.zlib").inputStream())
            .bufferedReader().use { reader ->
                assertEquals("#in-image=${symbols.symbolCount}", reader.readLine())
                reader.lineSequence().forEach { line ->
                    val (name, offsets) = line.split('\t')
                    val expected = offsets.split(',').map(String::toInt)
                    assertEquals(name, expected.first(), symbols.offsetOf(name))
                    assertEquals(name, expected, symbols.offsetsOf(name))
                }
            }
    }

    @Test
    fun `eight byte marker layout searches for a zero extended symbol count`() {
        val symbols = UltraKernelKallsymsTable.decode(legacyFixture(8, 0xFFFFFFC080000000UL.toLong()))
        assertEquals(1025, symbols.symbolCount)
        assertEquals(0, symbols.offsetOf("_text"))
        assertEquals(16, symbols.offsetOf("_s0001"))
        assertEquals(1024 * 16, symbols.offsetOf("_s1024"))
    }

    @Test
    fun `legacy count label immediately follows a zero image relative base`() {
        for (width in listOf(4, 8)) {
            val symbols = UltraKernelKallsymsTable.decode(legacyFixture(width, 0))
            assertEquals(1025, symbols.symbolCount)
            assertEquals(0, symbols.offsetOf("_text"))
            assertEquals(0L, symbols.relativeBase)
            assertEquals(16, symbols.offsetOf("_s0001"))
        }
    }

    @Test
    fun `positive nonzero legacy base is still rejected`() {
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelKallsymsTable.decode(legacyFixture(4, 0x50000))
        }
        assertTrue(error.detail.contains("KALLSYMS_RELATIVE_BASE_IMPLAUSIBLE"))
    }

    @Test
    fun `image relative coordinates require text at the raw Image start`() {
        for (width in listOf(4, 8)) {
            val raw = legacyFixture(width, 0)
            UltraKernelA64.writeLe32(raw, 128, 0x10000)
            val error = assertThrows(UltraKernelGenerateException::class.java) {
                UltraKernelKallsymsTable.decode(raw)
            }
            assertEquals("KALLSYMS_IMAGE_RELATIVE_TEXT_MISMATCH", error.detail)
        }
    }

    @Test
    fun `image relative shifted address table is rejected`() {
        val raw = legacyFixture(4, 0)
        raw.copyInto(raw, 128, 132, 128 + 1025 * 4)
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelKallsymsTable.decode(raw)
        }
        assertEquals("KALLSYMS_IMAGE_RELATIVE_TEXT_MISMATCH", error.detail)
    }

    @Test
    fun `image relative table cannot extend before its component`() {
        val raw = legacyFixture(4, 0).let { it.copyOfRange(136, it.size) }
        "ARMd".toByteArray().copyInto(raw, 56)
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelKallsymsTable.decode(raw)
        }
        assertTrue(error.detail.contains("KALLSYMS_OFFSETS_OUT_OF_RANGE"))
    }

    @Test
    fun `image relative names must match every marker`() {
        val raw = legacyFixture(4, 0)
        val marker = UltraKernelA64.alignUp(4248 + 3 + 1024 * 7, 8)
        UltraKernelA64.writeLe32(raw, marker + 4, UltraKernelA64.le32(raw, marker + 4) + 4)
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelKallsymsTable.decode(raw)
        }
        assertEquals("KALLSYMS_NAMES_MARKER_MISMATCH:256", error.detail)
    }

    @Test
    fun `new address layout still requires a canonical nonzero base`() {
        val raw = legacyFixture(4, 0, modern = true)
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelKallsymsTable.decode(raw)
        }
        assertTrue(error.detail.contains("newer=KALLSYMS_RELATIVE_BASE_IMPLAUSIBLE:0x0"))
    }

    @Test
    fun `new address layout retains canonical base support`() {
        val symbols = UltraKernelKallsymsTable.decode(
            legacyFixture(4, 0xFFFFFFC080000000UL.toLong(), modern = true))
        assertEquals(1025, symbols.symbolCount)
        assertEquals(0, symbols.offsetOf("_text"))
        assertEquals(16, symbols.offsetOf("_s0001"))
    }

    private fun retainedKernel(): ByteArray {
        val directory = File(System.getProperty("maplesu.ngki.fixture"))
        val window = InflaterInputStream(File(directory, "target-5.4-kallsyms.zlib").inputStream()).use { it.readBytes() }
        assertEquals(4854032, window.size)
        return ByteArray(46117376).also {
            File(directory, "target-5.4-header.bin").readBytes().copyInto(it)
            window.copyInto(it, 27125624)
        }
    }

    /** Same label order as scripts/kallsyms.c; all addresses remain relative offsets. */
    private fun legacyFixture(markerWidth: Int, base: Long, modern: Boolean = false): ByteArray {
        val count = 1025
        val out = ByteArrayOutputStream()
        fun align() { while (out.size() % 8 != 0) out.write(0) }
        fun word(value: Long, width: Int) {
            repeat(width) { out.write(((value ushr (it * 8)) and 255).toInt()) }
        }
        out.write(ByteArray(128))
        if (!modern) {
            repeat(count) { word((it * 16).toLong(), 4) }
            align()
            word(base, 8)
        }
        word(count.toLong(), 4)
        align()
        val start = out.size()
        val markers = arrayListOf<Int>()
        repeat(count) { index ->
            if (index % 256 == 0) markers += out.size() - start
            val tokens = if (index == 0) byteArrayOf(84, 128.toByte())
                else byteArrayOf(84, 95) + index.toString().padStart(4, '0').toByteArray()
            out.write(tokens.size)
            out.write(tokens)
        }
        align()
        markers.forEach { word(it.toLong(), markerWidth) }
        align()
        val tokenStart = out.size()
        val tokenIndex = arrayListOf<Int>()
        repeat(256) { index ->
            tokenIndex += out.size() - tokenStart
            val token = when (index) {
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
        if (modern) {
            align()
            repeat(count) { word((it * 16).toLong(), 4) }
            align()
            word(base, 8)
        }
        while (out.size() < 0x6000) out.write(0)
        return out.toByteArray().also {
            "ARMd".toByteArray().copyInto(it, 56)
        }
    }
}
