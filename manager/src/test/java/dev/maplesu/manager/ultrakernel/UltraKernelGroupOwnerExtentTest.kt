package dev.maplesu.manager.ultrakernel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

/** Only the five new fixed-header regressions; prior 19 accessor checks are reused. */
class UltraKernelGroupOwnerExtentTest {
    private fun symbols(image: ByteArray, entries: Map<String, Int>) = object : UltraKernelSymbols {
        override val imageSize = image.size
        override fun offsetOf(name: String) = entries[name]
        override fun isSymbolStart(value: Int) = value in entries.values
        override fun nameAt(offset: Int) = entries.entries.firstOrNull { it.value == offset }?.key
        override fun nextOffset(offset: Int) = entries.values.filter { it > offset }.minOrNull()
        override val summary = "synthetic-inline-accessor"
    }

    private fun word(image: ByteArray, at: Int, value: Int) {
        for (byte in 0..3) image[at + byte] = (value ushr (byte * 8)).toByte()
    }

    private fun groupHeaderImage(extent: Int, fallbackExtent: Int = extent,
        storeOffset: Int = 0, guarded: Boolean = true, unknownSize: Boolean = false):
        Pair<ByteArray, UltraKernelSymbols> {
        val image = ByteArray(0x1000)
        val words = intArrayOf(
            0x531e7409, // LSL W9,W0,#2; zero-count input, not a slab slot.
            UltraKernelA64.addImm(20, 9, extent, sf = 0),
            if (unknownSize) 0xaa0303e0.toInt() else 0xaa1403e0.toInt(),
            UltraKernelA64.encodeBl(0x10c, 0x400),
            UltraKernelA64.encodeCbz(0, 0x110, 0x120, sf = true, nonZero = true),
            UltraKernelA64.movz(0, fallbackExtent),
            UltraKernelA64.encodeBl(0x118, 0x440),
            if (guarded) UltraKernelA64.encodeCbz(0, 0x11c, 0x128, sf = true, nonZero = false)
                else UltraKernelA64.NOP,
            UltraKernelA64.movz(8, 1, sf = 0),
            UltraKernelA64.ldAuto("str", 8, 0, storeOffset, 4),
            UltraKernelA64.RET,
        )
        words.forEachIndexed { index, value -> word(image, 0x100 + index * 4, value) }
        return image to symbols(image, mapOf("groups_alloc" to 0x100, "after_groups_alloc" to 0x12c,
            "__kmalloc" to 0x400, "__vmalloc" to 0x440))
    }

    @Test fun `flexible group header uses target zero-count allocation size`() {
        for (extent in listOf(8, 24)) {
            val (kernel, symbols) = groupHeaderImage(extent)
            assertEquals(extent, UltraKernelOwnerSizes.size(symbols, kernel, "group_info"))
        }
    }

    @Test fun `group header allocation alternatives must agree on exact size`() {
        val (kernel, symbols) = groupHeaderImage(8, fallbackExtent = 24)
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelOwnerSizes.size(symbols, kernel, "group_info")
        }
        assertTrue(error.message.orEmpty().contains("STRUCT_ALLOCATION_EXTENT_AMBIGUOUS"))
    }

    @Test fun `group initializer must fit the requested zero-count header`() {
        val (kernel, symbols) = groupHeaderImage(8, storeOffset = 8)
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelOwnerSizes.size(symbols, kernel, "group_info")
        }
        assertTrue(error.message.orEmpty().contains("STRUCT_ALLOCATION_HEADER"))
    }

    @Test fun `group header writes require the actual returned allocation null guard`() {
        val (kernel, symbols) = groupHeaderImage(8, guarded = false)
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelOwnerSizes.size(symbols, kernel, "group_info")
        }
        assertTrue(error.message.orEmpty().contains("STRUCT_ALLOCATION_HEADER"))
    }

    @Test fun `unknown allocator size does not qualify a group header extent`() {
        val (kernel, symbols) = groupHeaderImage(8, unknownSize = true)
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelOwnerSizes.size(symbols, kernel, "group_info")
        }
        assertTrue(error.message.orEmpty().contains("STRUCT_ALLOCATION_EXTENT"))
    }
}
