package dev.maplesu.manager.ultrakernel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

/** Narrow fixtures for target-derived inlined accessor and cache publication evidence. */
class UltraKernelNoBtfInlineAccessTest {
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

    private fun image(position: Int, version: Int): Pair<ByteArray, UltraKernelSymbols> {
        // vfs_setpos's real input/compare/update/error shape, with deliberately varied member sites.
        val code = "3f0002eb8100f8b7ed000054a80280920c000014a80280924c010054094440b909016836083c40f91f0101eb60000054013c00f91f6400f9e00301aac0035fd6e00308aac0035fd6"
        val image = ByteArray(0x1000)
        val start = 0x100
        code.chunked(2).map { it.toInt(16).toByte() }.toByteArray().copyInto(image, start)
        word(image, start + 9 * 4, UltraKernelA64.ldAuto("ldr", 8, 0, position, 8))
        word(image, start + 12 * 4, UltraKernelA64.ldAuto("str", 1, 0, position, 8))
        word(image, start + 13 * 4, UltraKernelA64.ldAuto("str", 31, 0, version, 8))
        return image to symbols(image, mapOf("vfs_setpos" to start, "after_vfs_setpos" to start + code.length / 2))
    }

    private fun cache(size: Int, publication: Int = 0x800, name: String = "dentry"):
        Pair<ByteArray, UltraKernelSymbols> {
        val image = ByteArray(0x1000)
        (name + "\u0000").toByteArray(Charsets.US_ASCII).copyInto(image, 0x600)
        val words = intArrayOf(
            UltraKernelA64.encodeAdrp(0x100, 0x600, 0), UltraKernelA64.addImm(0, 0, 0x600),
            UltraKernelA64.movz(1, size, sf = 0), UltraKernelA64.encodeBl(0x10c, 0x400),
            UltraKernelA64.encodeAdrp(0x110, publication.toLong(), 8),
            UltraKernelA64.ldAuto("str", 0, 8, publication and 0xfff, 8), UltraKernelA64.RET,
        )
        words.forEachIndexed { index, value -> word(image, 0x100 + index * 4, value) }
        return image to symbols(image, mapOf("vfs_caches_init" to 0x100, "after_vfs_caches_init" to 0x11c,
            "kmem_cache_create_usercopy" to 0x400, "dentry_cache" to 0x800))
    }

    @Test fun `inlined cache discovery reads target size not a reference size`() {
        for (size in listOf(208, 272)) {
            val (kernel, symbols) = cache(size)
            assertEquals(size, UltraKernelOwnerSizes.size(symbols, kernel, "dentry"))
        }
    }

    @Test fun `inlined cache requires exact published cache and name`() {
        for ((publication, name) in listOf(0x808 to "dentry", 0x800 to "other")) {
            val (kernel, symbols) = cache(208, publication, name)
            assertEquals(null, UltraKernelOwnerSizes.size(symbols, kernel, "dentry"))
        }
    }

    @Test fun `position comes from the compared and written target member`() {
        for ((position, version) in listOf(96 to 152, 120 to 200)) {
            val (kernel, symbols) = image(position, version)
            val result = UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "file.f_pos")
            assertEquals(position, result.offsetBytes)
            assertEquals(8, result.widthBytes)
            assertTrue(result.source.startsWith("accessor:vfs_setpos:"))
        }
    }

    @Test fun `position and version sharing a member is rejected`() {
        val (kernel, symbols) = image(96, 96)
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "file.f_pos")
        }
        assertTrue(error.message.orEmpty().contains("STRUCT_POSITION_UPDATE"))
    }

    @Test fun `position store not matching the comparison is rejected`() {
        val (kernel, symbols) = image(96, 152)
        word(kernel, 0x100 + 12 * 4, UltraKernelA64.ldAuto("str", 1, 0, 104, 8))
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "file.f_pos")
        }
        assertTrue(error.message.orEmpty().contains("STRUCT_POSITION_UPDATE"))
    }

    @Test fun `unknown store destination is rejected`() {
        val (kernel, symbols) = image(96, 152)
        word(kernel, 0x100 + 13 * 4, UltraKernelA64.ldAuto("str", 31, 3, 152, 8))
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "file.f_pos")
        }
        assertTrue(error.message.orEmpty().contains("STRUCT_POSITION_WRITE"))
    }

    private fun sizeImage(size: Int, storedSize: Int = size, mapping: Int = 48):
        Pair<ByteArray, UltraKernelSymbols> {
        val image = ByteArray(0x1000)
        fun move(destination: Int, source: Int) = 0xaa0003e0.toInt() or (source shl 16) or destination
        val words = intArrayOf(
            move(19, 0), move(20, 1), UltraKernelA64.ldAuto("ldr", 21, 0, size, 8),
            UltraKernelA64.ldAuto("str", 1, 0, storedSize, 8), move(1, 21), move(2, 20),
            UltraKernelA64.encodeBl(0x118, 0x400), UltraKernelA64.ldAuto("ldr", 0, 19, mapping, 8),
            move(1, 20), UltraKernelA64.movn(2, 0), UltraKernelA64.encodeBl(0x128, 0x500), UltraKernelA64.RET,
        )
        words.forEachIndexed { index, value -> word(image, 0x100 + index * 4, value) }
        return image to symbols(image, mapOf("truncate_setsize" to 0x100, "after_truncate_setsize" to 0x130,
            "pagecache_isize_extended" to 0x400, "truncate_inode_pages_range" to 0x500))
    }

    @Test fun `inode size comes from independently correlated old load and new store`() {
        for (offset in listOf(80, 112)) {
            val (kernel, symbols) = sizeImage(offset)
            val result = UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "inode.i_size")
            assertEquals(offset, result.offsetBytes)
            assertEquals(8, result.widthBytes)
            assertTrue(result.source.startsWith("accessor:truncate_setsize:"))
        }
    }

    @Test fun `inode size load and store mismatch is rejected`() {
        val (kernel, symbols) = sizeImage(80, 88)
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "inode.i_size")
        }
        assertTrue(error.message.orEmpty().contains("STRUCT_SIZE_EXTENSION_ARGUMENTS"))
    }

    @Test fun `inode size and mapping member alias is rejected`() {
        val (kernel, symbols) = sizeImage(80, mapping = 80)
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "inode.i_size")
        }
        assertTrue(error.message.orEmpty().contains("STRUCT_SIZE_TRUNCATE_ARGUMENTS"))
    }

    @Test fun `inode size truncation must carry the same new-size argument`() {
        val (kernel, symbols) = sizeImage(80)
        word(kernel, 0x120, UltraKernelA64.movz(1, 0))
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "inode.i_size")
        }
        assertTrue(error.message.orEmpty().contains("STRUCT_SIZE_TRUNCATE_ARGUMENTS"))
    }

    private fun attributeImage(inode: Int, inline: Boolean): Pair<ByteArray, UltraKernelSymbols> {
        val image = ByteArray(0x1000)
        val generic = intArrayOf(UltraKernelA64.ldAuto("ldr", 8, 0, 80, 8),
            UltraKernelA64.ldAuto("str", 8, 1, 56, 8), UltraKernelA64.RET)
        generic.forEachIndexed { index, value -> word(image, 0x400 + index * 4, value) }
        val words = if (inline) intArrayOf(
            UltraKernelA64.ldAuto("ldr", 8, 0, 8, 8), UltraKernelA64.movz(0, 0, sf = 0),
            UltraKernelA64.ldAuto("ldr", 8, 8, inode, 8),
            UltraKernelA64.ldAuto("ldr", 9, 8, 80, 8), UltraKernelA64.ldAuto("str", 9, 1, 56, 8),
            UltraKernelA64.RET,
        ) else intArrayOf(
            UltraKernelA64.ldAuto("ldr", 8, 0, 8, 8), UltraKernelA64.ldAuto("ldr", 0, 8, inode, 8),
            UltraKernelA64.encodeBl(0x108, 0x400), UltraKernelA64.movz(0, 0, sf = 0), UltraKernelA64.RET,
        )
        words.forEachIndexed { index, value -> word(image, 0x100 + index * 4, value) }
        return image to symbols(image, mapOf("simple_getattr" to 0x100,
            "after_simple_getattr" to 0x100 + words.size * 4, "generic_fillattr" to 0x400,
            "after_generic_fillattr" to 0x400 + generic.size * 4))
    }

    @Test fun `dentry inode follows the actual path passed to generic attributes`() {
        for (offset in listOf(48, 80)) for (inline in listOf(false, true)) {
            val (kernel, symbols) = attributeImage(offset, inline)
            val result = UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "dentry.d_inode")
            assertEquals(offset, result.offsetBytes)
            assertEquals(8, result.widthBytes)
            assertTrue(result.source.startsWith("accessor:simple_getattr:"))
        }
    }

    @Test fun `an incomplete generic attribute inline body is rejected`() {
        val (kernel, symbols) = attributeImage(48, true)
        word(kernel, 0x110, UltraKernelA64.ldAuto("str", 9, 1, 64, 8))
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "dentry.d_inode")
        }
        assertTrue(error.message.orEmpty().contains("STRUCT_ATTRIBUTE_INODE"))
    }

    @Test fun `attribute traversal writing to its inode input is rejected`() {
        val (kernel, symbols) = attributeImage(48, true)
        word(kernel, 0x110, UltraKernelA64.ldAuto("str", 9, 8, 80, 8))
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "dentry.d_inode")
        }
        assertTrue(error.message.orEmpty().contains("STRUCT_ATTRIBUTE_WRITE"))
    }

    @Test fun `generic attribute invocation must retain the original stat output`() {
        val (kernel, symbols) = attributeImage(48, false)
        word(kernel, 0x100, UltraKernelA64.ldAuto("ldr", 1, 0, 8, 8))
        word(kernel, 0x104, UltraKernelA64.ldAuto("ldr", 0, 1, 48, 8))
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "dentry.d_inode")
        }
        assertTrue(error.message.orEmpty().contains("STRUCT_ATTRIBUTE_ARGUMENTS"))
    }

    private fun fileInodeImage(inode: Int, helper: String = "posix_lock_inode"):
        Pair<ByteArray, UltraKernelSymbols> {
        val image = ByteArray(0x1000)
        val words = intArrayOf(UltraKernelA64.ldAuto("ldr", 0, 0, inode, 8), UltraKernelA64.NOP,
            UltraKernelA64.encodeBl(0x108, 0x400), UltraKernelA64.NOP, UltraKernelA64.RET)
        words.forEachIndexed { index, value -> word(image, 0x100 + index * 4, value) }
        return image to symbols(image, mapOf("posix_lock_file" to 0x100,
            "after_posix_lock_file" to 0x114, helper to 0x400))
    }

    @Test fun `file inode is the target field forwarded to named inode locking`() {
        for (offset in listOf(32, 88)) for (helper in listOf("posix_lock_inode", "posix_lock_inode.llvm.123456")) {
            val (kernel, symbols) = fileInodeImage(offset, helper)
            val result = UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "file.f_inode")
            assertEquals(offset, result.offsetBytes)
            assertEquals(8, result.widthBytes)
            assertTrue(result.source.startsWith("accessor:posix_lock_file:"))
        }
    }

    @Test fun `inode locking must preserve both original lock arguments`() {
        val (kernel, symbols) = fileInodeImage(32)
        word(kernel, 0x104, 0xaa0203e1.toInt()) // MOV X1,X2 loses the lock request.
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "file.f_inode")
        }
        assertTrue(error.message.orEmpty().contains("STRUCT_LOCK_FORWARD_ARGUMENTS"))
    }

    @Test fun `inode locking must forward its actual helper result`() {
        val (kernel, symbols) = fileInodeImage(32)
        word(kernel, 0x10c, UltraKernelA64.movz(0, 0, sf = 0))
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "file.f_inode")
        }
        assertTrue(error.message.orEmpty().contains("STRUCT_LOCK_FORWARD_RETURN"))
    }

    @Test fun `a similarly named but different inode helper is rejected`() {
        val (kernel, symbols) = fileInodeImage(32, "posix_lock_inode_other")
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "file.f_inode")
        }
        assertTrue(error.message.orEmpty().contains("STRUCT_SUBJECT_CALL"))
    }

    @Test fun `inode forwarding with an opaque store is rejected`() {
        val (kernel, symbols) = fileInodeImage(32)
        word(kernel, 0x104, UltraKernelA64.ldAuto("str", 31, 3, 0, 8))
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, "file.f_inode")
        }
        assertTrue(error.message.orEmpty().contains("STRUCT_LOCK_FORWARD_WRITE"))
    }
}
