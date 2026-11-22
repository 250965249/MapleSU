package dev.maplesu.manager.litehidden

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ELF `DT_NEEDED` 变换的 JVM 测试，使用随测试交付的原始库与固定补丁基准逐字节比较。
 *
 * 这是整个寄生方案里唯一会碰宿主二进制的变换，必须锁死：
 * 只多一个 PT_LOAD + 一条 DT_NEEDED，其余字节零改动，回滚才能做到 sha 级复原。
 */
class HiddenElfTest {

    // 夹具以 `<原名>.bin` 存放：AGP 的 processDebugUnitTestJavaRes 会把 .so/.class 后缀
    // 从 java resources 里过滤掉（MergeJavaResourceTask.excludedFileSuffixes），
    // 直接叫 libt2host.orig.so 的话运行期只会得到 missing fixture。字节不变，见同目录 README。
    private fun fixture(name: String): ByteArray = checkNotNull(
        javaClass.getResourceAsStream("/parasite/$name.bin"),
    ) { "missing fixture $name.bin" }.use { it.readBytes() }

    // 1
    @Test
    fun inspectsVerifiedHostLibrary() {
        val inspection = HiddenElf.inspect(fixture("libt2host.orig.so"))
        assertNotNull(inspection)
        inspection!!
        assertEquals(HiddenElf.ET_DYN, inspection.type)
        assertEquals(HiddenElf.EM_AARCH64, inspection.machine)
        assertTrue(inspection.isSharedObject)
        assertTrue(inspection.isAarch64)
        assertEquals(listOf("liblog.so", "libm.so", "libdl.so", "libc.so"), inspection.needed)
    }

    // 2
    @Test
    fun patchMatchesGoldenArtifactByteForByte() {
        val original = fixture("libt2host.orig.so")
        val expected = fixture("libt2host.patched.so")
        val result = HiddenElf.addNeeded(original, "libmsspike.so")
        assertTrue("patch must succeed: $result", result is ElfPatchResult.Ok)
        val ok = result as ElfPatchResult.Ok
        assertTrue(ok.inserted)
        assertArrayEquals("补丁结果必须与固定基准逐字节一致", expected, ok.bytes)
        assertEquals("fe1be25deba3305a5a3d1795cc3440bc3557dce52ed111f7b2101640bf9fcb26", ok.sha256)
    }

    // 3
    @Test
    fun patchedLibraryKeepsEveryOriginalDependencyAndAddsExactlyOne() {
        val result = HiddenElf.addNeeded(fixture("libt2host.orig.so"), "libmsspike.so") as ElfPatchResult.Ok
        assertEquals(
            listOf("liblog.so", "libm.so", "libdl.so", "libc.so", "libmsspike.so"),
            result.neededAfter,
        )
        assertEquals(4, result.neededBefore.size)
        assertTrue(result.loaderSize > 0)
    }

    // 4
    @Test
    fun patchingAnAlreadyPatchedLibraryIsANoOp() {
        val patched = fixture("libt2host.patched.so")
        val result = HiddenElf.addNeeded(patched, "libmsspike.so")
        assertTrue(result is ElfPatchResult.Ok)
        val ok = result as ElfPatchResult.Ok
        assertFalse("已注入过 → 不重写字节", ok.inserted)
        assertArrayEquals(patched, ok.bytes)
        assertEquals(HiddenElf.inspect(patched)!!.needed, ok.neededAfter)
    }

    // 5
    @Test
    fun patchRefusesNonElfInput() {
        val result = HiddenElf.addNeeded(ByteArray(128) { 0x41 }, "libmsspike.so")
        assertTrue(result is ElfPatchResult.Failed)
        assertEquals(HiddenElf.Codes.NOT_ELF64_LE, (result as ElfPatchResult.Failed).code)
    }

    // 6
    @Test
    fun inspectReturnsNullForNonElf() {
        assertNull(HiddenElf.inspect(ByteArray(64)))
        assertNull(HiddenElf.inspect(ByteArray(0)))
        assertTrue(HiddenElf.neededLibraries(ByteArray(64)).isEmpty())
    }

    // 7
    @Test
    fun patchRefusesLibraryNameWithPath() {
        val result = HiddenElf.addNeeded(fixture("libt2host.orig.so"), "../../evil.so")
        assertTrue(result is ElfPatchResult.Failed)
        assertEquals(HiddenElf.Codes.INVALID_NAME, (result as ElfPatchResult.Failed).code)
    }

    // 8
    @Test
    fun patchedLibraryStillParsesAsSharedObjectWithNewNameBytes() {
        val result = HiddenElf.addNeeded(fixture("libt2host.orig.so"), "libmaplesu_parasite.so") as ElfPatchResult.Ok
        val inspection = HiddenElf.inspect(result.bytes)
        assertNotNull(inspection)
        assertTrue(inspection!!.needed.contains("libmaplesu_parasite.so"))
        val text = String(result.bytes, Charsets.ISO_8859_1)
        assertTrue("新库名必须真的写进字符串表", text.contains("libmaplesu_parasite.so"))
        assertTrue("文件必须变长（追加只读段）", result.bytes.size > fixture("libt2host.orig.so").size)
    }
}
