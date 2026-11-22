// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ramdisk 结构断言 + 四态解析。
 *
 * 关键安全性质：
 * - 未识别词 → UNKNOWN，**绝不默认 STOCK**（否则会在别人补丁上再打一层）；
 * - `sevenk.ko` 是 7K 双条目布局的产物 → FOREIGN_ARTIFACT，拒绝；
 * - 缺 `init.real`/`kernelsu.ko`/`ksu_config` 任一 → 拒绝（畸形镜像）；
 * - `maplesu_id` 标记决定 OURS vs COMPATIBLE。
 */
class KsuRamdiskAssertionTest {

    private val healthy = setOf("init", "init.real", "kernelsu.ko", "ksu_config", "maplesu_id")

    @Test
    fun oursWhenMarkerPresent() {
        val verdict = KsuRamdiskLayout.verify(healthy)
        assertTrue(verdict is KsuRamdiskLayout.Verdict.Accepted)
        assertEquals(
            RamdiskState.OUR,
            (verdict as KsuRamdiskLayout.Verdict.Accepted).state,
        )
    }

    @Test
    fun compatibleWithoutMarker() {
        val verdict = KsuRamdiskLayout.verify(healthy - "maplesu_id")
        assertTrue(verdict is KsuRamdiskLayout.Verdict.Accepted)
        assertEquals(
            RamdiskState.COMPATIBLE,
            (verdict as KsuRamdiskLayout.Verdict.Accepted).state,
        )
    }

    @Test
    fun foreignArtifactIsRejected() {
        val verdict = KsuRamdiskLayout.verify(healthy + "sevenk.ko")
        assertTrue(verdict is KsuRamdiskLayout.Verdict.Rejected)
        val reasons = (verdict as KsuRamdiskLayout.Verdict.Rejected).reasons
        assertTrue(reasons.any { it.startsWith("FOREIGN_ARTIFACT") })
    }

    @Test
    fun missingEachRequiredEntryIsRejected() {
        KsuRamdiskLayout.REQUIRED_ENTRIES.forEach { entry ->
            val verdict = KsuRamdiskLayout.verify(healthy - entry)
            assertTrue("missing $entry must be rejected", verdict is KsuRamdiskLayout.Verdict.Rejected)
            assertTrue(
                (verdict as KsuRamdiskLayout.Verdict.Rejected).reasons
                    .any { it.contains(entry) },
            )
        }
    }

    @Test
    fun malformedEmptyAndGarbageAreRejected() {
        assertTrue(KsuRamdiskLayout.verify(emptySet()) is KsuRamdiskLayout.Verdict.Rejected)
        assertTrue(
            KsuRamdiskLayout.verify(listOf("", " ", "TRAILER!!!"))
                is KsuRamdiskLayout.Verdict.Rejected,
        )
        // 大小写/空白不应被当作有效条目
        assertTrue(
            KsuRamdiskLayout.verify(listOf("INIT", "init.real ", "kernelsu.ko", "ksu_config"))
                is KsuRamdiskLayout.Verdict.Rejected,
        )
    }

    @Test
    fun requireOursMarkerAddsRejection() {
        val verdict = KsuRamdiskLayout.verify(healthy - "maplesu_id", requireOursMarker = true)
        assertTrue(verdict is KsuRamdiskLayout.Verdict.Rejected)
    }

    @Test
    fun ramdiskStateTokensAreStrictlyMapped() {
        assertEquals(RamdiskState.OUR, RamdiskState.fromToken("ours"))
        assertEquals(RamdiskState.COMPATIBLE, RamdiskState.fromToken(" COMPATIBLE \n"))
        assertEquals(RamdiskState.FOREIGN, RamdiskState.fromToken("foreign"))
        assertEquals(RamdiskState.STOCK, RamdiskState.fromToken("stock"))
        assertEquals(RamdiskState.UNKNOWN, RamdiskState.fromToken("stock-ish"))
        assertEquals(RamdiskState.UNKNOWN, RamdiskState.fromToken(""))
        assertEquals(RamdiskState.UNKNOWN, RamdiskState.fromToken(null))
        // 不得把未知词默认成 STOCK（这是「在别人补丁上再打一层」的入口）
        assertFalse(RamdiskState.fromToken("weird") == RamdiskState.STOCK)
    }

    @Test
    fun newcEntryListingParsesMinimalArchive() {
        val data = newcArchive(
            listOf("init" to "x", "init.real" to "y", "kernelsu.ko" to "zz", "ksu_config" to "1"),
        )
        val names = KsuRamdiskLayout.listNewcEntries(data)
        assertEquals(listOf("init", "init.real", "kernelsu.ko", "ksu_config"), names)
        // 截断/畸形字节流不能崩溃，也不能伪造出条目
        assertTrue(KsuRamdiskLayout.listNewcEntries(ByteArray(3)).isEmpty())
        assertTrue(KsuRamdiskLayout.listNewcEntries("not a cpio".toByteArray()).isEmpty())
    }

    private fun newcArchive(entries: List<Pair<String, String>>): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        fun writeHex(value: Int, width: Int) {
            out.write(String.format("%0${width}x", value).toByteArray(Charsets.US_ASCII))
        }
        for ((name, content) in entries) {
            val nameBytes = name.toByteArray(Charsets.UTF_8) + byteArrayOf(0)
            out.write("070701".toByteArray(Charsets.US_ASCII))
            writeHex(0, 8) // ino
            writeHex(0x81a4, 8) // mode = 0100644（普通文件；0 会被解析器当作异常终止）
            writeHex(0, 8) // uid
            writeHex(0, 8) // gid
            writeHex(0, 8) // nlink
            writeHex(0, 8) // mtime
            writeHex(content.length, 8) // filesize
            writeHex(0, 8) // devmajor
            writeHex(0, 8) // devminor
            writeHex(0, 8) // rdevmajor
            writeHex(0, 8) // rdevminor
            writeHex(nameBytes.size, 8) // namesize
            writeHex(0, 8) // check
            out.write(nameBytes)
            while (out.size() % 4 != 0) out.write(0)
            out.write(content.toByteArray(Charsets.US_ASCII))
            while (out.size() % 4 != 0) out.write(0)
        }
        return out.toByteArray()
    }
}
