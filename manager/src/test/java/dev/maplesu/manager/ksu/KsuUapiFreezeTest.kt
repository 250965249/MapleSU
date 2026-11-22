// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * UAPI=7 冻结表：ioctls 30–36，22 保留给上游。
 * 只读 applied 树，不执行 native。
 */
class KsuUapiFreezeTest {

    private fun header(): String {
        val file = File(KsuTestPaths.applied(), "uapi/supercall.h")
        assertTrue("applied/uapi/supercall.h not generated (run rebuild.sh)", file.isFile)
        return file.readText()
    }

    private fun ioctlNumber(text: String, name: String): Int {
        val match = Regex("""KSU_IOCTL_$name\s*=\s*_IO[RW]*\('K',\s*(\d+)""").find(text)
        assertTrue("ioctl not found: $name", match != null)
        return match!!.groupValues[1].toInt()
    }

    @Test
    fun uapiVersionIsSeven() {
        assertTrue(
            Regex("""KERNEL_SU_UAPI_VERSION\s*=\s*7\s*;""").containsMatchIn(header()),
        )
    }

    @Test
    fun frozenIoctlNumbers() {
        val text = header()
        // 上游保留：22 必须仍是 LOOKUP_SYMBOLS
        assertEquals(22, ioctlNumber(text, "LOOKUP_SYMBOLS"))
        assertEquals(30, ioctlNumber(text, "APP_LOCK_STATE"))
        assertEquals(31, ioctlNumber(text, "APP_LOCK_AUTH"))
        assertEquals(32, ioctlNumber(text, "APP_LOCK_SET"))
        assertEquals(33, ioctlNumber(text, "STEALTH_GET"))
        assertEquals(34, ioctlNumber(text, "STEALTH_SET"))
        assertEquals(35, ioctlNumber(text, "STEALTH_GET_G"))
        assertEquals(36, ioctlNumber(text, "STEALTH_SET_G"))
    }

    @Test
    fun noDuplicateIoctlNumbers() {
        val text = header()
        val numbers = Regex("""KSU_IOCTL_\w+\s*=\s*_IO[RW]*\('K',\s*(\d+)""")
            .findAll(text).map { it.groupValues[1].toInt() }.toList()
        assertTrue(numbers.isNotEmpty())
        assertEquals("duplicate ioctl number: $numbers", numbers.size, numbers.toSet().size)
    }

    @Test
    fun reservedNumbersNotUsed() {
        val text = header()
        listOf(37, 38, 39).forEach { reserved ->
            assertFalse(
                "reserved ioctl number $reserved must stay unused",
                Regex("""_IO[RW]*\('K',\s*$reserved[,)]""").containsMatchIn(text),
            )
        }
    }

    @Test
    fun structLayoutIsByteStable() {
        val text = header()
        // 7K 的结构体字段顺序/尺寸不得变（变了必须升 UAPI 并同步三端）
        assertTrue(text.contains("struct ksu_app_lock_state_cmd {"))
        assertTrue(text.contains("struct ksu_app_lock_auth_cmd {"))
        assertTrue(text.contains("struct ksu_app_lock_set_cmd {"))
        assertTrue(text.contains("struct ksu_stealth_cmd {"))
        assertTrue(text.contains("struct ksu_stealth_gen_cmd {"))
        assertTrue(text.contains("__u8 hash[32];"))
        assertTrue(text.contains("__u32 manager_gen;"))
        assertTrue(text.contains("__u8 _pad[3];"))
        assertTrue(text.contains("__u8 configured;"))
        assertTrue(text.contains("__u8 authed;"))
    }

    @Test
    fun threeUapiCopiesAreByteIdentical() {
        val applied = KsuTestPaths.applied()
        assertTrue("applied/ not generated", applied.isDirectory)
        val canonical = File(applied, "uapi/supercall.h").readBytes()
        listOf(
            "kernel/include/uapi/supercall.h",
            "manager/app/src/main/cpp/uapi/supercall.h",
        ).forEach { rel ->
            val copy = File(applied, rel)
            assertTrue("missing same-tree copy: $rel", copy.isFile)
            assertTrue("same-tree broken: $rel", canonical.contentEquals(copy.readBytes()))
        }
    }
}
