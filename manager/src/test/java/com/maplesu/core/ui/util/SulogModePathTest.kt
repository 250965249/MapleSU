// SPDX-License-Identifier: GPL-3.0-or-later
package com.maplesu.core.ui.util

import dev.maplesu.manager.workmode.WorkMode
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * sulog：目录随模式 + 读取通道随模式（2026-11-01 收尾）。
 *
 * 审计 §7 的两个事实：
 * 1. ksud 把日志写在 `/data/adb/ksu/log`（`defs.rs:17`），而代码恒读
 *    `/data/adb/sevenk/log`（Ultra 的实现细节）→ Normal 下永远"没有日志"；
 * 2. `/data/adb` 是 0700 root，`SuFile` 的默认 shell 是 app uid → 即使路径对了也读不到。
 */
class SulogModePathTest {

    private class FakeTransport(
        private val names: List<String> = emptyList(),
        private val lines: List<String> = emptyList(),
        private val code: Boolean = true,
    ) : SulogTransport {
        val listDirs = mutableListOf<String>()
        val reads = mutableListOf<String>()
        val cleared = mutableListOf<String>()
        val deleted = mutableListOf<String>()

        override fun list(directory: String): List<String> {
            listDirs += directory
            return names
        }

        override fun read(path: String, limit: Int): List<String> {
            reads += "$path#$limit"
            return lines
        }

        override fun clear(path: String): Boolean {
            cleared += path
            return code
        }

        override fun delete(path: String): Boolean {
            deleted += path
            return code
        }
    }

    @After
    fun tearDown() {
        SulogTransports.installForTest(null)
    }

    @Test
    fun directoryIsModeScoped() {
        assertEquals("/data/adb/ksu/log", sulogDirectory(WorkMode.KSU))
        assertEquals("/data/adb/sevenk/log", sulogDirectory(WorkMode.LITE))
        assertEquals("/data/adb/sevenk/log", sulogDirectory(null))
        assertNotEquals(sulogDirectory(WorkMode.KSU), sulogDirectory(WorkMode.LITE))
    }

    @Test
    fun transportIsSelectedByMode() {
        assertTrue(SulogTransports.forMode(WorkMode.KSU) is KsuRootShellSulogTransport)
        assertTrue(SulogTransports.forMode(WorkMode.LITE) === SuFileSulogTransport)
        assertTrue(SulogTransports.forMode(null) === SuFileSulogTransport)
    }

    @Test
    fun listingUsesTheModeDirectory() {
        val transport = FakeTransport(
            names = listOf("sulog-2026-11-01.log", "sulog-2026-10-31-1.log", "not-a-log.txt"),
        )
        SulogTransports.installForTest(transport)
        val files = listSulogFiles()
        assertEquals(listOf("/data/adb/sevenk/log"), transport.listDirs)
        // 只认 sulog-<date>[-n].log，且新的在前（既有排序语义不变）。
        assertEquals(
            listOf("sulog-2026-11-01.log", "sulog-2026-10-31-1.log"),
            files.map { it.name },
        )
        assertEquals("/data/adb/sevenk/log/sulog-2026-11-01.log", files[0].path)
    }

    @Test
    fun readsGoThroughTheSelectedTransport() {
        val transport = FakeTransport(lines = listOf("line-a", "line-b"))
        SulogTransports.installForTest(transport)
        assertEquals(listOf("line-a", "line-b"), readSulogFile("/data/adb/sevenk/log/sulog-2026-11-01.log"))
        assertEquals(listOf("/data/adb/sevenk/log/sulog-2026-11-01.log#1000"), transport.reads)
    }

    @Test
    fun cleanAndDeleteGoThroughTheSelectedTransport() {
        val transport = FakeTransport()
        SulogTransports.installForTest(transport)
        assertTrue(cleanSulogFile("/data/adb/ksu/log/sulog-2026-11-01.log"))
        assertTrue(deleteSulogFile("/data/adb/ksu/log/sulog-2026-10-31.log"))
        assertEquals(listOf("/data/adb/ksu/log/sulog-2026-11-01.log"), transport.cleared)
        assertEquals(listOf("/data/adb/ksu/log/sulog-2026-10-31.log"), transport.deleted)
    }

    // ── KSU transport：命令形态（root shell，不是 SuFile）────────────────

    @Test
    fun ksuTransportBuildsRootShellCommands() {
        val commands = mutableListOf<String>()
        val transport = KsuRootShellSulogTransport { command ->
            commands += command
            SulogCommandResult(0, listOf("sulog-2026-11-01.log"))
        }
        val names = transport.list("/data/adb/ksu/log")
        assertEquals(listOf("sulog-2026-11-01.log"), names)
        assertEquals(listOf("/system/bin/ls -1 '/data/adb/ksu/log' 2>/dev/null"), commands)

        commands.clear()
        transport.read("/data/adb/ksu/log/sulog-2026-11-01.log", 1000)
        assertEquals(
            listOf("/system/bin/tail -n 1000 '/data/adb/ksu/log/sulog-2026-11-01.log' 2>/dev/null"),
            commands,
        )

        commands.clear()
        assertTrue(transport.clear("/data/adb/ksu/log/sulog-2026-11-01.log"))
        assertTrue(transport.delete("/data/adb/ksu/log/sulog-2026-11-01.log"))
        assertEquals(
            listOf(
                ": > '/data/adb/ksu/log/sulog-2026-11-01.log'",
                "/system/bin/rm -f '/data/adb/ksu/log/sulog-2026-11-01.log'",
            ),
            commands,
        )
    }

    @Test
    fun ksuTransportQuotesSingleQuotes() {
        val commands = mutableListOf<String>()
        val transport = KsuRootShellSulogTransport { command ->
            commands += command
            SulogCommandResult(0)
        }
        transport.read("/data/adb/ksu/log/it's.log", 10)
        assertTrue(commands.single().contains("'/data/adb/ksu/log/it'\\''s.log'"))
    }

    @Test
    fun ksuTransportFailsClosedOnNonZeroExit() {
        val transport = KsuRootShellSulogTransport { SulogCommandResult(1) }
        assertTrue(transport.list("/data/adb/ksu/log").isEmpty())
        assertTrue(transport.read("/data/adb/ksu/log/x.log", 10).isEmpty())
        assertTrue(!transport.clear("/data/adb/ksu/log/x.log"))
        assertTrue(!transport.delete("/data/adb/ksu/log/x.log"))
    }

    @Test
    fun ksuTransportSwallowsRunnerExceptions() {
        val transport = KsuRootShellSulogTransport { error("shell died") }
        assertTrue(transport.list("/data/adb/ksu/log").isEmpty())
        assertTrue(!transport.delete("/data/adb/ksu/log/x.log"))
    }
}
