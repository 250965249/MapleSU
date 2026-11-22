// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** 用户模块 ID 对齐固定 KSU module.rs / 模块指南；不涉及实际文件系统长度上限。 */
class KsuModuleIdContractTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val daemon = "/data/adb/ksud"
    private val longId = "A".repeat(129)
    private val invalidIds = listOf("", "a", "1x", "_x", ".x", "-x", "a b", "a/b", "a\nb", "模块")

    private class RecordingRunner(
        private val result: KsuShellResult = KsuShellResult(0, emptyList(), emptyList()),
    ) : KsuShellRunner {
        val calls = mutableListOf<Pair<List<String>, Long>>()

        override fun run(command: List<String>, timeoutMs: Long): KsuShellResult {
            calls += command to timeoutMs
            return result
        }
    }

    private fun backend(
        plain: KsuShellRunner,
        global: KsuShellRunner = plain,
        exists: Boolean = true,
    ): KsuCommandBackend = KsuCommandBackend(
        daemonPathProvider = { daemon },
        runner = plain,
        globalMountRunner = global,
        probe = object : KsuPathProbe {
            override fun exists(path: String): Boolean = exists

            override fun canExecute(path: String): Boolean = exists
        },
    )

    @Test
    fun commandBuilderAcceptsPinnedKsuModuleIdsWithoutExtraLengthLimit() {
        listOf("ab", "a.module", "a_module", "module-101", longId).forEach { id ->
            assertEquals(listOf(daemon, "module", "enable", id), KsuCommands.module(daemon, "enable", id))
        }
    }

    @Test
    fun commandBuilderRejectsIdsOutsidePinnedKsuModuleContract() {
        invalidIds.forEach { id ->
            val error = runCatching { KsuCommands.module(daemon, "enable", id) }.exceptionOrNull()
            assertTrue("invalid module ID must be rejected: $id", error is KsuCommandRejectedException)
        }
    }

    @Test
    fun allOperationsPassTheSameValidIdToTheirExistingRunner() {
        val plain = RecordingRunner()
        val global = RecordingRunner()
        val ops = KsuModuleOps(backend(plain, global))

        assertTrue(ops.toggle(longId, true))
        assertTrue(ops.toggle(longId, false))
        assertTrue(ops.uninstall(longId))
        assertTrue(ops.undoUninstall(longId))
        assertTrue(ops.action(longId).ok)

        assertEquals(
            listOf("enable", "disable", "uninstall", "undo-uninstall").map {
                listOf(daemon, "module", it, longId) to KsuTimeouts.COMMAND_MS
            },
            plain.calls,
        )
        assertEquals(listOf(listOf(daemon, "module", "action", longId) to KsuTimeouts.COMMAND_MS), global.calls)
    }

    @Test
    fun allOperationsRejectInvalidIdsBeforeStartingAnyProcess() {
        val plain = RecordingRunner()
        val global = RecordingRunner()
        val ops = KsuModuleOps(backend(plain, global))

        invalidIds.forEach { id ->
            assertFalse("enable: $id", ops.toggle(id, true))
            assertFalse("disable: $id", ops.toggle(id, false))
            assertFalse("uninstall: $id", ops.uninstall(id))
            assertFalse("undo: $id", ops.undoUninstall(id))
            val action = ops.action(id)
            assertEquals(-1, action.code)
            assertTrue(action.err.contains("KSU_MODULE_ID_REJECTED"))
        }
        assertTrue(plain.calls.isEmpty())
        assertTrue(global.calls.isEmpty())
    }

    @Test
    fun toggleKeepsPlainRunnerTimeoutAndNonzeroFailure() {
        val plain = RecordingRunner(KsuShellResult(7, listOf("output", ""), listOf("error", "")))
        val global = RecordingRunner()
        val ops = KsuModuleOps(backend(plain, global))

        assertFalse(ops.toggle("module-101", true))
        assertFalse(ops.toggle("module-101", false))

        assertEquals(
            listOf("enable", "disable").map {
                listOf(daemon, "module", it, "module-101") to KsuTimeouts.COMMAND_MS
            },
            plain.calls,
        )
        assertTrue(global.calls.isEmpty())
    }

    @Test
    fun missingDaemonStillPreventsEveryModuleOperation() {
        val runner = RecordingRunner()
        val ops = KsuModuleOps(backend(runner, exists = false))

        assertFalse(ops.toggle("module-101", true))
        assertFalse(ops.toggle("module-101", false))
        assertFalse(ops.uninstall("module-101"))
        assertFalse(ops.undoUninstall("module-101"))
        val action = ops.action("module-101")
        assertEquals(-1, action.code)
        assertTrue(action.err.contains(KsuCommandBackend.CODE_KSUD_UNAVAILABLE))
        assertTrue(runner.calls.isEmpty())
    }

    @Test
    fun actionPreservesActualReceiptForLongFormatValidId() {
        val plain = RecordingRunner()
        val global = RecordingRunner(KsuShellResult(7, listOf("output", ""), listOf("error", "")))
        val result = KsuModuleOps(backend(plain, global)).action(longId)

        assertEquals(7, result.code)
        assertEquals("output\n", result.out)
        assertEquals("error\n", result.err)
        assertTrue(plain.calls.isEmpty())
        assertEquals(listOf(listOf(daemon, "module", "action", longId) to KsuTimeouts.COMMAND_MS), global.calls)
    }

    @Test
    fun bootBlockKernelNamesKeepTheirIndependentConstructionBehavior() {
        val source = tmp.newFile("boot.img").apply { writeBytes(ByteArray(16)) }
        val output = File(tmp.root, "out").apply { mkdirs() }
        val command = KsuCommands.bootPatch(
            daemon, source, output, "candidate.img", KsuBootPatchOptions(blockModules = listOf("1", "_v")),
        )

        assertEquals("1,_v", command[command.indexOf("--block-module") + 1])
    }
}
