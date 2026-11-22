package dev.maplesu.manager.ksu

import org.junit.Assert.*
import org.junit.Test

class KsuModuleReceiptTest {
    private fun ops(receipt: KsuShellResult, calls: MutableList<List<String>> = mutableListOf()) =
        KsuModuleOps(KsuCommandBackend(
            daemonPathProvider = { "/data/adb/ksud" },
            runner = KsuShellRunner { command, _ -> calls += command; receipt },
            probe = object : KsuPathProbe { override fun exists(path: String) = true },
        ))

    @Test fun nonzeroListRetainsActualReceiptAndNeverBecomesEmptySuccess() {
        val receipt = KsuShellResult(7, listOf("partial", ""), listOf("permission denied", ""))
        val calls = mutableListOf<List<String>>()
        val failure = runCatching { ops(receipt, calls).listJson() }.exceptionOrNull()
        assertTrue(failure is KsuModuleListException)
        assertSame(receipt, (failure as KsuModuleListException).receipt)
        assertTrue(failure.message.orEmpty().contains("permission denied"))
        assertEquals(listOf(listOf("/data/adb/ksud", "module", "list")), calls)
    }

    @Test fun malformedSuccessfulListRetainsBytesAndNeverBecomesEmptySuccess() {
        listOf("", "{}", "not json", "[{}]", "[null]").forEach { raw ->
            val receipt = KsuShellResult(0, listOf(raw), listOf("warning"))
            val failure = runCatching { ops(receipt).listJson() }.exceptionOrNull()
            assertTrue("raw=$raw", failure is KsuModuleListException)
            assertSame(receipt, (failure as KsuModuleListException).receipt)
        }
    }

    @Test fun validEmptyListRemainsARealEmptySuccess() {
        assertEquals("[]", ops(KsuShellResult(0, listOf("[]"), emptyList())).listJson())
    }

    @Test fun listCountReportsReadFailure() {
        assertTrue(runCatching { ops(KsuShellResult(9, emptyList(), listOf("read failed"))).count() }
            .exceptionOrNull() is KsuModuleListException)
    }

    @Test fun duplicateUninstallAndUndoEachPreserveOneActualDaemonResult() {
        val receipt = KsuShellResult(19, listOf("output", ""), listOf("mark failed", ""))
        val calls = mutableListOf<List<String>>()
        val backend = ops(receipt, calls)
        repeat(2) { assertSame(receipt, backend.uninstallResult("module-101")) }
        assertSame(receipt, backend.undoUninstallResult("module-101"))
        assertEquals(listOf("uninstall", "uninstall", "undo-uninstall").map {
            listOf("/data/adb/ksud", "module", it, "module-101")
        }, calls)
    }
}
