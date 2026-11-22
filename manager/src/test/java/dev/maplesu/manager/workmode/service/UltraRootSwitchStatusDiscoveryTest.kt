package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootExecResult
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.nio.file.Files

class UltraRootSwitchStatusDiscoveryTest {
    private val id = "11111111-1111-1111-1111-111111111111"
    private val otherId = "22222222-2222-2222-2222-222222222222"
    private val roots = mutableListOf<File>()
    private val complete = "MAPLESU_SWITCH_LIST_COMPLETE"
    private val absent = "MAPLESU_SWITCH_RECORD_ABSENT"

    @After fun cleanup() { roots.forEach { it.deleteRecursively() } }

    private fun root(): File = Files.createTempDirectory("maplesu-status-discovery-").toFile().also { roots += it }
    private fun json(taskId: String = id) = ControlJsonCodec.encode(UltraSwitchStateFile(
        switchId = taskId, state = "REBOOT_REQUIRED", fromMode = "KSU", toMode = "LITE", targetPartition = "boot"))
    private inline fun <T> background(action: () -> T): T {
        val thread = Thread.currentThread()
        val previous = thread.name
        thread.name = "maplesu-status-discovery-test"
        return try { action() } finally { thread.name = previous }
    }

    @Test fun localDiscoverySkipsNonTasksAndReadsTheLatestActualRecord() {
        val root = root()
        val tx = File(root, "tx").apply { mkdirs() }
        File(tx, "notes").writeText("not a task")
        File(tx, "bad id/state.json").apply { parentFile!!.mkdirs(); writeText("invalid name") }
        File(tx, "empty").mkdirs()
        File(tx, "$otherId/state.json").apply { parentFile!!.mkdirs(); writeText(json(otherId)); setLastModified(1000) }
        File(tx, "$id/state.json").apply { parentFile!!.mkdirs(); writeText(json()); setLastModified(2000) }
        val client = UltraRootModeSwitchClient(runner = { error("local discovery must not run a command") }, workRoot = root)
        assertEquals(id, client.statusExact("")!!.switchId)
    }

    @Test fun localMalformedAndWrongIdRecordsStayErrorsInsteadOfBecomingNoTask() {
        for (wrongId in listOf(false, true)) {
            val root = root()
            File(root, "tx/$id/state.json").apply {
                parentFile!!.mkdirs()
                writeText(if (wrongId) json(otherId) else "{broken")
            }
            val client = UltraRootModeSwitchClient(runner = { error("must read local record") }, workRoot = root)
            val failure = runCatching { client.statusExact("") }.exceptionOrNull()
            assertEquals(if (wrongId) "SWITCH_STATUS_TASK_MISMATCH" else "SWITCH_STATUS_RECORD_INVALID", failure?.message)
        }
    }

    @Test fun remoteDirectoryFailureAndMissingCompletionReceiptAreNotAnEmptyHistory() = background {
        for ((code, output, detail) in listOf(Triple(13, "", "original-list-error"), Triple(0, "", ""))) {
            val client = UltraRootModeSwitchClient(runner = {
                assertTrue(it.startsWith("#maplesu:list-tx\n"))
                RootExecResult(RootBackend.ULTRA_ENV, code, output, detail)
            }, workRoot = File(root(), "remote"))
            val failure = runCatching { client.statusExact("") }.exceptionOrNull()
            assertEquals(detail.ifBlank { "SWITCH_STATUS_READ_FAILED" }, failure?.message)
        }
    }

    @Test fun explicitEmptyRemoteDirectoryAndExactMissingIdReturnNoRecord() = background {
        val scripts = mutableListOf<String>()
        val client = UltraRootModeSwitchClient(runner = {
            scripts += it
            RootExecResult(RootBackend.ULTRA_ENV, 0,
                if (it.startsWith("#maplesu:list-tx\n")) "\n$complete\n" else absent)
        }, workRoot = File(root(), "remote"))
        assertNull(client.statusExact(""))
        assertNull(client.statusExact(id))
        assertTrue(scripts.any { it.startsWith("#maplesu:state-read\n") })
        assertTrue(scripts.any { it.startsWith("#maplesu:journal-read\n") })
    }

    @Test fun remoteDiscoveryValidatesEveryCandidateBeforeUsingItAndQuotesTheRoot() = background {
        val scripts = mutableListOf<String>()
        val workRoot = File(root(), "remote root's")
        fun quoted(path: File) = "'" + path.absolutePath.replace("'", "'\\''") + "'"
        val notesState = quoted(File(workRoot, "tx/notes/state.json"))
        val notesJournal = quoted(File(workRoot, "tx/notes/journal.jsonl"))
        val client = UltraRootModeSwitchClient(runner = {
            scripts += it
            val output = when {
                it.startsWith("#maplesu:list-tx\n") -> "../outside\nbad id\nnotes\n$id\n$complete\n"
                notesState in it || notesJournal in it -> absent
                it.startsWith("#maplesu:state-read\n") -> json()
                else -> absent
            }
            RootExecResult(RootBackend.ULTRA_ENV, 0, output)
        }, workRoot = workRoot)
        assertEquals(id, client.statusExact("")!!.switchId)
        assertTrue(scripts.all { "../outside" !in it && "/bad id/" !in it })
        assertTrue(scripts.first().contains(quoted(File(workRoot, "tx"))))
        assertTrue(scripts.any { notesState in it })
    }

    @Test fun invalidExactIdIsRejectedBeforeAnyRead() {
        val client = UltraRootModeSwitchClient(runner = { error("invalid id must not reach the command") }, workRoot = root())
        assertEquals("SWITCH_STATUS_TASK_INVALID", runCatching { client.statusExact("../outside") }.exceptionOrNull()?.message)
    }
}
