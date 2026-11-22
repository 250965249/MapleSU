package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootExecResult
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ModeSwitchExactStatusTest {
    @get:Rule val temp = TemporaryFolder()
    private val id = "0f8fad5b-d9cb-469f-a165-70867728950e"

    @Test fun absentRecordRequiresSuccessfulRootReadOfBothFiles() = runBlocking {
        val scripts = mutableListOf<String>()
        val client = client { script -> scripts += script; reply("MAPLESU_SWITCH_RECORD_ABSENT\n") }
        assertNull(withContext(Dispatchers.IO) { client.statusExact(id) })
        assertEquals(listOf("#maplesu:state-read", "#maplesu:journal-read"), scripts.map { it.lineSequence().first() })
        assertFalse(scripts.any { it.contains("dd ") || it.contains("rm ") || it.contains("mkdir ") })
    }

    @Test fun lostRootReadIsReportedAsAnError() = runBlocking {
        val client = client { reply("", 1) }
        val error = runCatching { withContext(Dispatchers.IO) { client.statusExact(id) } }.exceptionOrNull()
        assertEquals("SWITCH_STATUS_READ_FAILED", error?.message)
        assertNull(client.status(id))
    }

    @Test fun unreadableJournalIsAnErrorAfterMissingState() = runBlocking {
        val client = client { script ->
            if (script.startsWith("#maplesu:state-read")) reply("MAPLESU_SWITCH_RECORD_ABSENT\n") else reply("", 1)
        }
        assertEquals("SWITCH_STATUS_READ_FAILED", runCatching {
            withContext(Dispatchers.IO) { client.statusExact(id) }
        }.exceptionOrNull()?.message)
    }

    @Test fun corruptStateIsNotReportedAsNoRecord() {
        File(temp.root, "tx/$id/state.json").apply { requireNotNull(parentFile).mkdirs(); writeText("{") }
        val client = client { error("Unexpected root call") }
        assertEquals("SWITCH_STATUS_RECORD_INVALID", runCatching { client.statusExact(id) }.exceptionOrNull()?.message)
    }

    @Test fun exactStateReadsIgnoreAChangedLatestTask() {
        val state = UltraSwitchStateFile(switchId = id, state = "REBOOT_REQUIRED", fromMode = "LITE",
            toMode = "KSU", targetPartition = "init_boot")
        File(temp.root, "tx/$id/state.json").apply { requireNotNull(parentFile).mkdirs(); writeText(ControlJsonCodec.encode(state)) }
        val other = "d8472b5a-4e2f-4a20-9a26-aa8a9cc70293"
        File(temp.root, "tx/$other/state.json").apply {
            requireNotNull(parentFile).mkdirs(); writeText(ControlJsonCodec.encode(state.copy(switchId = other, state = "PRODUCE")))
        }
        val client = client { error("Unexpected root call") }
        assertEquals(id, client.statusExact(id)?.switchId)
        assertEquals("REBOOT_REQUIRED", client.statusExact(id)?.state)
    }

    private fun client(runner: (String) -> RootExecResult) =
        UltraRootModeSwitchClient(workRoot = temp.root, runner = runner)

    private fun reply(output: String, code: Int = 0) = RootExecResult(RootBackend.ULTRA_ENV, code, output)
}
