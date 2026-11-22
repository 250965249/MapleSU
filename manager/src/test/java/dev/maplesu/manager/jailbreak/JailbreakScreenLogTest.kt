package dev.maplesu.manager.jailbreak

import com.maplesu.core.ui.util.BugreportArchive
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.GZIPInputStream

class JailbreakScreenLogTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun exportedScreenMatchesTheSnapshotAtButtonPress() {
        val lines = mutableListOf(JailbreakLogReader.Line("progress.jsonl", "开始共享接管",
            JailbreakLogReader.Tone.STEP))
        val snapshot = JailbreakLogReader.Snapshot("attempt-a", lines, 7, "PROVIDER_RUNNING")
        val textAtPress = snapshot.text()
        val screen = JailbreakScreenLog(snapshot, "maplesu_93260", "hook")
        lines += JailbreakLogReader.Line("provider.log", "later output", JailbreakLogReader.Tone.DETAIL)
        val destination = temporary.newFolder("report")
        screen.writeTo(destination)
        assertEquals(textAtPress, File(destination, "jailbreak-screen/screen.log").readText())
        val metadata = JSONObject(File(destination, "jailbreak-screen/metadata.json").readText())
        assertEquals("attempt-a", metadata.getString("attemptId"))
        assertEquals("maplesu_93260", metadata.getString("method"))
        assertEquals("hook", metadata.getString("rootBackend"))
        assertEquals("PROVIDER_RUNNING", metadata.getString("stage"))
        assertEquals(1, metadata.getInt("lines"))
        assertEquals(7, metadata.getInt("omitted"))
    }

    @Test fun screenDirectoryIsPackedAndTokensStayRedacted() {
        val token = "12abcdef34abcdef"
        val snapshot = JailbreakLogReader.Snapshot(lines = listOf(
            JailbreakLogReader.Line("provider.log", "suToken=$token", JailbreakLogReader.Tone.DETAIL)))
        val destination = temporary.newFolder("private-report")
        JailbreakScreenLog(snapshot, "maplesu_93260", "ksu").writeTo(destination)
        val archive = BugreportArchive.pack(destination, File(temporary.root, "report.tar.gz"))
        val entries = mutableMapOf<String, String>()
        GZIPInputStream(archive.inputStream()).use { gzip ->
            TarArchiveInputStream(gzip).use { tar ->
                while (true) {
                    val entry = tar.nextEntry ?: break
                    entries[entry.name] = tar.readBytes().toString(Charsets.UTF_8)
                }
            }
        }
        assertEquals(setOf("jailbreak-screen/screen.log", "jailbreak-screen/metadata.json"), entries.keys)
        assertTrue(entries.values.none { it.contains(token) })
        assertTrue(entries.getValue("jailbreak-screen/screen.log").contains("<REDACTED-TOKEN>"))
    }
}
