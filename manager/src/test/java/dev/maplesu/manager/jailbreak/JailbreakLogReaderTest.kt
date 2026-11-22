package dev.maplesu.manager.jailbreak

import java.io.File
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class JailbreakLogReaderTest {
    @get:Rule val temporary = TemporaryFolder()
    private val files by lazy { temporary.newFolder("files") }
    private val protected by lazy { temporary.newFolder("protected") }

    private fun attempt(id: String, method: String = "dirtyfrag", backend: String = "hook", start: Long = 100): File {
        val directory = JailbreakDiagnostics.attemptDirectory(files, id)
        File(directory, "status.json").writeText(JSONObject().put("attemptId", id).put("method", method)
            .put("rootBackend", backend).put("startedAtMillis", start).put("stage", "PROVIDER_RUNNING")
            .put("message", "preparing").toString())
        return directory
    }

    @Test fun followsBothProvidersAndBothTargetsIncludingDetachedWorkerAndLateOutput() {
        for (method in listOf("dirtyfrag", "ghostlock")) for (backend in listOf("ksu", "hook")) {
            val id = "$method-$backend"
            val directory = attempt(id, method, backend)
            val native = File(directory, "$method-native.log").apply { writeText("[*] native started\n") }
            val worker = File(directory, "worker/root-worker.log").apply {
                parentFile!!.mkdirs(); writeText("[+] root worker uid=0\n")
            }
            val reader = JailbreakLogReader(protected, files, method, backend, id)
            val first = reader.poll()
            assertTrue(first.lines.any { it.text == "[*] native started" })
            assertTrue(first.lines.any { it.text == "[+] root worker uid=0" && it.tone == JailbreakLogReader.Tone.SUCCESS })
            assertEquals(first, reader.poll())
            native.appendText("[!] native failed\n")
            worker.appendText("cleanup finished") // No trailing newline is still visible.
            val second = reader.poll()
            assertEquals(1, second.lines.count { it.text == "[*] native started" })
            assertTrue(second.lines.any { it.text == "[!] native failed" && it.tone == JailbreakLogReader.Tone.ERROR })
            assertTrue(second.lines.any { it.text == "cleanup finished" })
        }
    }

    @Test fun neverMixesMethodsTargetsOrPreviousAttemptsAtStart() {
        attempt("old-right-selection", start = 50)
        attempt("different-method", "ghostlock", start = 300)
        attempt("different-target", backend = "ksu", start = 400)
        val reader = JailbreakLogReader(protected, files, "dirtyfrag", "hook", notBefore = 100)
        assertNull(reader.poll().attemptId)
        attempt("current", start = 500)
        assertEquals("current", reader.poll().attemptId)
        attempt("another", start = 600)
        assertEquals("current", reader.poll().attemptId)
    }

    @Test fun liveHelperIsReadOnlyForTheBoundAttemptAndReplacedBySavedCopyWithoutDuplication() {
        val directory = attempt("current")
        val live = File(files, "jailbreak/status.json")
        live.writeText(File(directory, "status.json").readText())
        val helper = File(protected, "maplesu-ultravider.log").apply { writeText("helper line\n") }
        val reader = JailbreakLogReader(protected, files, "dirtyfrag", "hook", "current")
        assertTrue(reader.poll().lines.any { it.text == "helper line" })
        helper.copyTo(File(directory, "maplesu-ultravider.log"))
        live.writeText("""{"attemptId":"different","stage":"PROVIDER_RUNNING"}""")
        helper.writeText("different attempt secret output\n")
        val snapshot = reader.poll()
        assertEquals(1, snapshot.lines.count { it.text == "helper line" })
        assertFalse(snapshot.lines.any { it.text.contains("different attempt") })
    }

    @Test fun incrementalReadsHandleUtf8PartialLinesAndFileTruncation() {
        val directory = attempt("current")
        val native = File(directory, "dirtyfrag-native.log")
        val bytes = "详细过程\n".toByteArray()
        native.writeBytes(bytes.copyOfRange(0, 2))
        val reader = JailbreakLogReader(protected, files, "dirtyfrag", "hook", "current")
        assertFalse(reader.poll().lines.any { it.source == native.name })
        native.appendBytes(bytes.copyOfRange(2, bytes.size))
        assertTrue(reader.poll().lines.any { it.text == "详细过程" })
        native.writeText("new\n")
        assertTrue(reader.poll().lines.any { it.text == "new" })
    }

    @Test fun failedAdmissionDoesNotShowStaleFixedPathOutput() {
        val directory = attempt("new-attempt", start = 1000)
        File(files, "jailbreak/status.json").writeText(File(directory, "status.json").readText())
        File(protected, "maplesu-ultravider.log").apply {
            writeText("earlier helper output\n")
            assertTrue(setLastModified(500))
        }
        val snapshot = JailbreakLogReader(protected, files, "dirtyfrag", "hook", "new-attempt").poll()
        assertFalse(snapshot.lines.any { it.text.contains("earlier helper") })
    }

    @Test fun liveNativeStageIsVisibleBeforeAnAttemptCopyExists() {
        val directory = attempt("current", start = 100)
        File(files, "jailbreak/status.json").writeText(File(directory, "status.json").readText())
        File(protected, "native-stage.log").writeText("[*] native setup in progress")
        val reader = JailbreakLogReader(protected, files, "dirtyfrag", "hook", notBefore = 100)
        assertTrue(reader.poll().lines.any { it.text == "[*] native setup in progress" })
        // An empty attempt copy must not suppress the only live output either.
        File(directory, "dirtyfrag-native.log").createNewFile()
        assertTrue(reader.poll().lines.any { it.text == "[*] native setup in progress" })
    }

    @Test fun requestAndPreparationProgressAreVisibleBeforeProviderStatusForBothModesAndMethods() {
        for (method in listOf("dirtyfrag", "ghostlock")) for (backend in listOf("hook", "ksu")) {
            val request = JailbreakRequest(method, "$method-$backend", null, rootBackend = backend)
            val started = System.currentTimeMillis()
            JailbreakDiagnostics.begin(files, request)
            val reader = JailbreakLogReader(protected, files, method, backend, notBefore = started)
            val initial = reader.poll()
            assertEquals(request.attemptId, initial.attemptId)
            assertTrue(initial.lines.any { it.text.contains("[request]") && it.text.contains("backend=$backend") })
            JailbreakDiagnostics.progress(files, request, "staged", "configuration prepared")
            val progress = reader.poll()
            assertTrue(progress.lines.any { it.text.contains("[staged] configuration prepared") })
            assertEquals(1, progress.lines.count { it.text.contains("[request]") })
        }
    }

    @Test fun reopeningALargeRetainedLogStartsAtTheLatestOutput() {
        val directory = attempt("large")
        val native = File(directory, "dirtyfrag-native.log")
        native.writeText("detail output\n".repeat(100_000) + "[+] latest output\n")
        val bytes = native.length()
        val snapshot = JailbreakLogReader(protected, files, "dirtyfrag", "hook", "large").poll()
        assertTrue(snapshot.lines.any { it.text == "[+] latest output" })
        assertTrue(snapshot.omitted > 0)
        assertEquals(bytes, native.length())
    }

    @Test fun boundedDisplayDoesNotTruncateTheLogFileAndRedactsCopiedContent() {
        val directory = attempt("current")
        val native = File(directory, "dirtyfrag-native.log").apply {
            writeText((1..2500).joinToString("\n") { "detail $it" } + "\nsuToken=12abcdef34abcdef\n")
        }
        val reader = JailbreakLogReader(protected, files, "dirtyfrag", "hook", "current", limit = 100)
        val snapshot = reader.poll()
        assertEquals(100, snapshot.lines.size)
        assertTrue(snapshot.omitted > 0)
        assertFalse(snapshot.lines.any { it.text.contains("12abcdef34abcdef") })
        assertTrue(native.readText().contains("detail 1\n"))
        assertTrue(native.readText().contains("12abcdef34abcdef"))
    }

    @Test fun preparationFailureWithoutProviderStatusRemainsVisible() {
        val directory = JailbreakDiagnostics.attemptDirectory(files, "preparation-failed")
        File(directory, "caller-outcome.json").writeText("""{"method":"ghostlock","rootBackend":"ksu",
            "completedAtMillis":200,"stage":"FAILED","message":"profile check failed",
            "failure":"GHOSTLOCK_PROFILE_INVALID"}""")
        val snapshot = JailbreakLogReader(protected, files, "ghostlock", "ksu", notBefore = 100).poll()
        assertEquals("preparation-failed", snapshot.attemptId)
        assertTrue(snapshot.lines.any { it.text.contains("GHOSTLOCK_PROFILE_INVALID") &&
            it.tone == JailbreakLogReader.Tone.ERROR })
    }

    @Test fun displaysProducerCodesWithoutChangingPersistedEvidence() {
        val directory = attempt("branded-codes")
        val native = File(directory, "dirtyfrag-native.log")
        val raw = "maplesu-dirtyfrag: ir: FAILED MAPLESU_IR_NOT_READY\n" +
            "sdkError=ERR_MAPLESU_ENV_UNPREPARED sdkErrorCode=-19916\n"
        native.writeText(raw)
        val snapshot = JailbreakLogReader(protected, files, "dirtyfrag", "hook", "branded-codes").poll()
        assertTrue(snapshot.text().contains("FAILED MAPLESU_IR_NOT_READY"))
        assertTrue(snapshot.text().contains("ERR_MAPLESU_ENV_UNPREPARED sdkErrorCode=-19916"))
        assertFalse(snapshot.text().contains("MAPLESU_"))
        assertEquals(raw, native.readText())
    }

    @Test fun statusHistoryShowsEachStageWithItsPersistedTimeAndError() {
        val directory = attempt("stages")
        val history = File(directory, "status-history.jsonl")
        history.writeText("""{"stage":"PROVIDER_RUNNING","message":"native started","updatedAtMillis":1000}""" + "\n")
        val reader = JailbreakLogReader(protected, files, "dirtyfrag", "hook", "stages")
        val first = reader.poll()
        assertEquals(1, first.lines.count { it.source == history.name })
        assertFalse(first.lines.any { it.source == "status.json" })
        history.appendText("""{"stage":"FAILED","message":"gate check failed","updatedAtMillis":2000,
            "failure":"HOOK_BACKEND_NOT_READY:su_gate_not_armed"}""".replace("\n", "") + "\n")
        val second = reader.poll()
        assertEquals(2, second.lines.count { it.source == history.name })
        assertTrue(second.lines.any { it.text.contains("[FAILED]") && it.text.contains("su_gate_not_armed") })
        assertTrue(second.lines.filter { it.source == history.name }.all {
            Regex("\\d{2}:\\d{2}:\\d{2}\\.\\d{3}").containsMatchIn(it.text)
        })
    }
}
