package com.maplesu.core.ui.util

import dev.maplesu.manager.jailbreak.JailbreakDiagnostics
import dev.maplesu.manager.jailbreak.JailbreakStatus
import dev.maplesu.manager.jailbreak.JailbreakRequest
import dev.maplesu.manager.jailbreak.JailbreakController
import org.json.JSONObject
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.GZIPInputStream

class JailbreakDiagnosticsTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun exportsModeAndFailureWhenTheProviderNeverWroteAStatus() {
        val files = temporary.newFolder("caller-files")
        val report = temporary.newFolder("caller-report")
        val request = JailbreakRequest("dirtyfrag", "failed-before-provider", "boot-1", rootBackend = "hook")
        JailbreakDiagnostics.recordOutcome(files, request, JailbreakController.Outcome(
            JailbreakStatus.STAGE_FAILED, "connection failed", "JAILBREAK_ATTEMPT_FAILED"))
        BugreportDiagnostics.collect(temporary.newFolder("caller-protected"), files, report)
        val document = JSONObject(File(report,
            "jailbreak/attempts/failed-before-provider/caller-outcome.json").readText())
        assertEquals("hook", document.getString("rootBackend"))
        assertEquals("dirtyfrag", document.getString("method"))
        assertEquals("JAILBREAK_ATTEMPT_FAILED", document.getString("failure"))
        assertFalse(File(files, "jailbreak/status.json").exists())
    }

    @Test fun exportsBothProvidersAndBothModesAcrossAttemptsAndReboots() {
        val protected = temporary.newFolder("protected")
        val files = temporary.newFolder("files")
        val report = temporary.newFolder("report")
        for (provider in listOf("dirtyfrag", "ghostlock")) for (backend in listOf("ksu", "hook")) {
            val id = "$provider-$backend"
            val status = JailbreakStatus(provider, JailbreakStatus.STAGE_PROVIDER_RUNNING, "started",
                1, 2, "boot-$id", attemptId = id, rootBackend = backend)
            File(protected, "maplesu-ultravider.log").writeText("helper:$id\n")
            JailbreakDiagnostics.record(protected, files, status,
                """{"method":"$provider","rootBackend":"$backend","stage":"PROVIDER_RUNNING","bootId":"boot-$id"}""")
            val directory = JailbreakDiagnostics.attemptDirectory(files, id)
            File(directory, "$provider-native.log").writeText("native:$id\n" + "output\n".repeat(2000))
            File(directory, "ghostlock-worker").mkdir()
            File(directory, "ghostlock-worker/root-worker.log").writeText("restore:$id\n")
            File(directory, "ghostlock-worker/.ghostlock_root.sh").writeText("private invocation")
            JailbreakDiagnostics.record(protected, files, status.copy(stage = JailbreakStatus.STAGE_FAILED),
                """{"failure":"HOOK_BACKEND_NOT_READY:su_gate_not_armed","suToken":"12abcdef34abcdef"}""")
        }
        // The live files now belong to a different attempt; earlier copies must survive.
        File(protected, "maplesu-ultravider.log").writeText("later boot")
        BugreportDiagnostics.collect(protected, files, report)
        val archive = BugreportArchive.pack(report, File(temporary.root, "report.tar.gz"))
        val entries = linkedMapOf<String, String>()
        GZIPInputStream(archive.inputStream()).use { gzip -> TarArchiveInputStream(gzip).use { tar ->
            while (true) {
                val entry = tar.nextEntry ?: break
                entries[entry.name] = tar.readBytes().toString(Charsets.UTF_8)
            }
        } }
        for (provider in listOf("dirtyfrag", "ghostlock")) for (backend in listOf("ksu", "hook")) {
            val id = "$provider-$backend"
            val prefix = "jailbreak/attempts/$id/"
            assertEquals("helper:$id\n", entries.getValue(prefix + "maplesu-ultravider.log"))
            assertEquals("native:$id\n" + "output\n".repeat(2000), entries.getValue(prefix + "$provider-native.log"))
            assertEquals("restore:$id\n", entries.getValue(prefix + "ghostlock-worker/root-worker.log"))
            val history = entries.getValue(prefix + "status-history.jsonl")
            assertTrue(history.contains("\"rootBackend\":\"$backend\""))
            assertTrue(history.contains("su_gate_not_armed"))
            assertFalse(history.contains("12abcdef34abcdef"))
        }
        assertFalse(entries.keys.any { it.endsWith(".sh") })
        assertFalse(entries.values.any { it.contains("12abcdef34abcdef") })
        assertTrue(entries.getValue("diagnostics-collection.log").contains("COPIED jailbreak/attempts/dirtyfrag-hook/dirtyfrag-native.log"))
        assertTrue(entries.getValue("diagnostics-collection.log").contains("MISSING_OR_UNREADABLE maplesu-hook-unload.json"))
    }
}
