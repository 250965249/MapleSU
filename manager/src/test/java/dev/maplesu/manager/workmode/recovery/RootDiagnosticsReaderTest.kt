package dev.maplesu.manager.workmode.recovery

import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootExecResult
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.control.EvidenceLine
import dev.maplesu.manager.workmode.switch.AvbFacts
import dev.maplesu.manager.workmode.switch.BaselineManifest
import dev.maplesu.manager.workmode.switch.PatchMarkers
import java.io.File
import java.util.Base64
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class RootDiagnosticsReaderTest {
    @get:Rule val tmp = TemporaryFolder()

    @Test fun realShellReadsOnlyMetadataAndReusesTheExistingRedactor() {
        val root = tmp.newFolder("root's metadata")
        val cache = tmp.newFolder("cache")
        write(root, "control/switch.json", """{"switchId":"switch-1","state":"VERIFIED"}""")
        write(root, "control/device.kernel", "6.6.89\n")
        write(root, "control/boot_id", "boot-fixture\n")
        write(root, "control/evidence.jsonl", ControlJsonCodec.encode(EvidenceLine(
            at = 1, bootId = "boot-fixture", kind = "SWITCH", result = "FAIL", error = "token=private-value",
        )) + "\n")
        val manifest = BaselineManifest(id = "base-1", createdAt = 1, provenance = "OEM_PACKAGE",
            clean = true, verifiedAt = 1, slot = "_a", firmware = "device", kernelRelease = "6.6.89",
            partitions = emptyList(), avb = AvbFacts(false, verificationDisabled = false), patchMarkers = PatchMarkers())
        write(root, "boot/baseline/base-1/manifest.json", ControlJsonCodec.encode(manifest, BaselineManifest.serializer()))
        write(root, "boot/baseline/base-1/boot.img", "binary-image-private-value")
        write(root, "control/private.key", "credential-private-value")
        var captured = ""
        val snapshot = RootDiagnosticsReader(root, cache) { script -> shell(script).also { captured = it.output } }.read("switch-1")
        assertEquals("VERIFIED", snapshot.switchHead?.state)
        assertEquals("6.6.89", snapshot.device.kernelRelease)
        assertEquals("base-1", snapshot.baseline.single().id)
        assertEquals(1, snapshot.redactions)
        assertTrue(snapshot.notes.contains("ROOT_BACKEND:ULTRA_ENV"))
        assertFalse(ControlJsonCodec.encode(snapshot).contains("private-value"))
        assertFalse(captured.contains(encode("binary-image-private-value")))
        assertFalse(captured.contains(encode("credential-private-value")))
        assertTrue(cache.listFiles().orEmpty().isEmpty())
        assertEquals("credential-private-value", File(root, "control/private.key").readText())
    }

    @Test fun realShellReadsTheRequestedJournalWithoutLosingTruncatedTailEvidence() {
        val root = tmp.newFolder("source")
        write(root, "boot/work/switch-1/journal.jsonl", "unfinished tail")
        val snapshot = RootDiagnosticsReader(root, tmp.newFolder("cache"), ::shell).read("switch-1")
        assertTrue(snapshot.journal.present)
        assertTrue(snapshot.journal.truncatedTail)
        assertEquals("unfinished tail", File(root, "boot/work/switch-1/journal.jsonl").readText())
    }

    @Test fun aVerifiedRootWithNoControlTreeReportsMissingRecordsHonestly() {
        val root = File(tmp.root, "not-initialized")
        val snapshot = RootDiagnosticsReader(root, tmp.newFolder("cache"), ::shell).read("")
        assertNull(snapshot.switchHead)
        assertTrue(snapshot.notes.contains("CONTROL_ROOT_MISSING"))
        assertTrue(snapshot.notes.contains("ROOT_BACKEND:ULTRA_ENV"))
        assertFalse(root.exists())
    }

    @Test fun aNonRootShellFailsEvenWhenDiagnosticFilesExist() {
        val root = tmp.newFolder("source")
        write(root, "control/switch.json", """{"switchId":"switch-1","state":"VERIFIED"}""")
        val error = failure { RootDiagnosticsReader(root, tmp.newFolder("cache")) { shell(it, uid = "2000") }.read("") }
        assertTrue(error.message.orEmpty().contains("DIAGNOSTICS_ROOT_IDENTITY_REQUIRED"))
    }

    @Test fun aRootTransportFailureRetainsTheBackendExitAndOriginalDetail() {
        val error = failure { RootDiagnosticsReader(tmp.root, tmp.newFolder("cache")) {
            RootExecResult(RootBackend.ULTRA_ENV, 7, "", "ULTRA_ROOT_COMMAND_EXIT:7")
        }.read("") }
        assertTrue(error.message.orEmpty().contains("ULTRA_ENV:exit=7:ULTRA_ROOT_COMMAND_EXIT:7"))
    }

    @Test fun aFileTypeErrorIsReportedInsteadOfBecomingAnEmptySnapshot() {
        val root = tmp.newFolder("source")
        File(root, "control/device.slot").mkdirs()
        val error = failure { RootDiagnosticsReader(root, tmp.newFolder("cache"), ::shell).read("") }
        assertTrue(error.message.orEmpty().contains("DIAGNOSTICS_SOURCE_UNREADABLE"))
    }

    @Test fun malformedReceiptsAndUnprovenIdentityNeverProduceAReadableSnapshot() {
        listOf("", "MAPLESU_DIAGNOSTICS_V1\nEND\n", "MAPLESU_DIAGNOSTICS_V1\nUID\t2000\nEND\n",
            "MAPLESU_DIAGNOSTICS_V1\nUID\t0\nFILE\tcontrol/switch.json\t\n").forEach { output ->
            assertEquals("DIAGNOSTICS_REPLY_INVALID", failure {
                RootDiagnosticsReader(tmp.root, tmp.root) { RootExecResult(RootBackend.ULTRA_ENV, 0, output) }.read("")
            }.message)
        }
    }

    @Test fun sourcePathsAndInvalidSwitchIdsStayInsideTheMetadataWhitelist() {
        var calls = 0
        assertEquals("DIAGNOSTICS_SWITCH_ID_INVALID", failure {
            RootDiagnosticsReader(tmp.root, tmp.root) { calls++; error("unexpected command") }.read("../secret")
        }.message)
        assertEquals(0, calls)
        listOf("../../secret", "control/private.key", "boot/baseline/base-1/boot.img",
            "boot/work/other/journal.jsonl").forEach { path ->
            val output = "MAPLESU_DIAGNOSTICS_V1\nUID\t0\nFILE\t$path\t${encode("private")}\nEND\n"
            assertEquals("DIAGNOSTICS_PATH_INVALID", failure {
                RootDiagnosticsReader(tmp.root, tmp.root) { RootExecResult(RootBackend.ULTRA_ENV, 0, output) }.read("switch-1")
            }.message)
        }
    }

    private fun shell(script: String): RootExecResult = shell(script, "0")

    private fun shell(script: String, uid: String): RootExecResult {
        val executable = listOf("/bin/sh", "C:/Program Files/Git/bin/bash.exe").firstOrNull { File(it).canExecute() }
        assumeTrue("A POSIX shell is required", executable != null)
        // The host uid is unrelated to the device transport; only this identity probe is substituted.
        val process = ProcessBuilder(executable!!, "-s").redirectErrorStream(true).start()
        process.outputStream.bufferedWriter().use { it.write(script.replace("id -u", "printf $uid")); it.newLine() }
        val output = process.inputStream.bufferedReader().use { it.readText() }
        assertTrue(process.waitFor(5, TimeUnit.SECONDS))
        return RootExecResult(RootBackend.ULTRA_ENV, process.exitValue(), output, "HOST_EXIT:${process.exitValue()}")
    }

    private fun write(root: File, path: String, text: String) {
        val file = File(root, path)
        file.parentFile!!.mkdirs()
        file.writeText(text)
    }

    private fun encode(text: String) = Base64.getEncoder().encodeToString(text.toByteArray())

    private fun failure(action: () -> Unit): Exception = try {
        action()
        throw AssertionError("Expected a diagnostic read failure")
    } catch (error: Exception) { error }
}
