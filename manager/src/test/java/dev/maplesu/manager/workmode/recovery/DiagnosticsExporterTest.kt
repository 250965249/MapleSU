package dev.maplesu.manager.workmode.recovery

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.control.EvidenceLine
import dev.maplesu.manager.workmode.control.schema.SwitchHeadView
import dev.maplesu.manager.workmode.switch.AvbFacts
import dev.maplesu.manager.workmode.switch.BaselineManifest
import dev.maplesu.manager.workmode.switch.BaselinePartition
import dev.maplesu.manager.workmode.switch.BaselineProvenance
import dev.maplesu.manager.workmode.switch.FileSwitchJournal
import dev.maplesu.manager.workmode.switch.PatchMarkers
import dev.maplesu.manager.workmode.switch.SwitchOp
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/** 诊断导出（主文档 §5.7 / 红线 7）：合并、脱敏、原子写、保留策略。 */
class DiagnosticsExporterTest {
    @get:Rule val tmp = TemporaryFolder()

    private var now = 1_793_260_800_000L
    private val switchId = "3f2b0c9e-6a1d-4c47-9c2e-1b7d5a0f8e33"

    private fun root(): File = tmp.newFolder("workmode")
    private fun diagnostics(): File = File(tmp.root, "diagnostics")

    private fun exporter(root: File = root(), retained: Int = 5): DiagnosticsExporter =
        DiagnosticsExporter(
            root = root,
            diagnosticsDir = diagnostics(),
            clock = { now++ },
            maxRetainedFiles = retained,
        )

    private fun writeEvidence(root: File, vararg lines: EvidenceLine) {
        val file = File(root, "control/evidence.jsonl")
        file.parentFile?.mkdirs()
        lines.forEach { line ->
            AtomicControlFile.appendLine(file, ControlJsonCodec.encode(line))
        }
    }

    private fun writeSwitchHead(root: File, state: String) {
        val json = """
            {"schema":1,"switchId":"$switchId","state":"$state","fromMode":"A","toMode":"B",
             "startBootId":"boot-1","attempts":{"rebootRequests":1},
             "error":{"code":"SWITCH_WRITE","stage":"S4"},"updatedAtUptimeMs":7}
        """.trimIndent()
        // AtomicControlFile 要求父目录已存在（生产侧由 ControlPermissions.ensureTree 预建）；
        // host 夹具按同一契约构造合法 `control/` 目录，不放宽生产校验。
        val target = File(root, "control/switch.json")
        target.parentFile?.mkdirs()
        AtomicControlFile.writeUtf8(target, json.toByteArray(Charsets.UTF_8))
    }

    private fun writeJournal(root: File, code: String = "") {
        val file = File(root, "boot/work/$switchId/journal.jsonl")
        val journal = FileSwitchJournal(file)
        journal.append(
            switchId = switchId,
            planSha256 = "a".repeat(64),
            stage = "S4",
            step = "4d",
            op = SwitchOp.INTENT,
            partition = "init_boot",
            expectedSha256 = "b".repeat(64),
            observedSha256 = "c".repeat(64),
            code = code,
        )
        journal.append(
            switchId = switchId,
            planSha256 = "a".repeat(64),
            stage = "S4",
            step = "4d",
            op = SwitchOp.DONE,
            partition = "init_boot",
            expectedSha256 = "b".repeat(64),
            observedSha256 = "b".repeat(64),
            code = "",
        )
    }

    private fun writeBaseline(root: File, firmware: String = "PLQ110") {
        val manifest = BaselineManifest(
            id = "baseline-1",
            createdAt = 1,
            provenance = BaselineProvenance.OEM_PACKAGE,
            clean = true,
            verifiedAt = 1,
            slot = "_a",
            firmware = firmware,
            kernelRelease = "6.1.75",
            partitions = listOf(
                BaselinePartition("boot", 64, "d".repeat(64), avbTailPreserved = true),
            ),
            avb = AvbFacts(vbmetaPresent = true, vbmetaSha256 = "e".repeat(64), verificationDisabled = false),
            patchMarkers = PatchMarkers(),
        )
        val file = File(root, "boot/baseline/baseline-1/manifest.json")
        file.parentFile?.mkdirs()
        AtomicControlFile.writeJson(file, ControlJsonCodec.encode(manifest, BaselineManifest.serializer()))
    }

    private fun decision(): RecoveryDecision = RecoveryDecisionEngine.decide(
        RecoveryInput(
            head = SwitchHeadView(
                schema = 1, switchId = switchId, state = "RECOVERY_REQUIRED", from = "A", to = "B",
                bootIdAtBegin = "boot-1", pending = true, attempts = 1,
                errorCode = "SWITCH_WRITE", errorStage = "S4", updatedAt = 3,
            ),
            baselineState = dev.maplesu.manager.workmode.switch.BaselineState.PRESENT_OK,
            rootAvailable = true,
            currentBootId = "boot-1",
        ),
    )

    @Test
    fun exportMergesEvidenceJournalAndBaseline() {
        val root = root()
        writeEvidence(root, EvidenceLine(at = 1, bootId = "boot-1", kind = "SWITCH", result = "FAIL"))
        writeSwitchHead(root, "RECOVERY_REQUIRED")
        writeJournal(root)
        writeBaseline(root)
        val result = exporter(root).export(switchId, decision())
        assertTrue(result.file.isFile)
        assertEquals(Hashes.sha256(result.file.readBytes()), result.sha256)
        val snapshot = ControlJsonCodec.decodeOrNull<DiagnosticsSnapshot>(result.file.readText())
        assertNotNull(snapshot)
        snapshot!!
        assertEquals(switchId, snapshot.switchHead?.switchId)
        assertEquals("RECOVERY_REQUIRED", snapshot.switchHead?.state)
        assertTrue(snapshot.journal.present)
        assertFalse(snapshot.journal.corrupt)
        assertEquals(2, snapshot.journal.lines.size)
        assertEquals(1, snapshot.baseline.size)
        assertEquals("baseline-1", snapshot.baseline.single().id)
        assertEquals(1, snapshot.evidence.size)
        assertEquals("AUTO_ROLLBACK", snapshot.recovery?.action)
    }

    @Test
    fun sensitiveEvidenceIsRedactedAndNeverExported() {
        val root = root()
        writeEvidence(
            root,
            EvidenceLine(
                at = 1, bootId = "boot-1", kind = "SWITCH", result = "FAIL",
                error = "rootKey=deadbeef stealth_code=abc123 token=xyz",
            ),
        )
        val exporter = exporter(root)
        val snapshot = exporter.collect(switchId)
        assertTrue(snapshot.redactions >= 1)
        assertTrue(snapshot.evidence.any { it.error == EvidenceLine.EVIDENCE_REDACTED })
        val json = ControlJsonCodec.encode(snapshot)
        listOf("rootKey", "rootkey", "stealth_code", "stealthcode", "token", "deadbeef").forEach { token ->
            assertFalse("must not export $token", json.contains(token, ignoreCase = true))
        }
        assertTrue(json.contains(EvidenceLine.EVIDENCE_REDACTED))
    }

    @Test
    fun exportingAnObservedRootSnapshotDoesNotRereadTheAppUidSource() {
        val root = root()
        writeSwitchHead(root, "VERIFIED")
        val exporter = exporter(root)
        val snapshot = exporter.collect(switchId)
        writeSwitchHead(root, "COMMIT")
        val result = exporter.export(snapshot)
        val exported = ControlJsonCodec.decodeOrNull<DiagnosticsSnapshot>(result.file.readText())!!
        assertEquals("VERIFIED", exported.switchHead?.state)
        assertEquals(Hashes.sha256(result.file.readBytes()), result.sha256)
    }

    @Test
    fun apkPathsAreReplacedByPlaceholder() {
        val root = root()
        writeBaseline(root, firmware = "/data/app/~~abc/com.example/base.apk")
        val json = ControlJsonCodec.encode(exporter(root).collect(switchId))
        assertFalse(json.contains("/data/app/"))
        assertFalse(json.contains(".apk"))
        assertTrue(json.contains("[PATH]"))
    }

    @Test
    fun journalCodesAreRedacted() {
        val root = root()
        writeJournal(root, code = "stealth_code=leaked")
        val json = ControlJsonCodec.encode(exporter(root).collect(switchId))
        assertFalse(json.contains("stealth_code", ignoreCase = true))
        assertTrue(json.contains("[REDACTED]") || json.contains("REDACT", ignoreCase = true))
    }

    @Test
    fun corruptJournalIsFlaggedNotFatal() {
        val root = root()
        val file = File(root, "boot/work/$switchId/journal.jsonl")
        file.parentFile?.mkdirs()
        file.writeText("{broken line\n")
        val snapshot = exporter(root).collect(switchId)
        assertTrue(snapshot.journal.present)
        assertTrue(snapshot.journal.corrupt)
        assertTrue(snapshot.notes.contains("JOURNAL_CORRUPT"))
    }

    @Test
    fun missingArtifactsAreReportedHonestly() {
        val root = root()
        val snapshot = exporter(root).collect(switchId)
        assertFalse(snapshot.journal.present)
        assertTrue(snapshot.baseline.isEmpty())
        assertTrue(snapshot.evidence.isEmpty())
        assertTrue(snapshot.notes.contains("JOURNAL_MISSING"))
        assertTrue(snapshot.notes.contains("BASELINE_NONE"))
        assertEquals(null, snapshot.switchHead)
    }

    @Test
    fun exportWritesJsonAndRecordsHash() {
        val root = root()
        writeSwitchHead(root, "VERIFIED")
        val result = exporter(root).export(switchId)
        assertTrue(result.bytes > 0)
        assertEquals(result.bytes, result.file.length())
        val text = result.file.readText()
        assertTrue(text.contains("\"schema\":1"))
        assertTrue(text.contains("MAPLESU_W16_DIAGNOSTICS"))
    }

    @Test
    fun exportPrunesOldFiles() {
        val root = root()
        writeSwitchHead(root, "VERIFIED")
        val exporter = exporter(root, retained = 2)
        repeat(3) { exporter.export(switchId) }
        val files = diagnostics().listFiles()!!.filter { it.name.startsWith("diagnostics-") }
        assertEquals(2, files.size)
    }

    @Test
    fun switchIdIsOptionalForOrdinaryDiagnostics() {
        val root = root()
        writeSwitchHead(root, "VERIFIED")
        val snapshot = exporter(root).collect(null)
        assertNotNull(snapshot.switchHead)
        assertFalse(snapshot.journal.present)
        assertEquals("", snapshot.switchId)
    }

    @Test
    fun decisionIsEncodedWithReasonsAndControls() {
        val root = root()
        writeSwitchHead(root, "RECOVERY_REQUIRED")
        writeBaseline(root)
        val snapshot = exporter(root).collect(switchId, decision())
        val recovery = snapshot.recovery!!
        assertEquals("AUTO_ROLLBACK", recovery.action)
        assertTrue(recovery.reasons.contains("RECOVERY_REQUIRED"))
        assertTrue(recovery.allowed.contains("ROLLBACK"))
        assertTrue(recovery.blocked.contains("SWITCH"))
        assertFalse(recovery.requiresExternalImage)
    }
}
