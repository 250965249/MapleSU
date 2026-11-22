package dev.maplesu.manager.workmode.recovery

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.control.EvidenceLine
import dev.maplesu.manager.workmode.control.EvidenceLog
import dev.maplesu.manager.workmode.control.EvidenceRedactor
import dev.maplesu.manager.workmode.control.schema.SwitchHeadViewCodec
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.WallClock
import dev.maplesu.manager.workmode.switch.BaselineManifest
import dev.maplesu.manager.workmode.switch.FileSwitchJournal
import dev.maplesu.manager.workmode.switch.JournalLine
import kotlinx.serialization.Serializable
import java.io.File

/**
 * 诊断导出。
 *
 * 合并 `control/evidence.jsonl` + `boot/work/<switchId>/journal.jsonl` + `boot/baseline/<id>/manifest.json`
 * + `control/switch.json` 投影，输出**脱敏** JSON 到 `diagnosticsDir`（设备上 = `filesDir/diagnostics`）。
 *
 * 红线（发布红线 7）：凭据、rootKey、stealth_code、token、密码、signer 明文、APK 原始路径
 * **绝不出现**；命中敏感行整条替换为 `EVIDENCE_REDACTED`，命中路径替换为 `[PATH]`。
 * 本类只读控制面，不写 `/data/adb`、不执行任何 root 命令。
 */
@Serializable
data class DiagnosticsDevice(
    val slot: String = "",
    val firmware: String = "",
    val kernelRelease: String = "",
    val bootId: String = "",
)

@Serializable
data class DiagnosticsRecovery(
    val action: String = "",
    val reasons: List<String> = emptyList(),
    val allowed: List<String> = emptyList(),
    val blocked: List<String> = emptyList(),
    val titleKey: String = "",
    val detailKey: String = "",
    val nextStepKey: String = "",
    val requiresExternalImage: Boolean = false,
    val diagnosticOnly: Boolean = false,
)

@Serializable
data class DiagnosticsSwitchHead(
    val switchId: String = "",
    val state: String = "",
    val from: String = "",
    val to: String = "",
    val pending: Boolean = false,
    val attempts: Int = 0,
    val errorCode: String = "",
    val errorStage: String = "",
    val bootIdAtBegin: String = "",
)

@Serializable
data class DiagnosticsJournalLine(
    val seq: Long = 0,
    val stage: String = "",
    val step: String = "",
    val partition: String = "",
    val op: String = "",
    val expectedSha256: String = "",
    val observedSha256: String = "",
    val code: String = "",
    val bootId: String = "",
    val atUptimeMs: Long = 0,
)

@Serializable
data class DiagnosticsJournal(
    val present: Boolean = false,
    val corrupt: Boolean = false,
    val truncatedTail: Boolean = false,
    val lastSeq: Long = 0,
    val lines: List<DiagnosticsJournalLine> = emptyList(),
    val lineLimit: Int = 0,
)

@Serializable
data class DiagnosticsBaselinePartition(
    val name: String = "",
    val size: Long = 0,
    val sha256: String = "",
    val avbTailPreserved: Boolean = false,
)

@Serializable
data class DiagnosticsBaselineManifest(
    val id: String = "",
    val createdAt: Long = 0,
    val provenance: String = "",
    val clean: Boolean = false,
    val slot: String = "",
    val firmware: String = "",
    val kernelRelease: String = "",
    val partitions: List<DiagnosticsBaselinePartition> = emptyList(),
    val patchMarkersAbsent: Boolean = false,
    val avbVerificationDisabled: Boolean = false,
    val corrupt: Boolean = false,
)

@Serializable
data class DiagnosticsSnapshot(
    val schema: Int = SCHEMA,
    val generator: String = "MAPLESU_W16_DIAGNOSTICS",
    val generatorRevision: String = "W16",
    val createdAtEpochMs: Long = 0,
    val switchId: String = "",
    val device: DiagnosticsDevice = DiagnosticsDevice(),
    val recovery: DiagnosticsRecovery? = null,
    val switchHead: DiagnosticsSwitchHead? = null,
    val journal: DiagnosticsJournal = DiagnosticsJournal(),
    val baseline: List<DiagnosticsBaselineManifest> = emptyList(),
    val evidence: List<EvidenceLine> = emptyList(),
    val redactions: Int = 0,
    val notes: List<String> = emptyList(),
) {
    companion object {
        const val SCHEMA = 1
    }
}

data class DiagnosticsExportResult(
    val file: File,
    val sha256: String,
    val bytes: Long,
    val redactions: Int,
)

class DiagnosticsExporter(
    /** 控制面根：设备 `/data/adb/maplesu-workmode`，主机测试临时目录。 */
    private val root: File,
    /** 输出目录：设备 `filesDir/diagnostics`，主机测试临时目录。 */
    private val diagnosticsDir: File,
    private val clock: Clock = WallClock,
    private val generatorRevision: String = "W16",
    private val maxRetainedFiles: Int = 5,
    private val journalLineLimit: Int = 200,
) {

    fun export(switchId: String? = null, decision: RecoveryDecision? = null): DiagnosticsExportResult {
        return export(collect(switchId, decision))
    }

    /** Export the already-read Root snapshot; never reread protected files as the App uid. */
    fun export(snapshot: DiagnosticsSnapshot): DiagnosticsExportResult {
        val json = ControlJsonCodec.encode(snapshot)
        val directory = diagnosticsDir.apply { mkdirs() }
        MigrationGuard.require(directory.isDirectory, "DIAGNOSTICS_DIR_INVALID")
        val name = "diagnostics-${snapshot.switchId.takeIf { it.isNotBlank() } ?: "none"}-${clock.nowMillis()}.json"
        val file = File(directory, name)
        AtomicControlFile.writeJson(file, json)
        val bytes = file.length()
        val sha = Hashes.sha256(file.readBytes())
        prune(directory)
        return DiagnosticsExportResult(file, sha, bytes, snapshot.redactions)
    }

    fun collect(switchId: String? = null, decision: RecoveryDecision? = null): DiagnosticsSnapshot {
        var redactions = 0
        val notes = mutableListOf<String>()

        val head = readSwitchHead()
        val journal = readJournal(switchId)
        val baseline = readBaseline()
        val evidence = readEvidence { redactions += it }

        // 最后一道 fail-closed：serialized 形态不得含敏感 token/路径；命中即再脱敏一次。
        val recovery = decision?.let {
            DiagnosticsRecovery(
                action = safe(it.action.wire),
                reasons = it.reasons.map { reason -> safe(reason.code) },
                allowed = it.allowed.map { control -> safe(control.name) }.sorted(),
                blocked = it.blocked.map { control -> safe(control.name) }.sorted(),
                titleKey = safe(it.titleKey),
                detailKey = safe(it.detailKey),
                nextStepKey = safe(it.nextStepKey),
                requiresExternalImage = it.requiresExternalImage,
                diagnosticOnly = it.diagnosticOnly,
            )
        }
        val snapshot = DiagnosticsSnapshot(
            generatorRevision = generatorRevision,
            createdAtEpochMs = clock.nowMillis(),
            switchId = safe(switchId.orEmpty()),
            device = currentDevice(),
            recovery = recovery,
            switchHead = head,
            journal = journal,
            baseline = baseline,
            evidence = evidence,
            redactions = redactions,
            notes = notes,
        )
        // 设备事实在快照生成后不可再被外部注入；notes 供 UI 说明来源缺失。
        if (journal.present && journal.corrupt) notes += "JOURNAL_CORRUPT"
        if (!journal.present) notes += "JOURNAL_MISSING"
        if (baseline.isEmpty()) notes += "BASELINE_NONE"
        return if (notes.isEmpty()) snapshot else snapshot.copy(notes = notes)
    }

    // ------------------------------------------------------------------ 读取/脱敏

    private fun readSwitchHead(): DiagnosticsSwitchHead? {
        val file = File(root, "control/switch.json")
        val raw = AtomicControlFile.readUtf8(file) ?: return null
        val parsed = SwitchHeadViewCodec.parse(raw) ?: return null
        return DiagnosticsSwitchHead(
            switchId = safe(parsed.switchId),
            state = safe(parsed.state),
            from = safe(parsed.from),
            to = safe(parsed.to),
            pending = parsed.pending,
            attempts = parsed.attempts,
            errorCode = safe(parsed.errorCode),
            errorStage = safe(parsed.errorStage),
            bootIdAtBegin = safe(parsed.bootIdAtBegin),
        )
    }

    private fun readJournal(switchId: String?): DiagnosticsJournal {
        val id = switchId?.takeIf { it.isNotBlank() } ?: return DiagnosticsJournal()
        val file = File(root, "boot/work/$id/journal.jsonl")
        if (!file.isFile) return DiagnosticsJournal()
        val journal = FileSwitchJournal(file)
        val read = journal.read()
        return when (read) {
            is dev.maplesu.manager.workmode.switch.JournalRead.Ok -> DiagnosticsJournal(
                present = true,
                corrupt = false,
                truncatedTail = read.truncatedTail,
                lastSeq = read.lines.lastOrNull()?.seq ?: 0,
                lines = read.lines.takeLast(journalLineLimit).map { line -> line.toDiagnostics() },
                lineLimit = journalLineLimit,
            )
            is dev.maplesu.manager.workmode.switch.JournalRead.Corrupt -> DiagnosticsJournal(
                present = true,
                corrupt = true,
                lastSeq = read.lines.lastOrNull()?.seq ?: 0,
                lines = read.lines.takeLast(journalLineLimit).map { line -> line.toDiagnostics() },
                lineLimit = journalLineLimit,
            )
        }
    }

    private fun JournalLine.toDiagnostics(): DiagnosticsJournalLine = DiagnosticsJournalLine(
        seq = seq,
        stage = safe(stage),
        step = safe(step),
        partition = safe(partition),
        op = safe(op),
        expectedSha256 = hashOrEmpty(expectedSha256),
        observedSha256 = hashOrEmpty(observedSha256),
        code = safe(code),
        bootId = safe(bootId),
        atUptimeMs = atUptimeMs,
    )

    private fun readBaseline(): List<DiagnosticsBaselineManifest> {
        val baselineRoot = File(root, "boot/baseline")
        if (!baselineRoot.isDirectory) return emptyList()
        val dirs = baselineRoot.listFiles { file -> file.isDirectory }?.toList() ?: return emptyList()
        return dirs.sortedBy { it.name }.mapNotNull { dir ->
            val file = File(dir, "manifest.json")
            val raw = AtomicControlFile.readUtf8(file) ?: return@mapNotNull null
            val manifest = ControlJsonCodec.decodeOrNull(raw, BaselineManifest.serializer())
                ?: return@mapNotNull null
            manifest.toDiagnostics()
        }
    }

    private fun BaselineManifest.toDiagnostics(): DiagnosticsBaselineManifest = DiagnosticsBaselineManifest(
        id = safe(id),
        createdAt = createdAt,
        provenance = safe(provenance),
        clean = clean,
        slot = safe(slot),
        firmware = safe(firmware),
        kernelRelease = safe(kernelRelease),
        partitions = partitions.map { partition ->
            DiagnosticsBaselinePartition(
                name = safe(partition.name),
                size = partition.size,
                sha256 = hashOrEmpty(partition.sha256),
                avbTailPreserved = partition.avbTailPreserved,
            )
        },
        patchMarkersAbsent = patchMarkers.allAbsent,
        avbVerificationDisabled = avb.verificationDisabled,
    )

    private fun readEvidence(onRedaction: (Int) -> Unit): List<EvidenceLine> {
        val log = EvidenceLog(File(root, "control/evidence.jsonl"))
        val raw = runCatching { log.readAll(maxLines = 500) }.getOrElse { return emptyList() }
        val kept = mutableListOf<EvidenceLine>()
        var redactions = 0
        for (line in raw) {
            val scrubbed = EvidenceRedactor.scrub(line)
            if (scrubbed == null) {
                redactions++
                kept += EvidenceRedactor.redactionMarker(line, at = clock.nowMillis(), bootId = "")
                continue
            }
            kept += scrubbed.copy(
                stage = safe(scrubbed.stage),
                state = safe(scrubbed.state),
                rule = safe(scrubbed.rule),
                error = safe(scrubbed.error),
                evidence = scrubbed.evidence.map(::safe),
            )
        }
        if (redactions > 0) onRedaction(redactions)
        return kept
    }

    private fun currentDevice(): DiagnosticsDevice = DiagnosticsDevice(
        slot = safe(readSystemPropertyLike("slot")),
        firmware = safe(readSystemPropertyLike("firmware")),
        kernelRelease = safe(readSystemPropertyLike("kernel")),
        bootId = safe(readBootId()),
    )

    /** 主机测试可控：设备文件存在则读取，否则空串（UNKNOWN，不猜）。 */
    private fun readSystemPropertyLike(kind: String): String = when (kind) {
        "slot" -> AtomicControlFile.readUtf8(File(root, "control/device.slot"))?.trim().orEmpty()
        "firmware" -> AtomicControlFile.readUtf8(File(root, "control/device.firmware"))?.trim().orEmpty()
        "kernel" -> AtomicControlFile.readUtf8(File(root, "control/device.kernel"))?.trim().orEmpty()
        else -> ""
    }

    private fun readBootId(): String =
        AtomicControlFile.readUtf8(File(root, "control/boot_id"))?.trim()
            ?: runCatching { File("/proc/sys/kernel/random/boot_id").readText().trim() }.getOrDefault("")

    private fun prune(directory: File) {
        val files = directory.listFiles { file -> file.isFile && file.name.startsWith("diagnostics-") }
            ?.sortedByDescending { it.lastModified() } ?: return
        files.drop(maxRetainedFiles).forEach { stale -> runCatching { stale.delete() } }
    }

    private fun hashOrEmpty(value: String): String =
        if (value.matches(Regex("[0-9a-fA-F]{64}"))) value.lowercase() else safe(value)

    /** 单个字段脱敏：敏感 token → [REDACTED]；路径片段 → [PATH]。 */
    private fun safe(value: String): String {
        if (value.isBlank()) return value
        val lower = value.lowercase()
        if (EvidenceRedactor.SENSITIVE_TOKENS.any { lower.contains(it) }) return "[REDACTED]"
        var result = value
        EvidenceRedactor.FORBIDDEN_PATH_TOKENS.forEach { token ->
            if (result.contains(token)) result = result.replace(token, "[PATH]")
        }
        return result
    }
}

/** 诊断导出前置条件（目录/写入失败 → 明确失败，不静默产出半份文件）。 */
internal object MigrationGuard {
    fun require(condition: Boolean, code: String) {
        if (!condition) throw IllegalStateException(code)
    }
}
