package dev.maplesu.manager.workmode.control

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.ProcBootIdSource
import dev.maplesu.manager.workmode.detect.WallClock
import kotlinx.serialization.Serializable
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * `control/evidence.jsonl`：可观测、不泄密的追证行。
 *
 * 红线（发布红线 7）：禁止出现凭据、rootKey、stealth_code、APK 路径、包名明文、
 * signerSha256 明文（用 packageHash 代替）。
 */
@Serializable
data class EvidenceLine(
    val at: Long,
    val bootId: String,
    /** "DETECT" | "RESTORE" | "SWITCH" | "SUPERUSER_SYNC" | "MOVE" | "BASELINE"。 */
    val kind: String,
    val stage: String = "",
    val switchId: String = "",
    /** "OK" | "FAIL" | "PARTIAL" | "UNKNOWN"。 */
    val result: String,
    val state: String = "",
    val rule: String = "",
    /** ["S1:ok","S2:ok","L3:unknown"]。 */
    val evidence: List<String> = emptyList(),
    val uid: Int? = null,
    /** sha256(packageName) 前 16 hex，**不写包名**。 */
    val packageHash: String? = null,
    /** [{"restoredKeys":42}, …]。 */
    val counts: List<CountFact> = emptyList(),
    val error: String = "",
) {
    companion object {
        const val OK = "OK"
        const val FAIL = "FAIL"
        const val PARTIAL = "PARTIAL"
        const val UNKNOWN = "UNKNOWN"
        const val EVIDENCE_REDACTED = "EVIDENCE_REDACTED"
    }
}

@Serializable
data class CountFact(val name: String, val value: Long)

/** 脱敏器：命中敏感键名 → 丢整条并记 EVIDENCE_REDACTED（01 §4.6）。 */
object EvidenceRedactor {
    /** 命中即丢整条（大小写不敏感的子串匹配，"保守"优先）。 */
    val SENSITIVE_TOKENS: List<String> = listOf(
        "rootkey", "root_key", "stealth_code", "stealthcode", "credential", "token",
        "password", "secret", "signersha256",
    )

    /** 诊断不得落盘原始路径。 */
    val FORBIDDEN_PATH_TOKENS: List<String> = listOf("/data/app/", ".apk", "/data/user/")

    fun scrub(line: EvidenceLine): EvidenceLine? {
        val encoded = runCatching { ControlJsonCodec.encode(line) }.getOrNull() ?: return null
        val lower = encoded.lowercase()
        if (SENSITIVE_TOKENS.any { lower.contains(it) }) return null
        if (FORBIDDEN_PATH_TOKENS.any { encoded.contains(it) }) return null
        return line
    }

    fun hashPackageName(packageName: String): String = Hashes.shortSha256(packageName, 16)

    fun redactionMarker(original: EvidenceLine, at: Long, bootId: String): EvidenceLine =
        EvidenceLine(
            at = at,
            bootId = bootId,
            kind = original.kind,
            stage = original.stage,
            switchId = original.switchId,
            result = EvidenceLine.UNKNOWN,
            state = original.state,
            rule = original.rule,
            error = EvidenceLine.EVIDENCE_REDACTED,
        )
}

/**
 * evidence.jsonl 追加 + 轮转（单文件上限 1 MiB，超过时轮转 `evidence.jsonl.1`，保留 1 代）。
 */
class EvidenceLog(
    private val file: java.io.File,
    private val clock: Clock = WallClock,
    private val bootIdSource: BootIdSource = ProcBootIdSource,
    private val maxBytes: Long = 1L shl 20,
) {
    /** @return true = 原始行已落盘；false = 被脱敏（落盘的是 EVIDENCE_REDACTED 标记行）。 */
    fun append(line: EvidenceLine): Boolean {
        val scrubbed = EvidenceRedactor.scrub(line)
        val output = scrubbed ?: EvidenceRedactor.redactionMarker(
            line,
            at = clock.nowMillis(),
            bootId = if (line.bootId.isBlank()) bootIdSource.read() else line.bootId,
        )
        val encoded = ControlJsonCodec.encode(output)
        rotateIfNeeded(encoded.toByteArray(Charsets.UTF_8).size.toLong())
        AtomicControlFile.appendLine(file, encoded)
        return scrubbed != null
    }

    fun readAll(maxLines: Int = 10_000): List<EvidenceLine> {
        if (!file.isFile) return emptyList()
        return file.readLines(Charsets.UTF_8)
            .asSequence()
            .filter { it.isNotBlank() }
            .take(maxLines)
            .mapNotNull { ControlJsonCodec.decodeOrNull<EvidenceLine>(it) }
            .toList()
    }

    fun rotatedFile(): java.io.File = java.io.File(file.parentFile, "${file.name}.1")

    private fun rotateIfNeeded(nextLineBytes: Long) {
        if (!file.isFile) return
        val current = file.length()
        if (current == 0L || current + nextLineBytes <= maxBytes) return
        val parent = file.parentFile ?: return
        if (!parent.isDirectory) return
        val rotated = rotatedFile()
        runCatching {
            Files.move(file.toPath(), rotated.toPath(), StandardCopyOption.REPLACE_EXISTING)
        }.onFailure {
            // 轮转失败不得阻断证据追加，也不得丢证据：单文件继续增长，下次再尝试轮转。
        }
    }
}
