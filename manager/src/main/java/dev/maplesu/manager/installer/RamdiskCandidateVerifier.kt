package dev.maplesu.manager.installer

import dev.maplesu.image.RamdiskInspector
import dev.maplesu.installer.BlockDeviceTransaction
import java.io.File
import java.io.IOException
import java.security.MessageDigest

/**
 * 候选结构校验的生产实现（02 §9.5 两层判定的第二层）：不信任 producer 自述，
 * 用 image-core `RamdiskInspector` 从候选字节重新解析。
 *
 * 断言链：满长（== 目标分区长度）→ 目标分区在 Normal 白名单内（`init_boot` / `boot`，
 * 用户口径 2026-11-01）→ 非畸形容器 → KSU LKM 形态（init/init.real/kernelsu.ko/ksu_config）
 * →（默认）`maplesu_id` 归属标记 → **kernel 段未被改动**（[KsuKernelPreservation]）→
 * 整文件 SHA-256 与 producer 一致。
 * 畸形 / stock / foreign / 未归属 / 改了内核的候选一律拒绝，绝不进入提交。
 */
class RamdiskCandidateVerifier : KsuCandidateVerifierPort {
    override fun verify(artifact: KsuProducedArtifact, expectation: KsuCandidateExpectation): KsuVerifyOutcome {
        if (!KsuInstallProducerDefaults.isTarget(expectation.partition)) {
            return KsuVerifyOutcome.Rejected(
                "PRODUCE_PARTITION_UNSUPPORTED",
                "Normal only accepts ${KsuInstallProducerDefaults.TARGETS.sorted()}, " +
                    "got '${expectation.partition}'",
            )
        }
        if (expectation.partitionSize <= 0 ||
            expectation.partitionSize > BlockDeviceTransaction.MAX_BYTES
        ) {
            return KsuVerifyOutcome.Rejected(
                "INSTALLER_DEVICE_SIZE_INVALID", "partition size ${expectation.partitionSize}",
            )
        }
        if (!artifact.candidate.isFile) {
            return KsuVerifyOutcome.Rejected(
                "PRODUCE_OUTPUT_MISSING", "candidate missing: ${artifact.candidate.absolutePath}",
            )
        }
        if (artifact.candidate.length() != expectation.partitionSize) {
            return KsuVerifyOutcome.Rejected(
                "PRODUCE_OUTPUT_SIZE_INVALID",
                "candidate is not full length: ${artifact.candidate.length()} != ${expectation.partitionSize}",
            )
        }
        val report = try {
            RamdiskInspector.inspect(artifact.candidate)
        } catch (error: IOException) {
            return KsuVerifyOutcome.Rejected("PRODUCE_CANDIDATE_MALFORMED", error.message.orEmpty())
        } catch (error: RuntimeException) {
            return KsuVerifyOutcome.Rejected("PRODUCE_CANDIDATE_MALFORMED", error.message.orEmpty())
        }
        if (report.malformed) {
            val problemCodes = report.problems.joinToString(",") { it.code }
            return KsuVerifyOutcome.Rejected(
                "PRODUCE_CANDIDATE_MALFORMED",
                "${report.errorCode} [$problemCodes]",
            )
        }
        val form = report.requireKsuLkmForm()
        if (!form.ok) {
            return KsuVerifyOutcome.Rejected(
                "PRODUCE_CANDIDATE_FORM_${form.code}",
                "${form.detail} ${form.violations.joinToString()}",
            )
        }
        val owned = report.hasMaplesuId
        if (expectation.requireOwned) {
            val ownedVerdict = report.requireOwnedKsuLkmForm()
            if (!ownedVerdict.ok) {
                // 归属标记缺失是"候选不由本分支产出"的稳定拒绝码（fail-closed）。
                val code = if (ownedVerdict.code == "MISSING_MAPLESU_ID") {
                    "PRODUCE_CANDIDATE_UNOWNED"
                } else {
                    "PRODUCE_CANDIDATE_FORM_${ownedVerdict.code}"
                }
                return KsuVerifyOutcome.Rejected(code, ownedVerdict.detail)
            }
        }
        // LKM 补丁只允许改 ramdisk：boot 目标下 kernel 段必须逐字节未变（init_boot 下不许有）。
        val preservation = KsuKernelPreservation.check(
            expectation.partition, artifact.source, artifact.candidate,
        )
        if (preservation is KsuKernelPreservation.Verdict.Rejected) {
            return KsuVerifyOutcome.Rejected(preservation.code, preservation.detail)
        }
        val actualSha = sha256(artifact.candidate)
        if (!actualSha.equals(artifact.sha256, ignoreCase = true)) {
            return KsuVerifyOutcome.Rejected(
                "PRODUCE_CANDIDATE_CHANGED",
                "candidate sha256 changed: $actualSha != ${artifact.sha256}",
            )
        }
        return KsuVerifyOutcome.Ok(
            tailSha256 = tailSha256(artifact.candidate, expectation.partitionSize),
            form = report.form().name,
            owned = owned,
            kernelsuKoSha256 = report.entry("kernelsu.ko")?.sha256,
        )
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return hex(digest.digest())
    }

    private fun tailSha256(file: File, size: Long): String {
        val window = minOf(size, dev.maplesu.installer.WritablePartition.TAIL_PROBE_BYTES.toLong())
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            var skip = size - window
            while (skip > 0) {
                val stepped = input.skip(skip)
                if (stepped <= 0) {
                    if (input.read() < 0) throw IOException("PRODUCE_CANDIDATE_TRUNCATED")
                    skip -= 1
                } else {
                    skip -= stepped
                }
            }
            var remaining = window
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (remaining > 0) {
                val read = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
                if (read < 0) throw IOException("PRODUCE_CANDIDATE_TRUNCATED")
                digest.update(buffer, 0, read)
                remaining -= read
            }
        }
        return hex(digest.digest())
    }

    private fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}
