// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.patching

import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.BootImageRebuilder
import dev.maplesu.image.BootImageRoundTrip
import dev.maplesu.image.KernelCompression
import dev.maplesu.image.RamdiskInspector
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.Locale

/**
 * W09: Lite (mode A) candidate producer.
 *
 * Produces a **full-length** boot candidate from a read-only, full-length baseline image by
 * reusing the existing patch/rebuild chain, then re-verifies the candidate from its own bytes:
 *
 * - container: `BootImageInspector` layout unchanged (header version, kernel/ramdisk sizes);
 * - kernel: patched SHA-256 identity, unchanged raw length, unchanged release, ARM64 magic;
 * - ramdisk: byte-identical to baseline and structurally stock (no KSU residue, not malformed)
 *   via `image-core` `RamdiskInspector` (02-switch-contract §9.5, 03-ksu-contract §2.2.5);
 * - length/tail: candidate size == baseline size (partition length), zero trailing material or
 *   a structurally valid preserved AVB footer (04 §4.5 tail contract);
 * - idempotent: a second call for the same baseline/work directory re-validates and returns the
 *   same artifact without invoking the patch engine again.
 *
 * The producer never opens a block device and never writes outside [CandidateRequest.workDirectory].
 * Failure is reported as a structured [CandidateCodes] value, never as an exception.
 */
interface CandidateProducer {
    fun produce(request: CandidateRequest): CandidateOutcome
}

/** Mode identifiers are plain strings so this package stays decoupled from workmode enums. */
object CandidateMode {
    const val LITE = "LITE"
    const val KSU = "KSU"
}

/**
 * @param baseline read-only full-length baseline boot image (S2 `base-boot.img` copy).
 * @param workDirectory caller-owned private directory for this candidate. A fresh directory is
 *   created; an existing directory is accepted only when it already holds a valid artifact for
 *   the same baseline (idempotency) — anything else is `CANDIDATE_WORK_DIRECTORY_CONFLICT`.
 * @param sourceMode mode the baseline comes from (`"KSU"` when switching B -> A).
 * @param targetMode mode this candidate boots into; must be `"LITE"` for this producer.
 * @param baselineSha256 optional pin from the S2 snapshot; when present it must match the file.
 * @param expectedSize optional partition length; defaults to (and must equal) the baseline length.
 */
data class CandidateRequest(
    val baseline: File,
    val workDirectory: File,
    val sourceMode: String,
    val targetMode: String = CandidateMode.LITE,
    val baselineSha256: String? = null,
    val expectedSize: Long? = null,
)

/** The single product of W09: a candidate image plus its independently re-derived identity. */
data class CandidateArtifact(
    val image: File,
    val evidence: File,
    val sha256: String,
    val size: Long,
    val sourceMode: String,
    val targetMode: String,
    val baselineSha256: String,
    val baselineSize: Long,
    val headerVersion: Int,
    val compression: String,
    val kernelSize: Long,
    val kernelRelease: String,
    val sourceKernelSha256: String,
    val patchedKernelSha256: String,
    val ramdiskSize: Long,
    val ramdiskSha256: String,
    val tailSha256: String,
    val tailPaddingBytes: Long,
)

sealed class CandidateOutcome {
    data class Produced(val artifact: CandidateArtifact) : CandidateOutcome()
    data class Rejected(val code: String, val detail: String = "") : CandidateOutcome()
}

/** Stable machine codes; the caller maps them to switch-journal / UI messages. */
object CandidateCodes {
    const val CANCELLED = "PRODUCE_CANCELLED"
    const val CANDIDATE_REQUEST_INVALID = "PRODUCE_REQUEST_INVALID"
    const val BASELINE_MISSING = "PRODUCE_BASELINE_MISSING"
    const val BASELINE_NOT_FILE = "PRODUCE_BASELINE_NOT_FILE"
    const val BASELINE_SIZE_LIMIT = "PRODUCE_BASELINE_SIZE_LIMIT"
    const val BASELINE_SIZE_MISMATCH = "PRODUCE_BASELINE_SIZE_MISMATCH"
    const val BASELINE_INVALID = "PRODUCE_BASELINE_INVALID"
    const val BASELINE_SHA_MISMATCH = "PRODUCE_BASELINE_SHA_MISMATCH"
    const val BASELINE_MUTATED = "PRODUCE_BASELINE_MUTATED"
    const val BASELINE_KERNEL_MISSING = "PRODUCE_BASELINE_KERNEL_MISSING"
    const val BASELINE_KERNEL_INVALID = "PRODUCE_BASELINE_KERNEL_INVALID"
    const val BASELINE_KERNEL_COMPRESSION_UNSUPPORTED = "PRODUCE_BASELINE_KERNEL_COMPRESSION_UNSUPPORTED"
    const val BASELINE_KERNEL_DECODE_FAILED = "PRODUCE_BASELINE_KERNEL_DECODE_FAILED"
    const val BASELINE_RAMDISK_MALFORMED = "PRODUCE_BASELINE_RAMDISK_MALFORMED"
    const val BASELINE_RAMDISK_SIZE_LIMIT = "PRODUCE_BASELINE_RAMDISK_SIZE_LIMIT"
    const val BASELINE_UNCLEAN = "PRODUCE_BASELINE_UNCLEAN"
    const val BASELINE_TAIL_INVALID = "PRODUCE_BASELINE_TAIL_INVALID"
    const val WORK_DIRECTORY_CONFLICT = "PRODUCE_WORK_DIRECTORY_CONFLICT"
    const val WORK_DIRECTORY_FAILED = "PRODUCE_WORK_DIRECTORY_FAILED"
    const val PATCH_ENGINE_FAILED = "PRODUCE_PATCH_ENGINE_FAILED"
    const val CANDIDATE_MISSING = "PRODUCE_CANDIDATE_MISSING"
    const val CANDIDATE_SIZE_CONFLICT = "PRODUCE_CANDIDATE_SIZE_CONFLICT"
    const val CANDIDATE_NOT_FULL_LENGTH = "PRODUCE_CANDIDATE_NOT_FULL_LENGTH"
    const val CANDIDATE_INVALID = "PRODUCE_CANDIDATE_INVALID"
    const val CANDIDATE_HEADER_CHANGED = "PRODUCE_CANDIDATE_HEADER_CHANGED"
    const val CANDIDATE_LAYOUT_CHANGED = "PRODUCE_CANDIDATE_LAYOUT_CHANGED"
    const val CANDIDATE_KERNEL_SIZE_CHANGED = "PRODUCE_CANDIDATE_KERNEL_SIZE_CHANGED"
    const val CANDIDATE_KERNEL_SHA_MISMATCH = "PRODUCE_CANDIDATE_KERNEL_SHA_MISMATCH"
    const val CANDIDATE_KERNEL_UNCHANGED = "PRODUCE_CANDIDATE_KERNEL_UNCHANGED"
    const val CANDIDATE_KERNEL_RELEASE_CHANGED = "PRODUCE_CANDIDATE_KERNEL_RELEASE_CHANGED"
    const val CANDIDATE_KERNEL_INVALID = "PRODUCE_CANDIDATE_KERNEL_INVALID"
    const val CANDIDATE_KERNEL_DECODE_FAILED = "PRODUCE_CANDIDATE_KERNEL_DECODE_FAILED"
    const val CANDIDATE_RAMDISK_CHANGED = "PRODUCE_CANDIDATE_RAMDISK_CHANGED"
    const val CANDIDATE_RAMDISK_MALFORMED = "PRODUCE_CANDIDATE_RAMDISK_MALFORMED"
    const val CANDIDATE_RAMDISK_KSU_RESIDUE = "PRODUCE_CANDIDATE_RAMDISK_KSU_RESIDUE"
    const val CANDIDATE_TAIL_CONTRACT = "PRODUCE_CANDIDATE_TAIL_CONTRACT"
    const val CANDIDATE_ROUNDTRIP_FAILED = "PRODUCE_CANDIDATE_ROUNDTRIP_FAILED"
    const val EVIDENCE_WRITE_FAILED = "PRODUCE_EVIDENCE_WRITE_FAILED"
}

/**
 * The privileged patch step, kept behind a functional interface so W09 stays host-testable and
 * decoupled from Android. Production wiring delegates to [LiteBootPatcher] via
 * [LiteBootPatcherEngine]; tests inject a synthetic engine that reuses `BootImageRebuilder`.
 */
fun interface LitePatchEngine {
    /**
     * Reads only [baseline]; writes only inside [engineDirectory]. Returns the rebuilt candidate
     * image and the raw kernel identity it claims. Must not write partitions.
     */
    fun produce(baseline: File, engineDirectory: File): EngineCandidate
}

data class EngineCandidate(
    val image: File,
    val patchedKernelSha256: String,
    val kernelRelease: String,
)

/**
 * Production adapter for the existing Lite patch chain. `LiteBootPatcher.patch` already runs the
 * native patcher, kernel codec and `BootImageRebuilder`; the producer re-validates its output
 * instead of trusting the accompanying report.
 */
class LiteBootPatcherEngine(
    private val patcher: LiteBootPatcher,
    private val credential: ByteArray,
) : LitePatchEngine {
    override fun produce(baseline: File, engineDirectory: File): EngineCandidate {
        val candidate = patcher.patch(baseline, engineDirectory, credential)
        return EngineCandidate(candidate.image, candidate.patchedKernelSha256, candidate.kernelRelease)
    }
}

/** W09 producer. See the file header for the full verification contract. */
class LiteCandidateProducer(private val engine: LitePatchEngine) : CandidateProducer {
    override fun produce(request: CandidateRequest): CandidateOutcome {
        var completed = false
        var workDirectoryCreated = false
        return try {
            cancelled()
            val baseline = inspectBaseline(request)
            restoreCached(request, baseline)?.let {
                completed = true
                return CandidateOutcome.Produced(it)
            }

            val work = request.workDirectory
            workDirectoryCreated = ensureWorkDirectory(work)
            val engineDirectory = File(work, ENGINE_DIRECTORY)
            val engineCandidate = runEngine(request.baseline, engineDirectory)
            val image = File(work, IMAGE_NAME)
            try {
                cancelled()
                verifyBaselineUnchanged(request.baseline, baseline)
                materialize(engineCandidate, image, baseline, request)
            } finally {
                engineDirectory.deleteRecursively()
            }
            cancelled()
            val evidence = File(work, EVIDENCE_NAME)
            val meta = File(work, META_NAME)
            val artifact = validateCandidate(
                request = request,
                baseline = baseline,
                image = image,
                evidence = evidence,
                expectedPatchedKernelSha256 = engineCandidate.patchedKernelSha256,
                expectedKernelRelease = engineCandidate.kernelRelease,
            )
            writeEvidence(artifact, meta)
            completed = true
            CandidateOutcome.Produced(artifact)
        } catch (rejection: Rejection) {
            CandidateOutcome.Rejected(rejection.code, rejection.detail)
        } catch (failure: IOException) {
            CandidateOutcome.Rejected(CandidateCodes.EVIDENCE_WRITE_FAILED, failure.message.orEmpty())
        } catch (failure: RuntimeException) {
            CandidateOutcome.Rejected(CandidateCodes.PATCH_ENGINE_FAILED, failure.javaClass.simpleName)
        } finally {
            if (!completed) cleanPartialProducts(request.workDirectory, workDirectoryCreated)
        }
    }

    // ------------------------------------------------------------------ baseline

    private fun inspectBaseline(request: CandidateRequest): Baseline {
        cancelled()
        if (!request.targetMode.equals(CandidateMode.LITE, ignoreCase = false)) {
            throw Rejection(CandidateCodes.CANDIDATE_REQUEST_INVALID, "targetMode must be LITE")
        }
        if (request.sourceMode.isBlank()) {
            throw Rejection(CandidateCodes.CANDIDATE_REQUEST_INVALID, "sourceMode is blank")
        }
        val baseline = request.baseline
        if (!baseline.exists()) throw Rejection(CandidateCodes.BASELINE_MISSING)
        if (!Files.isRegularFile(baseline.toPath(), LinkOption.NOFOLLOW_LINKS)) {
            throw Rejection(CandidateCodes.BASELINE_NOT_FILE)
        }
        val length = baseline.length()
        if (length <= 0) throw Rejection(CandidateCodes.BASELINE_MISSING)
        if (length > MAX_IMAGE_BYTES) throw Rejection(CandidateCodes.BASELINE_SIZE_LIMIT, "size=$length")
        val expectedSize = request.expectedSize ?: length
        if (expectedSize != length) {
            throw Rejection(CandidateCodes.BASELINE_SIZE_MISMATCH,
                "expectedSize=$expectedSize baselineSize=$length")
        }
        val sha256 = sha256(baseline)
        request.baselineSha256?.let { pinned ->
            if (pinned != sha256) throw Rejection(CandidateCodes.BASELINE_SHA_MISMATCH)
        }
        val report = try {
            BootImageInspector.inspect(baseline)
        } catch (invalid: BootImageInspector.InvalidImageException) {
            throw Rejection(CandidateCodes.BASELINE_INVALID, invalid.code)
        }
        if (report.kernelSize <= 0) throw Rejection(CandidateCodes.BASELINE_KERNEL_MISSING)
        if (report.ramdiskSize > MAX_RAMDISK_BYTES) {
            throw Rejection(CandidateCodes.BASELINE_RAMDISK_SIZE_LIMIT, "size=${report.ramdiskSize}")
        }
        val kernel = decodeKernel(baseline, report,
            decodeFailure = CandidateCodes.BASELINE_KERNEL_DECODE_FAILED,
            unsupportedFailure = CandidateCodes.BASELINE_KERNEL_COMPRESSION_UNSUPPORTED,
            invalidFailure = CandidateCodes.BASELINE_KERNEL_INVALID)
        val ramdisk = inspectRamdisk(baseline, report,
            malformedFailure = CandidateCodes.BASELINE_RAMDISK_MALFORMED,
            residueFailure = CandidateCodes.BASELINE_UNCLEAN)
        val avbFooter = readAvbFooter(baseline)
        val avbPresent: Boolean
        if (avbFooter != null) {
            if (!validAvbFooter(avbFooter, length)) {
                throw Rejection(CandidateCodes.BASELINE_TAIL_INVALID, "AVB footer is not valid")
            }
            avbPresent = true
        } else {
            if (!isAllZero(baseline, payloadEnd(report), length)) {
                throw Rejection(CandidateCodes.BASELINE_TAIL_INVALID, "non-zero baseline tail")
            }
            avbPresent = false
        }
        return Baseline(report, sha256, length, kernel, ramdisk, avbFooterPresent = avbPresent,
            expectedSize = expectedSize)
    }

    // ------------------------------------------------------------------ engine

    private fun runEngine(baseline: File, engineDirectory: File): EngineCandidate {
        if (engineDirectory.exists()) throw Rejection(CandidateCodes.WORK_DIRECTORY_CONFLICT,
            "engine directory already exists")
        val candidate = try {
            engine.produce(baseline, engineDirectory)
        } catch (rejection: Rejection) {
            throw rejection
        } catch (failure: IOException) {
            throw Rejection(CandidateCodes.PATCH_ENGINE_FAILED, failure.message.orEmpty())
        } catch (failure: RuntimeException) {
            throw Rejection(CandidateCodes.PATCH_ENGINE_FAILED, failure.javaClass.simpleName)
        }
        if (!candidate.image.exists()) throw Rejection(CandidateCodes.CANDIDATE_MISSING)
        if (!Files.isRegularFile(candidate.image.toPath(), LinkOption.NOFOLLOW_LINKS)) {
            throw Rejection(CandidateCodes.CANDIDATE_MISSING, "candidate is not a regular file")
        }
        return candidate
    }

    private fun verifyBaselineUnchanged(baseline: File, expected: Baseline) {
        if (!baseline.isFile || baseline.length() != expected.size || sha256(baseline) != expected.sha256) {
            throw Rejection(CandidateCodes.BASELINE_MUTATED)
        }
    }

    /**
     * Copies the engine output into the final candidate file, restoring the full partition length
     * with zero padding only when the baseline tail beyond the rebuilt payload is itself zero.
     * Padding the *file* is not "short image zero fill" (§4.3.1 #8 rejects short images); it is the
     * deterministic re-materialisation of the baseline's zero tail so the candidate is full length.
     */
    private fun materialize(engineCandidate: EngineCandidate, image: File, baseline: Baseline,
                            request: CandidateRequest) {
        val engineLength = engineCandidate.image.length()
        val expectedSize = baseline.expectedSize
        if (engineLength > expectedSize) {
            throw Rejection(CandidateCodes.CANDIDATE_SIZE_CONFLICT,
                "candidate=$engineLength expected=$expectedSize")
        }
        if (engineLength == expectedSize) {
            copyAtomically(engineCandidate.image, image)
            return
        }
        // A shorter output is acceptable only when it is a structurally complete image whose
        // missing suffix is zero padding. A truncated component (or a non-zero dropped tail)
        // must never be silently padded back into a "full length" candidate.
        val structurallyComplete = try {
            BootImageInspector.inspect(engineCandidate.image)
            true
        } catch (failure: IOException) {
            false
        }
        if (!structurallyComplete) {
            throw Rejection(CandidateCodes.CANDIDATE_NOT_FULL_LENGTH,
                "engine output is a truncated image: candidate=$engineLength expected=$expectedSize")
        }
        if (!isAllZero(request.baseline, engineLength, expectedSize)) {
            throw Rejection(CandidateCodes.CANDIDATE_TAIL_CONTRACT,
                "baseline tail is not zero padding; refusing to fabricate full length")
        }
        val temporary = File(image.parentFile, "$IMAGE_NAME.tmp")
        try {
            engineCandidate.image.inputStream().use { input ->
                java.io.FileOutputStream(temporary).use { output ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        cancelled()
                        val count = input.read(buffer)
                        if (count < 0) break
                        output.write(buffer, 0, count)
                    }
                    val zero = ByteArray(64 * 1024)
                    var remaining = expectedSize - engineLength
                    while (remaining > 0) {
                        val count = minOf(remaining, zero.size.toLong()).toInt()
                        output.write(zero, 0, count)
                        remaining -= count
                    }
                    output.flush()
                    output.fd.sync()
                }
            }
            if (temporary.length() != expectedSize) {
                throw Rejection(CandidateCodes.CANDIDATE_NOT_FULL_LENGTH,
                    "materialized=${temporary.length()} expected=$expectedSize")
            }
            Files.move(temporary.toPath(), image.toPath(), StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE)
        } finally {
            Files.deleteIfExists(temporary.toPath())
        }
    }

    // ------------------------------------------------------------------ verification

    private fun validateCandidate(request: CandidateRequest, baseline: Baseline, image: File,
                                  evidence: File, expectedPatchedKernelSha256: String,
                                  expectedKernelRelease: String): CandidateArtifact {
        val size = image.length()
        val expectedSize = baseline.expectedSize
        if (size != expectedSize) {
            val code = if (size > expectedSize) CandidateCodes.CANDIDATE_SIZE_CONFLICT
            else CandidateCodes.CANDIDATE_NOT_FULL_LENGTH
            throw Rejection(code, "candidateSize=$size expected=$expectedSize")
        }
        val candidateSha256 = sha256(image)
        val report = try {
            BootImageInspector.inspect(image)
        } catch (invalid: BootImageInspector.InvalidImageException) {
            throw Rejection(CandidateCodes.CANDIDATE_INVALID, invalid.code)
        }
        if (report.headerVersion != baseline.report.headerVersion) {
            throw Rejection(CandidateCodes.CANDIDATE_HEADER_CHANGED,
                "header=${report.headerVersion} baseline=${baseline.report.headerVersion}")
        }
        // The compressed kernel size may legitimately change when the patched raw kernel is
        // re-encoded; the invariant is the decoded raw length, checked below.
        if (report.ramdiskSize != baseline.report.ramdiskSize) {
            throw Rejection(CandidateCodes.CANDIDATE_LAYOUT_CHANGED,
                "ramdiskSize=${report.ramdiskSize} baseline=${baseline.report.ramdiskSize}")
        }
        if (!report.compression.equals(baseline.report.compression, ignoreCase = false)) {
            throw Rejection(CandidateCodes.CANDIDATE_LAYOUT_CHANGED,
                "compression=${report.compression} baseline=${baseline.report.compression}")
        }

        // Kernel patch fingerprint: the candidate must be a different, same-length, same-release kernel.
        val kernel = decodeKernel(image, report,
            decodeFailure = CandidateCodes.CANDIDATE_KERNEL_DECODE_FAILED,
            unsupportedFailure = CandidateCodes.CANDIDATE_LAYOUT_CHANGED,
            invalidFailure = CandidateCodes.CANDIDATE_KERNEL_INVALID)
        if (kernel.size != baseline.kernel.size) {
            throw Rejection(CandidateCodes.CANDIDATE_KERNEL_SIZE_CHANGED,
                "rawKernel=${kernel.size} baseline=${baseline.kernel.size}")
        }
        if (kernel.sha256 != expectedPatchedKernelSha256) {
            throw Rejection(CandidateCodes.CANDIDATE_KERNEL_SHA_MISMATCH)
        }
        if (kernel.sha256 == baseline.kernel.sha256) {
            throw Rejection(CandidateCodes.CANDIDATE_KERNEL_UNCHANGED)
        }
        if (kernel.release != baseline.kernel.release) {
            throw Rejection(CandidateCodes.CANDIDATE_KERNEL_RELEASE_CHANGED,
                "candidate=${kernel.release} baseline=${baseline.kernel.release}")
        }
        if (kernel.release != expectedKernelRelease) {
            throw Rejection(CandidateCodes.CANDIDATE_KERNEL_RELEASE_CHANGED,
                "reported=$expectedKernelRelease decoded=${kernel.release}")
        }

        // Independent codec/container round trip (02-switch-contract §9.5 for the LITE candidate).
        val verifyDirectory = File(image.parentFile, VERIFY_DIRECTORY)
        try {
            Files.createDirectories(verifyDirectory.toPath())
            val roundTrip = try {
                BootImageRoundTrip.verify(image, verifyDirectory)
            } catch (failure: IOException) {
                throw Rejection(CandidateCodes.CANDIDATE_ROUNDTRIP_FAILED, failure.message.orEmpty())
            }
            if (roundTrip.decodedKernelSize != baseline.kernel.size ||
                roundTrip.decodedKernelSha256 != kernel.sha256 ||
                roundTrip.kernelRelease != kernel.release) {
                throw Rejection(CandidateCodes.CANDIDATE_ROUNDTRIP_FAILED,
                    "decoded=${roundTrip.decodedKernelSize} release=${roundTrip.kernelRelease}")
            }
        } finally {
            verifyDirectory.deleteRecursively()
        }

        // Ramdisk: byte-identical to baseline, structurally sound and stock (no KSU residue).
        val ramdisk = inspectRamdisk(image, report,
            malformedFailure = CandidateCodes.CANDIDATE_RAMDISK_MALFORMED,
            residueFailure = CandidateCodes.CANDIDATE_RAMDISK_KSU_RESIDUE)
        if (ramdisk.sha256 != baseline.ramdisk.sha256 || ramdisk.size != baseline.ramdisk.size) {
            throw Rejection(CandidateCodes.CANDIDATE_RAMDISK_CHANGED)
        }

        // Full-length tail contract: zero padding, or a preserved/relocated AVB footer.
        val tail = validateCandidateTail(image, report, baseline)
        val artifact = CandidateArtifact(
            image = image,
            evidence = evidence,
            sha256 = candidateSha256,
            size = size,
            sourceMode = request.sourceMode,
            targetMode = request.targetMode,
            baselineSha256 = baseline.sha256,
            baselineSize = baseline.size,
            headerVersion = report.headerVersion,
            compression = report.compression,
            kernelSize = report.kernelSize,
            kernelRelease = kernel.release,
            sourceKernelSha256 = baseline.kernel.sha256,
            patchedKernelSha256 = kernel.sha256,
            ramdiskSize = ramdisk.size,
            ramdiskSha256 = ramdisk.sha256,
            tailSha256 = tail.sha256,
            tailPaddingBytes = tail.paddingBytes,
        )
        return artifact
    }

    private data class TailEvidence(val sha256: String, val paddingBytes: Long)

    private fun validateCandidateTail(image: File, report: BootImageInspector.Report,
                                      baseline: Baseline): TailEvidence {
        val size = image.length()
        val payloadEnd = payloadEnd(report)
        val footer = readAvbFooter(image)
        if (footer != null) {
            if (!baseline.avbFooterPresent) {
                throw Rejection(CandidateCodes.CANDIDATE_TAIL_CONTRACT, "candidate gained an AVB footer")
            }
            if (!validAvbFooter(footer, size)) {
                throw Rejection(CandidateCodes.CANDIDATE_TAIL_CONTRACT, "AVB footer is not valid")
            }
            if (footer.originalImageSize < payloadEnd || footer.originalImageSize > footer.vbmetaOffset) {
                throw Rejection(CandidateCodes.CANDIDATE_TAIL_CONTRACT, "AVB original_image_size mismatch")
            }
            if (!isAllZero(image, payloadEnd, footer.vbmetaOffset)) {
                throw Rejection(CandidateCodes.CANDIDATE_TAIL_CONTRACT, "non-zero bytes before AVB metadata")
            }
            if (!isAllZero(image, footer.vbmetaOffset + footer.vbmetaSize, size - AVB_FOOTER_BYTES)) {
                throw Rejection(CandidateCodes.CANDIDATE_TAIL_CONTRACT, "non-zero bytes after AVB metadata")
            }
            val vbmetaMagic = readRange(image, footer.vbmetaOffset, 4)
            if (vbmetaMagic.size != 4 || vbmetaMagic[0] != 'A'.code.toByte() ||
                vbmetaMagic[1] != 'V'.code.toByte() || vbmetaMagic[2] != 'B'.code.toByte() ||
                vbmetaMagic[3] != '0'.code.toByte()) {
                throw Rejection(CandidateCodes.CANDIDATE_TAIL_CONTRACT, "AVB metadata magic missing")
            }
        } else {
            if (baseline.avbFooterPresent) {
                throw Rejection(CandidateCodes.CANDIDATE_TAIL_CONTRACT, "baseline AVB footer was dropped")
            }
            if (!isAllZero(image, payloadEnd, size)) {
                throw Rejection(CandidateCodes.CANDIDATE_TAIL_CONTRACT, "non-zero candidate tail")
            }
        }
        val tailStart = maxOf(0L, size - TAIL_PROBE_BYTES)
        return TailEvidence(sha256(readRange(image, tailStart, size - tailStart)), size - payloadEnd)
    }

    // ------------------------------------------------------------------ idempotency

    private fun restoreCached(request: CandidateRequest, baseline: Baseline): CandidateArtifact? {
        val work = request.workDirectory
        if (!work.exists()) return null
        if (!work.isDirectory) throw Rejection(CandidateCodes.WORK_DIRECTORY_CONFLICT,
            "work directory is not a directory")
        val children = work.listFiles()
        if (children == null || children.isEmpty()) return null
        val image = File(work, IMAGE_NAME)
        val metaFile = File(work, META_NAME)
        val evidence = File(work, EVIDENCE_NAME)
        if (!image.isFile || !metaFile.isFile || !evidence.isFile || children.size != 3) {
            throw Rejection(CandidateCodes.WORK_DIRECTORY_CONFLICT)
        }
        val meta = try {
            parseMeta(metaFile.readText(Charsets.UTF_8))
        } catch (failure: IOException) {
            throw Rejection(CandidateCodes.WORK_DIRECTORY_CONFLICT, "unreadable meta")
        }
        if (meta["schema"] != "1" || meta["operation"] != META_OPERATION ||
            meta["baselineSha256"] != baseline.sha256 ||
            meta["sourceMode"] != request.sourceMode ||
            meta["targetMode"] != request.targetMode) {
            throw Rejection(CandidateCodes.WORK_DIRECTORY_CONFLICT, "cached evidence belongs to another baseline")
        }
        val expectedCandidateSha = meta["candidateSha256"]
            ?: throw Rejection(CandidateCodes.WORK_DIRECTORY_CONFLICT, "cached sha missing")
        val expectedKernelSha = meta["patchedKernelSha256"]
            ?: throw Rejection(CandidateCodes.WORK_DIRECTORY_CONFLICT, "cached kernel sha missing")
        val expectedRelease = meta["kernelRelease"]
            ?: throw Rejection(CandidateCodes.WORK_DIRECTORY_CONFLICT, "cached release missing")
        if (image.length() != baseline.expectedSize ||
            sha256(image) != expectedCandidateSha) {
            throw Rejection(CandidateCodes.WORK_DIRECTORY_CONFLICT, "cached candidate bytes changed")
        }
        return validateCandidate(request, baseline, image, evidence, expectedKernelSha, expectedRelease)
    }

    // ------------------------------------------------------------------ evidence

    private fun writeEvidence(artifact: CandidateArtifact, metaFile: File) {
        val meta = mapOf(
            "schema" to "1",
            "operation" to META_OPERATION,
            "baselineSha256" to artifact.baselineSha256,
            "candidateSha256" to artifact.sha256,
            "candidateSize" to artifact.size.toString(),
            "patchedKernelSha256" to artifact.patchedKernelSha256,
            "kernelRelease" to artifact.kernelRelease,
            "tailSha256" to artifact.tailSha256,
            "sourceMode" to artifact.sourceMode,
            "targetMode" to artifact.targetMode,
        )
        val metaText = buildString {
            meta.forEach { (key, value) -> append(key).append('=').append(value).append('\n') }
        }
        val evidenceText = buildString {
            append("{\"schemaVersion\":1,\"operation\":\"").append(META_OPERATION).append("\",")
            append("\"sourceMode\":\"").append(jsonEscape(artifact.sourceMode)).append("\",")
            append("\"targetMode\":\"").append(jsonEscape(artifact.targetMode)).append("\",")
            append("\"baseline\":{\"sha256\":\"").append(artifact.baselineSha256).append("\",")
            append("\"size\":").append(artifact.baselineSize).append("},")
            append("\"candidate\":{\"sha256\":\"").append(artifact.sha256).append("\",")
            append("\"size\":").append(artifact.size).append(',')
            append("\"headerVersion\":").append(artifact.headerVersion).append(',')
            append("\"compression\":\"").append(jsonEscape(artifact.compression)).append("\",")
            append("\"kernelSize\":").append(artifact.kernelSize).append(',')
            append("\"ramdiskSize\":").append(artifact.ramdiskSize).append(',')
            append("\"ramdiskSha256\":\"").append(artifact.ramdiskSha256).append("\",")
            append("\"tailSha256\":\"").append(artifact.tailSha256).append("\",")
            append("\"tailPaddingBytes\":").append(artifact.tailPaddingBytes).append("},")
            append("\"kernel\":{\"release\":\"").append(jsonEscape(artifact.kernelRelease)).append("\",")
            append("\"sourceSha256\":\"").append(artifact.sourceKernelSha256).append("\",")
            append("\"patchedSha256\":\"").append(artifact.patchedKernelSha256).append("\"},")
            append("\"verified\":{\"container\":true,\"fullLength\":true,\"kernelPatch\":true,")
            append("\"ramdiskStock\":true,\"ramdiskUnchanged\":true,\"tailContract\":true},")
            append("\"flashableCandidate\":false}")
        }
        val metaTemporary = File(metaFile.parentFile, "$META_NAME.tmp")
        val evidenceTemporary = File(metaFile.parentFile, "$EVIDENCE_NAME.tmp")
        try {
            writeSynced(metaTemporary, metaText.toByteArray(Charsets.UTF_8))
            writeSynced(evidenceTemporary, evidenceText.toByteArray(Charsets.UTF_8))
            Files.move(metaTemporary.toPath(), metaFile.toPath(), StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE)
            Files.move(evidenceTemporary.toPath(), artifact.evidence.toPath(),
                StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } finally {
            Files.deleteIfExists(metaTemporary.toPath())
            Files.deleteIfExists(evidenceTemporary.toPath())
        }
    }

    // ------------------------------------------------------------------ decoding helpers

    private data class KernelIdentity(val size: Int, val sha256: String, val release: String)

    private data class RamdiskIdentity(val size: Long, val sha256: String)

    private class Baseline(
        val report: BootImageInspector.Report,
        val sha256: String,
        val size: Long,
        val kernel: KernelIdentity,
        val ramdisk: RamdiskIdentity,
        val avbFooterPresent: Boolean,
        val expectedSize: Long,
    )

    private fun decodeKernel(image: File, report: BootImageInspector.Report, decodeFailure: String,
                             unsupportedFailure: String, invalidFailure: String): KernelIdentity {
        cancelled()
        if (report.kernelSize <= 0L) throw Rejection(invalidFailure)
        if (report.kernelSize > KernelCompression.MAX_KERNEL_BYTES.toLong()) throw Rejection(invalidFailure)
        val compressed = readRange(image, report.kernelOffset, report.kernelSize)
        if (compressed.isEmpty()) throw Rejection(invalidFailure)
        val raw = try {
            KernelCompression.decode(compressed, report.compression, KernelCompression.MAX_KERNEL_BYTES)
        } catch (failure: IOException) {
            val message = failure.message.orEmpty()
            if (message.startsWith("UNSUPPORTED_COMPRESSION")) throw Rejection(unsupportedFailure, message)
            throw Rejection(decodeFailure, message)
        }
        if (raw.size < 64 || raw[56] != 'A'.code.toByte() || raw[57] != 'R'.code.toByte() ||
            raw[58] != 'M'.code.toByte() || raw[59] != 'd'.code.toByte()) {
            throw Rejection(invalidFailure, "RAW_ARM64_REQUIRED")
        }
        val release = kernelRelease(raw) ?: throw Rejection(invalidFailure, "KERNEL_RELEASE_MISSING")
        return KernelIdentity(raw.size, sha256(raw), release)
    }

    private fun inspectRamdisk(image: File, report: BootImageInspector.Report, malformedFailure: String,
                               residueFailure: String): RamdiskIdentity {
        if (report.ramdiskSize == 0L) return RamdiskIdentity(0, "")
        if (report.ramdiskSize > MAX_RAMDISK_BYTES) {
            throw Rejection(malformedFailure, "ramdisk size ${report.ramdiskSize}")
        }
        val bytes = readRange(image, report.ramdiskOffset, report.ramdiskSize)
        val inspected = RamdiskInspector.inspect(bytes)
        if (inspected.malformed) {
            throw Rejection(malformedFailure, inspected.errorCode.orEmpty())
        }
        if (!inspected.requireStockForm().ok) {
            val residue = inspected.requireStockForm().violations
            throw Rejection(residueFailure, residue.joinToString(","))
        }
        return RamdiskIdentity(inspected.ramdiskSize, sha256(bytes))
    }

    // ------------------------------------------------------------------ small utilities

    private class Rejection(val code: String, val detail: String = "") : Exception(code)

    private fun cancelled() {
        if (Thread.currentThread().isInterrupted) throw Rejection(CandidateCodes.CANCELLED)
    }

    private fun ensureWorkDirectory(work: File): Boolean {
        if (work.exists()) {
            if (!work.isDirectory) throw Rejection(CandidateCodes.WORK_DIRECTORY_CONFLICT)
            val children = work.listFiles()
            if (children != null && children.isNotEmpty()) {
                throw Rejection(CandidateCodes.WORK_DIRECTORY_CONFLICT, "work directory is not empty")
            }
            return false
        }
        val parent = work.absoluteFile.parentFile
        if (parent == null || !parent.isDirectory) {
            throw Rejection(CandidateCodes.WORK_DIRECTORY_FAILED, "parent directory missing")
        }
        if (!work.mkdir()) throw Rejection(CandidateCodes.WORK_DIRECTORY_FAILED)
        return true
    }

    private fun cleanPartialProducts(work: File, deleteWorkDirectory: Boolean) {
        if (!work.isDirectory) {
            if (deleteWorkDirectory) work.delete()
            return
        }
        listOf(IMAGE_NAME, META_NAME, EVIDENCE_NAME, "$IMAGE_NAME.tmp", "$META_NAME.tmp",
            "$EVIDENCE_NAME.tmp").forEach { File(work, it).delete() }
        File(work, VERIFY_DIRECTORY).deleteRecursively()
        File(work, ENGINE_DIRECTORY).deleteRecursively()
        if (deleteWorkDirectory && work.listFiles()?.isEmpty() == true) work.delete()
    }

    private fun copyAtomically(source: File, destination: File) {
        val temporary = File(destination.parentFile, "$IMAGE_NAME.tmp")
        try {
            Files.copy(source.toPath(), temporary.toPath(), StandardCopyOption.REPLACE_EXISTING)
            if (temporary.length() != source.length()) {
                throw Rejection(CandidateCodes.CANDIDATE_NOT_FULL_LENGTH)
            }
            Files.move(temporary.toPath(), destination.toPath(), StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE)
        } finally {
            Files.deleteIfExists(temporary.toPath())
        }
    }

    private fun writeSynced(file: File, bytes: ByteArray) {
        java.io.FileOutputStream(file).use { stream -> stream.write(bytes); stream.flush(); stream.fd.sync() }
    }

    private fun readRange(file: File, offset: Long, length: Long): ByteArray {
        if (length < 0 || length > Int.MAX_VALUE) throw Rejection(CandidateCodes.CANDIDATE_INVALID)
        val bytes = ByteArray(length.toInt())
        RandomAccessFile(file, "r").use { input ->
            if (offset < 0 || offset + length > input.length()) {
                throw Rejection(CandidateCodes.CANDIDATE_INVALID, "range out of bounds")
            }
            input.seek(offset)
            input.readFully(bytes)
        }
        return bytes
    }

    private fun isAllZero(file: File, from: Long, to: Long): Boolean {
        if (to < from) return false
        if (to == from) return true
        if (from < 0 || to > file.length()) return false
        RandomAccessFile(file, "r").use { input ->
            input.seek(from)
            var remaining = to - from
            val buffer = ByteArray(64 * 1024)
            while (remaining > 0) {
                cancelled()
                val count = input.read(buffer, 0, minOf(remaining, buffer.size.toLong()).toInt())
                if (count < 0) return false
                for (index in 0 until count) if (buffer[index] != 0.toByte()) return false
                remaining -= count
            }
        }
        return true
    }

    private fun payloadEnd(report: BootImageInspector.Report): Long {
        val ends = mutableListOf(
            report.kernelOffset + report.kernelSize,
            report.ramdiskOffset + report.ramdiskSize,
            report.secondOffset + report.secondSize,
            report.recoveryDtboOffset + report.recoveryDtboSize,
            report.dtbOffset + report.dtbSize,
        )
        if (report.headerVersion == 4) {
            ends += report.signatureOffset + report.signatureSize
        }
        return alignPage(ends.maxOrNull() ?: 0L)
    }

    /** AVB footer is little-endian on disk but `avbtool` writes the field set big-endian. */
    private class AvbFooter(val originalImageSize: Long, val vbmetaOffset: Long, val vbmetaSize: Long)

    private fun readAvbFooter(image: File): AvbFooter? {
        val size = image.length()
        if (size < AVB_FOOTER_BYTES) return null
        val footer = readRange(image, size - AVB_FOOTER_BYTES, AVB_FOOTER_BYTES)
        if (footer[0] != 'A'.code.toByte() || footer[1] != 'V'.code.toByte() ||
            footer[2] != 'B'.code.toByte() || footer[3] != 'f'.code.toByte()) return null
        return AvbFooter(u64be(footer, 12), u64be(footer, 20), u64be(footer, 28))
    }

    private fun validAvbFooter(footer: AvbFooter, size: Long): Boolean =
        footer.originalImageSize in 0..size &&
            footer.vbmetaOffset in 0..(size - AVB_FOOTER_BYTES) &&
            footer.vbmetaSize >= 256 &&
            footer.vbmetaSize <= size - AVB_FOOTER_BYTES - footer.vbmetaOffset

    private fun kernelRelease(bytes: ByteArray): String? {
        val marker = "Linux version ".toByteArray(Charsets.US_ASCII)
        var result: String? = null
        for (offset in 0..bytes.size - marker.size) {
            if (!marker.indices.all { bytes[offset + it] == marker[it] }) continue
            val start = offset + marker.size
            var end = start
            while (end < bytes.size && end - start < 128) {
                val character = bytes[end].toInt().toChar()
                if (character !in '0'..'9' && character !in 'A'..'Z' && character !in 'a'..'z'
                    && character !in ".-_+") break
                end++
            }
            if (end == start) continue
            val release = String(bytes, start, end - start, Charsets.US_ASCII)
            if (result != null && result != release) return null
            result = release
        }
        return result
    }

    private fun parseMeta(text: String): Map<String, String> =
        text.lineSequence().filter { it.isNotBlank() }.associate { line ->
            val separator = line.indexOf('=')
            if (separator <= 0) throw IOException("PRODUCE_META_INVALID")
            line.substring(0, separator) to line.substring(separator + 1)
        }

    private fun jsonEscape(value: String): String = buildString {
        value.forEach { character ->
            when (character) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (character.code < 0x20) {
                    append(String.format(Locale.ROOT, "\\u%04x", character.code))
                } else {
                    append(character)
                }
            }
        }
    }

    private fun alignPage(value: Long): Long = (value + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE

    private fun u64be(bytes: ByteArray, offset: Int): Long {
        var value = 0L
        for (index in 0 until 8) {
            value = (value shl 8) or (bytes[offset + index].toLong() and 0xFF)
        }
        return value
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                cancelled()
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        return hex(digest.digest())
    }

    private fun sha256(bytes: ByteArray): String = hex(MessageDigest.getInstance("SHA-256").digest(bytes))

    private fun hex(bytes: ByteArray): String = buildString {
        bytes.forEach { append(String.format(Locale.ROOT, "%02x", it.toInt() and 0xFF)) }
    }

    private companion object {
        const val META_OPERATION = "MAPLESU_LITE_CANDIDATE_V1"
        const val PAGE_SIZE = 4096L
        const val AVB_FOOTER_BYTES = 64L
        const val TAIL_PROBE_BYTES = 64L * 1024
        const val MAX_IMAGE_BYTES = 512L * 1024 * 1024
        const val MAX_RAMDISK_BYTES = 64L * 1024 * 1024
        const val IMAGE_NAME = "lite-candidate.img"
        const val META_NAME = "lite-candidate.meta"
        const val EVIDENCE_NAME = "lite-candidate.json"
        const val ENGINE_DIRECTORY = "engine"
        const val VERIFY_DIRECTORY = "verify"
    }
}
