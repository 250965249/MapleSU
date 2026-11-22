// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.patching

import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.BootImageRebuilder
import dev.maplesu.image.KernelCompression
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.security.MessageDigest
import java.util.Locale

/**
 * W09 host tests for [LiteCandidateProducer].
 *
 * Synthetic boot images are assembled byte-by-byte (no private device image). The success path
 * runs the real `BootImageRebuilder` rebuild chain through an injected engine, so the producer is
 * exercised against real image-core verification rather than a stub.
 */
class LiteCandidateProducerTest {
    private lateinit var root: File
    private lateinit var work: File

    @Before
    fun setUp() {
        root = Files.createTempDirectory("maplesu-lite-candidate-").toFile()
        work = File(root, "work")
    }

    @After
    fun tearDown() {
        Thread.interrupted()
        root.deleteRecursively()
    }

    // ------------------------------------------------------------------ fixtures

    private val page = 4096
    private val partitionSize = 128 * 1024

    private fun kernelRaw(release: String = "6.6.66-maplesu-test"): ByteArray {
        val raw = ByteArray(4096)
        for (index in raw.indices) raw[index] = ((index * 31 + 7) and 0xFF).toByte()
        raw[56] = 'A'.code.toByte()
        raw[57] = 'R'.code.toByte()
        raw[58] = 'M'.code.toByte()
        raw[59] = 'd'.code.toByte()
        val marker = "Linux version $release ".toByteArray(Charsets.US_ASCII)
        System.arraycopy(marker, 0, raw, 80, marker.size)
        return raw
    }

    private fun patchedKernel(raw: ByteArray, releaseSuffix: String? = null): ByteArray {
        val patched = raw.copyOf()
        patched[300] = (patched[300].toInt() xor 0x5A).toByte()
        patched[301] = (patched[301].toInt() xor 0x3C).toByte()
        if (releaseSuffix != null) {
            val original = "6.6.66-maplesu-test".toByteArray(Charsets.US_ASCII)
            val replacement = releaseSuffix.toByteArray(Charsets.US_ASCII)
            val index = indexOf(patched, original)
            System.arraycopy(replacement, 0, patched, index, minOf(original.size, replacement.size))
        }
        return patched
    }

    private fun align(value: Int, pageSize: Int = page): Int = (value + pageSize - 1) / pageSize * pageSize

    private fun bootImage(kernelCompressed: ByteArray, ramdisk: ByteArray?, totalSize: Int = partitionSize,
                          tamperTail: Boolean = false): ByteArray {
        val ramdiskBytes = ramdisk ?: ByteArray(0)
        val ramdiskOffset = align(page + kernelCompressed.size)
        val minimumSize = align(ramdiskOffset + ramdiskBytes.size)
        val size = maxOf(totalSize, minimumSize)
        val image = ByteArray(size)
        val header = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN)
        header.put("ANDROID!".toByteArray(Charsets.US_ASCII))
        header.putInt(8, kernelCompressed.size)
        header.putInt(12, ramdiskBytes.size)
        header.putInt(20, 1584)
        header.putInt(40, 4)
        System.arraycopy(kernelCompressed, 0, image, page, kernelCompressed.size)
        System.arraycopy(ramdiskBytes, 0, image, ramdiskOffset, ramdiskBytes.size)
        if (tamperTail) image[image.size - 1] = 0x7F
        return image
    }

    private fun gzipKernel(raw: ByteArray): ByteArray = KernelCompression.encode(raw, "GZIP")

    private fun write(bytes: ByteArray, name: String = "baseline.img"): File =
        File(root, name).also { it.writeBytes(bytes) }

    // ------------------------------------------------------------------ CPIO newc ramdisk

    private fun cpioEntry(name: String, mode: Int, data: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val encodedName = name.toByteArray(Charsets.UTF_8)
        fun hex(value: Int) = String.format(Locale.ROOT, "%08x", value and 0xFFFFFFFF.toInt())
        out.write("070701".toByteArray(Charsets.US_ASCII))
        out.write(hex(1).toByteArray(Charsets.US_ASCII)) // ino
        out.write(hex(mode).toByteArray(Charsets.US_ASCII))
        out.write(hex(0).toByteArray(Charsets.US_ASCII)) // uid
        out.write(hex(0).toByteArray(Charsets.US_ASCII)) // gid
        out.write(hex(1).toByteArray(Charsets.US_ASCII)) // nlink
        out.write(hex(0).toByteArray(Charsets.US_ASCII)) // mtime
        out.write(hex(data.size).toByteArray(Charsets.US_ASCII))
        out.write(hex(0).toByteArray(Charsets.US_ASCII)) // devmajor
        out.write(hex(0).toByteArray(Charsets.US_ASCII)) // devminor
        out.write(hex(0).toByteArray(Charsets.US_ASCII)) // rdevmajor
        out.write(hex(0).toByteArray(Charsets.US_ASCII)) // rdevminor
        out.write(hex(encodedName.size + 1).toByteArray(Charsets.US_ASCII))
        out.write(hex(0).toByteArray(Charsets.US_ASCII)) // check
        out.write(encodedName)
        out.write(0)
        while (out.size() % 4 != 0) out.write(0)
        out.write(data)
        while (out.size() % 4 != 0) out.write(0)
        return out.toByteArray()
    }

    private fun cpio(entries: List<ByteArray>): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        entries.forEach { out.write(it) }
        out.write(cpioEntry("TRAILER!!!", 0, ByteArray(0)))
        return out.toByteArray()
    }

    /** Raw CPIO ramdisk whose total length is fixed; the marker entry name is length-stable. */
    private fun stockRamdisk(markerName: String = "stock.entry", markerData: ByteArray = "stock".toByteArray()): ByteArray =
        cpio(listOf(
            cpioEntry("init", 0b1000000111101101, "stock-init".toByteArray()),
            cpioEntry(markerName, 0b1000000110100100, markerData),
            cpioEntry("fstab.qcom", 0b1000000110100100, "fstab".toByteArray()),
        ))

    private fun ksuRamdisk(): ByteArray = cpio(listOf(
        cpioEntry("init", 0b1000000111101101, "ksuinit".toByteArray()),
        cpioEntry("init.real", 0b1000000111101101, "android-init".toByteArray()),
        cpioEntry("kernelsu.ko", 0b1000000110100100, "kernelsu".toByteArray()),
        cpioEntry("ksu_config", 0b1000000110100100, "uapi=7\n".toByteArray()),
    ))

    // ------------------------------------------------------------------ fake engines

    private class FakeEngine(private val block: (File, File) -> EngineCandidate) : LitePatchEngine {
        var calls = 0
            private set

        override fun produce(baseline: File, engineDirectory: File): EngineCandidate {
            calls++
            return block(baseline, engineDirectory)
        }
    }

    private fun successEngine(patched: ByteArray = patchedKernel(kernelRaw())): FakeEngine =
        FakeEngine { baseline, engineDirectory ->
            engineDirectory.mkdirs()
            val source = BootImageInspector.inspect(baseline)
            val component = File(engineDirectory, "kernel.component")
            component.writeBytes(KernelCompression.encode(patched, source.compression))
            val candidate = File(engineDirectory, "candidate.img")
            BootImageRebuilder.rebuild(baseline, component, candidate)
            EngineCandidate(candidate, sha256(patched), kernelRelease(patched)!!)
        }

    private fun directEngine(candidateBytes: ByteArray, patchedSha: String,
                             release: String): FakeEngine = FakeEngine { _, engineDirectory ->
        engineDirectory.mkdirs()
        val candidate = File(engineDirectory, "candidate.img")
        candidate.writeBytes(candidateBytes)
        EngineCandidate(candidate, patchedSha, release)
    }

    private fun request(baseline: File = baselineFile(), workDirectory: File = work,
                        sourceMode: String = CandidateMode.KSU, baselineSha: String? = null,
                        expectedSize: Long? = null): CandidateRequest =
        CandidateRequest(baseline, workDirectory, sourceMode, CandidateMode.LITE, baselineSha, expectedSize)

    private fun baselineFile(): File = write(bootImage(gzipKernel(kernelRaw()), stockRamdisk()))

    private fun produce(request: CandidateRequest = request(), engine: LitePatchEngine = successEngine()):
        CandidateOutcome = LiteCandidateProducer(engine).produce(request)

    private fun rejected(engine: LitePatchEngine, request: CandidateRequest = request()): CandidateOutcome.Rejected {
        val outcome = LiteCandidateProducer(engine).produce(request)
        if (outcome is CandidateOutcome.Rejected) return outcome
        fail("Expected rejection but produced ${(outcome as CandidateOutcome.Produced).artifact.sha256}")
        throw IllegalStateException()
    }

    // ------------------------------------------------------------------ success

    @Test
    fun producesFullLengthCandidateWithVerifiedEvidence() {
        val baseline = baselineFile()
        val baselineBytes = baseline.readBytes()
        val outcome = produce(request(baseline = baseline), successEngine())
        val artifact = (outcome as CandidateOutcome.Produced).artifact

        assertEquals(partitionSize.toLong(), artifact.size)
        assertEquals(partitionSize.toLong(), artifact.baselineSize)
        assertEquals(baselineBytes.size.toLong(), artifact.size)
        assertEquals(CandidateMode.KSU, artifact.sourceMode)
        assertEquals(CandidateMode.LITE, artifact.targetMode)
        assertEquals(sha256(baselineBytes), artifact.baselineSha256)

        val report = BootImageInspector.inspect(artifact.image)
        assertEquals(report.fileSize, artifact.size)
        assertEquals(report.sha256, artifact.sha256)
        assertEquals(4, artifact.headerVersion)
        assertEquals("GZIP", artifact.compression)
        assertEquals("6.6.66-maplesu-test", artifact.kernelRelease)
        assertEquals(artifact.kernelSize, report.kernelSize)
        assertNotEquals(artifact.sourceKernelSha256, artifact.patchedKernelSha256)
        assertEquals(kernelRelease(kernelRaw()), artifact.kernelRelease)
        assertTrue(artifact.ramdiskSha256.matches(Regex("[0-9a-f]{64}")))
        assertTrue(artifact.tailSha256.matches(Regex("[0-9a-f]{64}")))
        assertTrue(artifact.tailPaddingBytes > 0)
        assertTrue(artifact.evidence.isFile)
        val evidence = artifact.evidence.readText()
        assertTrue(evidence.contains("\"operation\":\"MAPLESU_LITE_CANDIDATE_V1\""))
        assertTrue(evidence.contains("\"ramdiskStock\":true"))
        assertTrue(evidence.contains("\"fullLength\":true"))
        assertTrue(evidence.contains("\"flashableCandidate\":false"))
    }

    @Test
    fun candidateRamdiskStaysByteIdenticalAndStock() {
        val baseline = baselineFile()
        val outcome = produce(request(baseline = baseline), successEngine()) as CandidateOutcome.Produced
        val artifact = outcome.artifact
        val source = BootImageInspector.inspect(baseline)
        val candidate = BootImageInspector.inspect(artifact.image)
        assertEquals(source.ramdiskSize, candidate.ramdiskSize)
        assertEquals(readRange(baseline, source.ramdiskOffset, source.ramdiskSize).toList(),
            readRange(artifact.image, candidate.ramdiskOffset, candidate.ramdiskSize).toList())
        assertEquals(sha256(readRange(baseline, source.ramdiskOffset, source.ramdiskSize)),
            artifact.ramdiskSha256)
    }

    @Test
    fun kernelOnlyBootWithoutRamdiskIsSupported() {
        val baseline = write(bootImage(gzipKernel(kernelRaw()), null))
        val artifact = (produce(request(baseline = baseline), successEngine()) as CandidateOutcome.Produced).artifact
        assertEquals(0L, artifact.ramdiskSize)
        assertEquals("", artifact.ramdiskSha256)
        assertEquals(partitionSize.toLong(), artifact.size)
    }

    @Test
    fun secondCallIsIdempotentAndReusesArtifact() {
        val baseline = baselineFile()
        val engine = successEngine()
        val producer = LiteCandidateProducer(engine)
        val first = producer.produce(request(baseline = baseline)) as CandidateOutcome.Produced
        val imageBytes = first.artifact.image.readBytes()
        val metaBytes = File(work, "lite-candidate.meta").readBytes()
        val second = producer.produce(request(baseline = baseline)) as CandidateOutcome.Produced
        assertEquals(1, engine.calls)
        assertEquals(first.artifact.sha256, second.artifact.sha256)
        assertEquals(first.artifact.size, second.artifact.size)
        assertArrayEquals(imageBytes, second.artifact.image.readBytes())
        assertArrayEquals(metaBytes, File(work, "lite-candidate.meta").readBytes())
    }

    // ------------------------------------------------------------------ baseline rejection

    @Test
    fun rejectsMissingBaseline() {
        val outcome = produce(request(baseline = File(root, "missing.img")))
        assertEquals(CandidateCodes.BASELINE_MISSING, (outcome as CandidateOutcome.Rejected).code)
    }

    @Test
    fun rejectsBaselineWhoseDeclaredComponentIsTruncated() {
        val valid = bootImage(gzipKernel(kernelRaw()), stockRamdisk())
        val report = BootImageInspector.inspect(write(valid, "probe.img"))
        val truncated = valid.copyOf((report.ramdiskOffset + report.ramdiskSize - 1).toInt())
        val baseline = write(truncated, "truncated.img")
        val outcome = produce(request(baseline = baseline))
        assertEquals(CandidateCodes.BASELINE_INVALID, (outcome as CandidateOutcome.Rejected).code)
    }

    @Test
    fun rejectsBaselineShaPinMismatch() {
        val baseline = baselineFile()
        val outcome = produce(request(baseline = baseline, baselineSha = "0".repeat(64)))
        assertEquals(CandidateCodes.BASELINE_SHA_MISMATCH, (outcome as CandidateOutcome.Rejected).code)
    }

    @Test
    fun rejectsBaselineWithoutKernel() {
        val baseline = write(bootImage(ByteArray(0), stockRamdisk()))
        val outcome = produce(request(baseline = baseline))
        assertEquals(CandidateCodes.BASELINE_KERNEL_MISSING, (outcome as CandidateOutcome.Rejected).code)
    }

    @Test
    fun rejectsUnsupportedBaselineKernelCompression() {
        // 真正无法识别的容器：`KernelIdentity.formatOf` 判 UNKNOWN，`KernelCompression.decode`
        // 仍抛 `UNSUPPORTED_COMPRESSION:UNKNOWN`。W2 之后 LZ4_FRAME / XZ / ZSTD 都能解，
        // 所以这条门只对「识别不出的格式」成立（见下一个用例）。
        val unknown = byteArrayOf(0x4D, 0x53, 0x55, 0x00) + ByteArray(128)
        val baseline = write(bootImage(unknown, stockRamdisk()))
        val outcome = produce(request(baseline = baseline))
        assertEquals(CandidateCodes.BASELINE_KERNEL_COMPRESSION_UNSUPPORTED,
            (outcome as CandidateOutcome.Rejected).code)
    }

    @Test
    fun rejectsMalformedLz4FrameKernelAsDecodeFailure() {
        // LZ4_FRAME 的语义已被 W2 取代：不再是「不支持的压缩」，而是「支持解码」。
        // 同一个坏帧现在落到 DECODE_FAILED；判据仍是「拒绝，不静默接受」。
        val lz4Frame = byteArrayOf(4, 34, 77, 24) + ByteArray(128)
        val baseline = write(bootImage(lz4Frame, stockRamdisk()))
        val outcome = produce(request(baseline = baseline))
        assertEquals(CandidateCodes.BASELINE_KERNEL_DECODE_FAILED,
            (outcome as CandidateOutcome.Rejected).code)
    }

    @Test
    fun rejectsUncleanBaselineRamdisk() {
        val baseline = write(bootImage(gzipKernel(kernelRaw()), ksuRamdisk()))
        val outcome = produce(request(baseline = baseline))
        assertEquals(CandidateCodes.BASELINE_UNCLEAN, (outcome as CandidateOutcome.Rejected).code)
    }

    @Test
    fun rejectsInvalidTargetModeAndExpectedSizeMismatch() {
        val baseline = baselineFile()
        val wrongMode = LiteCandidateProducer(successEngine()).produce(
            request(baseline = baseline).copy(targetMode = CandidateMode.KSU))
        assertEquals(CandidateCodes.CANDIDATE_REQUEST_INVALID, (wrongMode as CandidateOutcome.Rejected).code)
        val wrongSize = produce(request(baseline = baseline, expectedSize = partitionSize.toLong() + 4096))
        assertEquals(CandidateCodes.BASELINE_SIZE_MISMATCH, (wrongSize as CandidateOutcome.Rejected).code)
    }

    // ------------------------------------------------------------------ engine rejection

    @Test
    fun rejectsEngineFailureAndLeavesNoArtifact() {
        val engine = FakeEngine { _, engineDirectory ->
            engineDirectory.mkdirs()
            throw java.io.IOException("PATCH_FAILED")
        }
        val outcome = produce(request(), engine)
        assertEquals(CandidateCodes.PATCH_ENGINE_FAILED, (outcome as CandidateOutcome.Rejected).code)
        assertFalse(work.exists())
    }

    @Test
    fun rejectsWhenEngineMutatesBaseline() {
        val engine = FakeEngine { baseline, engineDirectory ->
            engineDirectory.mkdirs()
            val source = BootImageInspector.inspect(baseline)
            val component = File(engineDirectory, "kernel.component")
            component.writeBytes(KernelCompression.encode(patchedKernel(kernelRaw()), source.compression))
            val candidate = File(engineDirectory, "candidate.img")
            BootImageRebuilder.rebuild(baseline, component, candidate)
            baseline.appendBytes(byteArrayOf(0x42))
            EngineCandidate(candidate, sha256(patchedKernel(kernelRaw())), "6.6.66-maplesu-test")
        }
        val outcome = produce(request(baseline = baselineFile()), engine)
        assertEquals(CandidateCodes.BASELINE_MUTATED, (outcome as CandidateOutcome.Rejected).code)
    }

    @Test
    fun rejectsMissingEngineCandidate() {
        val engine = FakeEngine { _, engineDirectory ->
            engineDirectory.mkdirs()
            EngineCandidate(File(engineDirectory, "absent.img"), "0".repeat(64), "6.6.66")
        }
        assertEquals(CandidateCodes.CANDIDATE_MISSING, rejected(engine).code)
    }

    // ------------------------------------------------------------------ candidate rejection

    @Test
    fun rejectsOverlongCandidate() {
        val patched = patchedKernel(kernelRaw())
        val overlong = bootImage(gzipKernel(patched), stockRamdisk(), totalSize = partitionSize + page)
        val engine = directEngine(overlong, sha256(patched), "6.6.66-maplesu-test")
        assertEquals(CandidateCodes.CANDIDATE_SIZE_CONFLICT, rejected(engine).code)
    }

    @Test
    fun rejectsTruncatedCandidateThatIsNotJustZeroPadding() {
        val patched = patchedKernel(kernelRaw())
        val full = bootImage(gzipKernel(patched), stockRamdisk())
        val source = BootImageInspector.inspect(write(full, "probe2.img"))
        // Cut inside the kernel component: the missing bytes are real data, not zero padding.
        val cut = (source.kernelOffset + source.kernelSize / 2).toInt()
        val truncated = full.copyOf(cut)
        val engine = directEngine(truncated, sha256(patched), "6.6.66-maplesu-test")
        assertEquals(CandidateCodes.CANDIDATE_NOT_FULL_LENGTH, rejected(engine).code)
    }

    @Test
    fun rejectsCandidateWithNonZeroTail() {
        val patched = patchedKernel(kernelRaw())
        val tampered = bootImage(gzipKernel(patched), stockRamdisk(), tamperTail = true)
        val engine = directEngine(tampered, sha256(patched), "6.6.66-maplesu-test")
        assertEquals(CandidateCodes.CANDIDATE_TAIL_CONTRACT, rejected(engine).code)
    }

    @Test
    fun rejectsWrongKernelFingerprint() {
        val patched = patchedKernel(kernelRaw())
        val candidate = bootImage(gzipKernel(patched), stockRamdisk())
        val engine = directEngine(candidate, "f".repeat(64), "6.6.66-maplesu-test")
        assertEquals(CandidateCodes.CANDIDATE_KERNEL_SHA_MISMATCH, rejected(engine).code)
    }

    @Test
    fun rejectsKernelReleaseChange() {
        val changed = patchedKernel(kernelRaw(), releaseSuffix = "6.6.67-maplesu-test")
        val candidate = bootImage(gzipKernel(changed), stockRamdisk())
        val engine = directEngine(candidate, sha256(changed), kernelRelease(changed)!!)
        assertEquals(CandidateCodes.CANDIDATE_KERNEL_RELEASE_CHANGED, rejected(engine).code)
    }

    @Test
    fun rejectsUnchangedKernel() {
        val raw = kernelRaw()
        val candidate = bootImage(gzipKernel(raw), stockRamdisk())
        val engine = directEngine(candidate, sha256(raw), kernelRelease(raw)!!)
        assertEquals(CandidateCodes.CANDIDATE_KERNEL_UNCHANGED, rejected(engine).code)
    }

    @Test
    fun rejectsKernelSizeChange() {
        val bigger = kernelRaw() + ByteArray(2048)
        val candidate = bootImage(gzipKernel(bigger), stockRamdisk())
        val engine = directEngine(candidate, sha256(bigger), kernelRelease(bigger)!!)
        assertEquals(CandidateCodes.CANDIDATE_KERNEL_SIZE_CHANGED, rejected(engine).code)
    }

    @Test
    fun rejectsCandidateWithKsuRamdiskResidue() {
        val patched = patchedKernel(kernelRaw())
        // Same CPIO length as the stock ramdisk: only the marker entry name changes to a KSU one.
        val residue = stockRamdisk(markerName = "kernelsu.ko")
        assertEquals(stockRamdisk().size, residue.size)
        val candidate = bootImage(gzipKernel(patched), residue)
        val engine = directEngine(candidate, sha256(patched), "6.6.66-maplesu-test")
        assertEquals(CandidateCodes.CANDIDATE_RAMDISK_KSU_RESIDUE, rejected(engine).code)
    }

    @Test
    fun rejectsCandidateWithMalformedRamdisk() {
        val patched = patchedKernel(kernelRaw())
        val malformed = stockRamdisk().copyOf()
        malformed[0] = 'X'.code.toByte()
        val candidate = bootImage(gzipKernel(patched), malformed)
        val engine = directEngine(candidate, sha256(patched), "6.6.66-maplesu-test")
        assertEquals(CandidateCodes.CANDIDATE_RAMDISK_MALFORMED, rejected(engine).code)
    }

    @Test
    fun rejectsCandidateWhoseStockRamdiskChanged() {
        val patched = patchedKernel(kernelRaw())
        val changedRamdisk = stockRamdisk(markerData = "other".toByteArray())
        assertEquals(stockRamdisk().size, changedRamdisk.size)
        val candidate = bootImage(gzipKernel(patched), changedRamdisk)
        val engine = directEngine(candidate, sha256(patched), "6.6.66-maplesu-test")
        assertEquals(CandidateCodes.CANDIDATE_RAMDISK_CHANGED, rejected(engine).code)
    }

    @Test
    fun rejectsWorkDirectoryWithForeignContent() {
        work.mkdirs()
        File(work, "unrelated.txt").writeText("x")
        val outcome = produce(request(), successEngine())
        assertEquals(CandidateCodes.WORK_DIRECTORY_CONFLICT, (outcome as CandidateOutcome.Rejected).code)
    }

    @Test
    fun corruptedCachedArtifactIsRejectedInsteadOfTrusted() {
        val baseline = baselineFile()
        val producer = LiteCandidateProducer(successEngine())
        val first = producer.produce(request(baseline = baseline)) as CandidateOutcome.Produced
        val image = first.artifact.image
        val bytes = image.readBytes()
        bytes[bytes.size - 1] = 0x11
        image.writeBytes(bytes)
        val outcome = producer.produce(request(baseline = baseline))
        assertEquals(CandidateCodes.WORK_DIRECTORY_CONFLICT, (outcome as CandidateOutcome.Rejected).code)
    }

    @Test
    fun cancelledProducerReturnsStructuredCode() {
        val baseline = baselineFile()
        Thread.currentThread().interrupt()
        try {
            val outcome = produce(request(baseline = baseline))
            assertEquals(CandidateCodes.CANCELLED, (outcome as CandidateOutcome.Rejected).code)
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun artifactCanBeRevalidatedFromDiskWithoutEngineCalls() {
        val baseline = baselineFile()
        val engine = successEngine()
        val artifact = (LiteCandidateProducer(engine).produce(request(baseline = baseline))
            as CandidateOutcome.Produced).artifact
        // Simulate a later W08 consumer that has only the artifact path: inspect bytes independently.
        val report = BootImageInspector.inspect(artifact.image)
        assertEquals(artifact.sha256, report.sha256)
        assertEquals(partitionSize.toLong(), report.fileSize)
        assertEquals("6.6.66-maplesu-test", kernelRelease(decodeKernel(artifact.image))!!)
        assertEquals(1, engine.calls)
    }

    // ------------------------------------------------------------------ helpers

    private fun decodeKernel(image: File): ByteArray {
        val report = BootImageInspector.inspect(image)
        val encoded = readRange(image, report.kernelOffset, report.kernelSize)
        return KernelCompression.decode(encoded, report.compression, KernelCompression.MAX_KERNEL_BYTES)
    }

    private fun readRange(file: File, offset: Long, length: Long): ByteArray {
        val bytes = ByteArray(length.toInt())
        RandomAccessFile(file, "r").use { input -> input.seek(offset); input.readFully(bytes) }
        return bytes
    }

    private fun kernelRelease(bytes: ByteArray): String? {
        val marker = "Linux version ".toByteArray(Charsets.US_ASCII)
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
            if (end > start) return String(bytes, start, end - start, Charsets.US_ASCII)
        }
        return null
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        for (offset in 0..haystack.size - needle.size) {
            if (needle.indices.all { haystack[offset + it] == needle[it] }) return offset
        }
        return -1
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
            String.format(Locale.ROOT, "%02x", it.toInt() and 0xFF)
        }
}
