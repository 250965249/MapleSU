package dev.maplesu.manager.installer

import dev.maplesu.installer.BlockDeviceTransaction
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.util.zip.GZIPOutputStream

/** Host tests for the production candidate verifier (image-core RamdiskInspector wiring). */
class RamdiskCandidateVerifierTest {
    private val verifier = RamdiskCandidateVerifier()

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    private fun sha256(file: File): String = sha256(file.readBytes())

    private fun tailSha256(file: File): String {
        val bytes = file.readBytes()
        val window = minOf(bytes.size, 64 * 1024)
        return sha256(bytes.copyOfRange(bytes.size - window, bytes.size))
    }

    private fun tempFile(name: String, bytes: ByteArray): File {
        val root = Files.createTempDirectory("maplesu-candidate-verify-").toFile()
        return File(root, name).apply { writeBytes(bytes) }
    }

    private fun artifact(file: File, sha: String = if (file.isFile) sha256(file) else "0".repeat(64)) = KsuProducedArtifact(
        candidate = file,
        size = file.length(),
        sha256 = sha,
        partition = "init_boot",
        form = null,
        ramdiskState = null,
        sourceSha256 = "0".repeat(64),
        kernelsuKoSha256 = null,
    )

    /** Build a minimal newc cpio archive and gzip it (a valid ramdisk component). */
    private fun gzipCpio(entries: List<Pair<String, ByteArray>>): ByteArray {
        val cpio = ByteArrayOutputStream()
        var inode = 1
        for ((name, data) in entries) {
            val nameBytes = (name + "\u0000").toByteArray(Charsets.UTF_8)
            val header = ByteArray(110) { '0'.code.toByte() }
            "070701".toByteArray(Charsets.US_ASCII).copyInto(header, 0)
            fun field(value: Int, offset: Int) {
                val text = "%08x".format(value)
                for (index in 0 until 8) header[offset + index] = text[index].code.toByte()
            }
            field(inode, 6); field(0x81A4, 14); field(0, 22); field(0, 30)
            field(1, 38); field(0, 46); field(data.size, 54)
            field(0, 62); field(0, 70); field(0, 78); field(0, 86)
            field(nameBytes.size, 94); field(0, 102)
            cpio.write(header)
            cpio.write(nameBytes)
            while (cpio.size() % 4 != 0) cpio.write(0)
            cpio.write(data)
            while (cpio.size() % 4 != 0) cpio.write(0)
            inode++
        }
        val trailer = "TRAILER!!!\u0000".toByteArray(Charsets.UTF_8)
        val header = ByteArray(110) { '0'.code.toByte() }
        "070701".toByteArray(Charsets.US_ASCII).copyInto(header, 0)
        fun field(value: Int, offset: Int) {
            val text = "%08x".format(value)
            for (index in 0 until 8) header[offset + index] = text[index].code.toByte()
        }
        field(inode, 6); field(0x81A4, 14); field(1, 38); field(trailer.size, 94)
        cpio.write(header)
        cpio.write(trailer)
        while (cpio.size() % 4 != 0) cpio.write(0)
        val out = ByteArrayOutputStream()
        GZIPOutputStream(out).use { it.write(cpio.toByteArray()) }
        return out.toByteArray()
    }

    private fun stockEntries(): List<Pair<String, ByteArray>> = listOf("init" to byteArrayOf(1, 2, 3))

    private fun lkmEntries(owned: Boolean, sevenk: Boolean = false): List<Pair<String, ByteArray>> {
        val entries = mutableListOf(
            "init" to byteArrayOf(1, 2, 3),
            "init.real" to byteArrayOf(4, 5),
            "kernelsu.ko" to byteArrayOf(9, 9, 9, 9),
            "ksu_config" to byteArrayOf(7),
        )
        if (sevenk) entries.add("sevenk.ko" to byteArrayOf(6, 6))
        if (owned) entries.add("maplesu_id" to byteArrayOf(0x75, 0x61, 0x70, 0x69, 0x3d, 0x37))
        return entries
    }

    private fun expectRejected(result: KsuVerifyOutcome, code: String) {
        assertTrue("expected Rejected but was $result", result is KsuVerifyOutcome.Rejected)
        assertEquals(code, (result as KsuVerifyOutcome.Rejected).code)
    }

    @Test
    fun missingCandidateRejected() {
        val missing = File(tempFile("x.img", ByteArray(1)).parentFile, "missing.img")
        expectRejected(
            verifier.verify(artifact(missing), KsuCandidateExpectation(partitionSize = 4096)),
            "PRODUCE_OUTPUT_MISSING",
        )
    }

    @Test
    fun notFullLengthRejected() {
        val file = tempFile("short.img", ByteArray(10))
        expectRejected(
            verifier.verify(artifact(file), KsuCandidateExpectation(partitionSize = 4096)),
            "PRODUCE_OUTPUT_SIZE_INVALID",
        )
    }

    @Test
    fun wrongPartitionRejected() {
        // Normal 的两个合法目标（init_boot / boot）之外的分区一律拒绝，且不做兜底映射。
        val file = tempFile("candidate.img", gzipCpio(lkmEntries(owned = true)))
        expectRejected(
            verifier.verify(artifact(file),
                KsuCandidateExpectation(partition = "vendor_boot", partitionSize = file.length())),
            "PRODUCE_PARTITION_UNSUPPORTED",
        )
    }

    @Test
    fun sizeOutOfBoundsRejected() {
        val file = tempFile("candidate.img", gzipCpio(lkmEntries(owned = true)))
        expectRejected(
            verifier.verify(artifact(file),
                KsuCandidateExpectation(partitionSize = BlockDeviceTransaction.MAX_BYTES + 1)),
            "INSTALLER_DEVICE_SIZE_INVALID",
        )
    }

    @Test
    fun garbageBytesAreMalformed() {
        val bytes = ByteArray(4096) { ((it * 7) and 0xFF).toByte() }
        val file = tempFile("garbage.img", bytes)
        expectRejected(
            verifier.verify(artifact(file), KsuCandidateExpectation(partitionSize = bytes.size.toLong())),
            "PRODUCE_CANDIDATE_MALFORMED",
        )
    }

    @Test
    fun stockRamdiskRejected() {
        val file = tempFile("stock.img", gzipCpio(stockEntries()))
        expectRejected(
            verifier.verify(artifact(file), KsuCandidateExpectation(partitionSize = file.length())),
            "PRODUCE_CANDIDATE_FORM_MISSING_KERNELSU_KO",
        )
    }

    @Test
    fun sevenkForeignArtifactRejected() {
        val file = tempFile("foreign.img", gzipCpio(lkmEntries(owned = true, sevenk = true)))
        expectRejected(
            verifier.verify(artifact(file), KsuCandidateExpectation(partitionSize = file.length())),
            "PRODUCE_CANDIDATE_FORM_FOREIGN_ARTIFACT",
        )
    }

    @Test
    fun unownedLkmRejectedByDefault() {
        val file = tempFile("unowned.img", gzipCpio(lkmEntries(owned = false)))
        expectRejected(
            verifier.verify(artifact(file), KsuCandidateExpectation(partitionSize = file.length())),
            "PRODUCE_CANDIDATE_UNOWNED",
        )
    }

    @Test
    fun ownedLkmAcceptedWithTailContract() {
        val file = tempFile("owned.img", gzipCpio(lkmEntries(owned = true)))
        val result = verifier.verify(artifact(file), KsuCandidateExpectation(partitionSize = file.length()))
        assertTrue("expected Ok but was $result", result is KsuVerifyOutcome.Ok)
        val ok = result as KsuVerifyOutcome.Ok
        assertTrue(ok.owned)
        assertEquals("KSU_LKM_OURS", ok.form)
        assertEquals(tailSha256(file), ok.tailSha256)
        assertEquals(sha256(byteArrayOf(9, 9, 9, 9)), ok.kernelsuKoSha256)
    }

    @Test
    fun unownedLkmAcceptedWhenRelaxed() {
        val file = tempFile("compatible.img", gzipCpio(lkmEntries(owned = false)))
        val result = verifier.verify(
            artifact(file),
            KsuCandidateExpectation(partitionSize = file.length(), requireOwned = false),
        )
        assertTrue(result is KsuVerifyOutcome.Ok)
        assertEquals("KSU_LKM_COMPATIBLE", (result as KsuVerifyOutcome.Ok).form)
        assertTrue(!result.owned)
    }

    @Test
    fun changedShaRejected() {
        val file = tempFile("owned.img", gzipCpio(lkmEntries(owned = true)))
        expectRejected(
            verifier.verify(
                artifact(file, sha = "0".repeat(64)),
                KsuCandidateExpectation(partitionSize = file.length()),
            ),
            "PRODUCE_CANDIDATE_CHANGED",
        )
    }
}
