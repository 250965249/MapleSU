package dev.maplesu.manager.patching

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.BootImageRoundTrip
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID

/** Uses only a private synthetic candidate; never reads or writes a device partition. */
@RunWith(AndroidJUnit4::class)
class LiteBootCandidateAndroidTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val patcher = LiteBootPatcher(context)
    private lateinit var directory: File
    private lateinit var image: File
    private lateinit var report: File
    private lateinit var digest: String
    private lateinit var evidence: JSONObject

    @Before fun setup() {
        directory = File(context.filesDir, "candidate-test-${UUID.randomUUID()}")
        check(directory.mkdir())
        image = File(directory, "maplesu-patched.img")
        report = File(directory, "candidate.json")
        val kernel = ByteArray(256)
        byteArrayOf(65, 82, 77, 100).copyInto(kernel, 56)
        "Linux version 6.6.0-candidate-test ".toByteArray().copyInto(kernel, 64)
        val bytes = ByteArray(8192)
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).apply {
            put("ANDROID!".toByteArray())
            putInt(8, kernel.size).putInt(20, 1584).putInt(40, 4)
        }
        kernel.copyInto(bytes, 4096)
        image.writeBytes(bytes)
        val actual = BootImageInspector.inspect(image)
        digest = actual.sha256
        val source = JSONObject().put("sha256", "a".repeat(64))
        evidence = JSONObject()
            .put("schemaVersion", 1).put("operation", "MAPLESU_LITE_BOOT_PATCH")
            .put("source", source).put("image", JSONObject(actual.toJson()))
            .put("rebuild", JSONObject().put("containerVerified", true)
                .put("outputReadbackVerified", true).put("kernelChanged", true)
                .put("source", source).put("image", JSONObject(actual.toJson())))
            .put("kernelRelease", "6.6.0-candidate-test")
            .put("sourceKernelSha256", "b".repeat(64))
            .put("patchedKernelSha256", BootImageRoundTrip.sha256(kernel))
            .put("patchEdits", 1).put("credentialContract", "MAPLESU_LITE_STDIN48_SLOT47_NUL")
            .put("credentialInitialized", true).put("sourceUnchanged", true)
            .put("candidateVerified", true).put("runtimeVerified", false)
        report.writeText(evidence.toString())
    }

    @After fun cleanup() { directory.deleteRecursively() }

    @Test fun acceptsOnlyAnActuallyMatchingImageAndKernel() {
        val found = requireNotNull(patcher.findVerifiedCandidate(digest))
        assertEquals(image.canonicalFile, found.image)
        assertEquals(digest, found.outputSha256)
        assertEquals("6.6.0-candidate-test", found.kernelRelease)
        assertNull(patcher.findVerifiedCandidate("c".repeat(64)))
    }

    @Test fun acceptsPreviouslyWrittenCandidateReports() {
        evidence.put("operation", "MAPLESU_LITE_BOOT_PATCH")
            .put("credentialContract", "MAPLESU_LITE_STDIN48_SLOT47_NUL")
        report.writeText(evidence.toString())
        assertEquals(digest, requireNotNull(patcher.findVerifiedCandidate(digest)).outputSha256)
    }

    @Test fun reportFlagsDoNotSubstituteForImageReadback() {
        val bytes = image.readBytes()
        bytes[4200] = 1
        image.writeBytes(bytes)
        assertNull(patcher.findVerifiedCandidate(digest))
    }

    @Test fun mismatchedKernelEvidenceIsRejected() {
        evidence.put("patchedKernelSha256", "c".repeat(64))
        report.writeText(evidence.toString())
        assertNull(patcher.findVerifiedCandidate(digest))
    }

    @Test fun incompleteOrMalformedReportIsRejected() {
        evidence.put("candidateVerified", false)
        report.writeText(evidence.toString())
        assertNull(patcher.findVerifiedCandidate(digest))
        report.writeText("{")
        assertNull(patcher.findVerifiedCandidate(digest))
    }

    @Test fun sourceAndRebuildMustBindTheSameImagePair() {
        evidence.getJSONObject("rebuild").put("source", JSONObject().put("sha256", "d".repeat(64)))
        report.writeText(evidence.toString())
        assertNull(patcher.findVerifiedCandidate(digest))
    }

    @Test fun knownCandidateIsRejectedBeforeNativeExecution() {
        val output = File(context.filesDir, "candidate-test-${UUID.randomUUID()}")
        try {
            assertThrows(LiteBootPatcher.AlreadyPatchedImageException::class.java) {
                patcher.patch(image, output, ByteArray(48) { 'A'.code.toByte() })
            }
            assertFalse(output.exists())
            assertEquals(digest, BootImageInspector.inspect(image).sha256)
        } finally { output.deleteRecursively() }
    }
}
