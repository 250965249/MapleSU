package dev.maplesu.manager.patching

import android.content.Context
import android.os.Looper
import com.maplesu.core.R
import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.BootImageRebuilder
import dev.maplesu.image.BootImageRoundTrip
import dev.maplesu.image.KernelCompression
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.util.concurrent.TimeUnit

/** Source-built Lite patcher. Produces a checked image; never opens a partition. */
class LiteBootPatcher(context: Context) {
    private val context = context.applicationContext
    private val executable = File(context.applicationInfo.nativeLibraryDir, "libmaplesu_patch.so")

    data class Candidate(
        val image: File,
        val report: File,
        val sourceSha256: String,
        val outputSha256: String,
        val kernelRelease: String,
        val patchedKernelSha256: String,
    )

    class AlreadyPatchedImageException : IOException("PATCH_ALREADY_PATCHED")

    /** Reports alone are not proof: recheck the retained image and its decoded kernel. */
    fun findVerifiedCandidate(outputSha256: String): Candidate? = synchronized(operationLock) {
        check(Looper.myLooper() != Looper.getMainLooper()) { "PATCH_BACKGROUND_THREAD_REQUIRED" }
        require(outputSha256.matches(Regex("[0-9a-f]{64}"))) { "PATCH_DIGEST_INVALID" }
        val root = context.filesDir.canonicalFile
        for (entry in root.listFiles().orEmpty()) {
            cancelled()
            if (!entry.name.startsWith("candidate-") || !entry.isDirectory) continue
            val candidate = try {
                val directory = entry.canonicalFile
                check(directory.parentFile == root)
                val evidence = File(directory, "candidate.json").canonicalFile
                val image = File(directory, "maplesu-patched.img").canonicalFile
                check(evidence.parentFile == directory && image.parentFile == directory &&
                    evidence.isFile && evidence.length() in 1L..1024L * 1024 && image.isFile)
                val json = JSONObject(evidence.readText())
                if (json.getJSONObject("image").getString("sha256") != outputSha256) continue
                check(json.getInt("schemaVersion") == 1 &&
                    json.getString("operation") in setOf("MAPLESU_LITE_BOOT_PATCH", "MAPLESU_LITE_BOOT_PATCH") &&
                    json.getString("credentialContract") in setOf("MAPLESU_LITE_STDIN48_SLOT47_NUL", "MAPLESU_LITE_STDIN48_SLOT47_NUL") &&
                    json.getBoolean("credentialInitialized") && json.getBoolean("sourceUnchanged") &&
                    json.getBoolean("candidateVerified") && json.getInt("patchEdits") > 0)
                val sourceHash = json.getJSONObject("source").getString("sha256")
                val sourceKernelHash = json.getString("sourceKernelSha256")
                check(sourceHash.matches(Regex("[0-9a-f]{64}")) && sourceHash != outputSha256 &&
                    sourceKernelHash.matches(Regex("[0-9a-f]{64}")))
                val rebuild = json.getJSONObject("rebuild")
                check(rebuild.getBoolean("containerVerified") && rebuild.getBoolean("outputReadbackVerified") &&
                    rebuild.getBoolean("kernelChanged") &&
                    rebuild.getJSONObject("source").getString("sha256") == sourceHash &&
                    rebuild.getJSONObject("image").getString("sha256") == outputSha256)
                val report = BootImageInspector.inspect(image)
                check(report.sha256 == outputSha256)
                val kernel = decodeIdentity(image, report)
                check(kernel.release == json.getString("kernelRelease") &&
                    kernel.sha256 == json.getString("patchedKernelSha256") && kernel.sha256 != sourceKernelHash)
                Candidate(image, evidence, sourceHash, outputSha256, kernel.release, kernel.sha256)
            } catch (_: Exception) {
                cancelled()
                null
            }
            if (candidate != null) return@synchronized candidate
        }
        null
    }

    /** The credential must already be durably stored by the caller before publishing this result. */
    fun patch(
        sourceBoot: File,
        outputDirectory: File,
        credential: ByteArray,
        onLog: (String) -> Unit = {},
    ): Candidate = synchronized(operationLock) {
        check(Looper.myLooper() != Looper.getMainLooper()) { "PATCH_BACKGROUND_THREAD_REQUIRED" }
        require(credential.size == 48 && credential.all { byte ->
            byte in 'A'.code.toByte()..'Z'.code.toByte() ||
                byte in 'a'.code.toByte()..'z'.code.toByte() ||
                byte in '0'.code.toByte()..'9'.code.toByte()
        }) { "PATCH_CREDENTIAL_INVALID" }
        check(executable.isFile && executable.canExecute()) { "PATCH_RUNTIME_UNAVAILABLE" }
        val directory = outputDirectory.canonicalFile
        require(listOf(context.filesDir, context.cacheDir).any {
            directory.toPath().startsWith(it.canonicalFile.toPath()) && directory != it.canonicalFile
        }) { "PATCH_PRIVATE_DIRECTORY_REQUIRED" }
        check(directory.mkdir()) { "PATCH_OUTPUT_DIRECTORY_EXISTS" }
        val raw = File(directory, "kernel.raw")
        val patchedRaw = File(directory, "kernel.patched.raw")
        val component = File(directory, "kernel.component")
        val log = File(directory, "patch.log")
        val image = File(directory, "maplesu-patched.img")
        val evidence = File(directory, "candidate.json")
        var complete = false
        try {
            cancelled()
            onLog(context.getString(R.string.install_patch_reading))
            val source = BootImageInspector.inspect(sourceBoot)
            check(source.headerVersion in 0..4 && source.kernelSize > 0) { "PATCH_BOOT_KERNEL_REQUIRED" }
            if (findVerifiedCandidate(source.sha256) != null) throw AlreadyPatchedImageException()
            val before = decodeIdentity(sourceBoot, source, raw)
            onLog(context.getString(R.string.install_patch_applying))
            val editCount = runPatcher(raw, patchedRaw, credential, log)
            cancelled()
            val patched = encodePatchedKernel(patchedRaw, component, sourceBoot, source, before)
            onLog(context.getString(R.string.install_patch_rebuilding))
            val rebuilt = BootImageRebuilder.rebuild(sourceBoot, component, image)
            check(rebuilt.source.sha256 == source.sha256 && rebuilt.kernelChanged) { "PATCH_SOURCE_CHANGED" }
            onLog(context.getString(R.string.install_patch_verifying))
            val after = decodeIdentity(image, rebuilt.image)
            check(after == patched && after.release == before.release &&
                BootImageInspector.inspect(sourceBoot).sha256 == source.sha256) { "PATCH_READBACK_MISMATCH" }
            val json = JSONObject()
                .put("schemaVersion", 1)
                .put("operation", "MAPLESU_LITE_BOOT_PATCH")
                .put("source", JSONObject(source.toJson()))
                .put("image", JSONObject(rebuilt.image.toJson()))
                .put("rebuild", JSONObject(rebuilt.toJson()))
                .put("kernelRelease", after.release)
                .put("sourceKernelSha256", before.sha256)
                .put("patchedKernelSha256", after.sha256)
                .put("patchEdits", editCount)
                .put("credentialContract", "MAPLESU_LITE_STDIN48_SLOT47_NUL")
                .put("credentialInitialized", true)
                .put("sourceUnchanged", true)
                .put("candidateVerified", true)
                .put("runtimeVerified", false)
            writeSynced(evidence, json.toString().toByteArray(Charsets.UTF_8))
            cancelled()
            complete = true
            Candidate(image, evidence, source.sha256, rebuilt.image.sha256, after.release, after.sha256)
        } finally {
            listOf(raw, patchedRaw, component, log).forEach { it.delete() }
            if (!complete) {
                image.delete()
                evidence.delete()
                directory.delete()
            }
        }
    }

    private fun runPatcher(input: File, output: File, credential: ByteArray, log: File): Int {
        val process = ProcessBuilder(executable.absolutePath, input.absolutePath, output.absolutePath)
            .redirectErrorStream(true).redirectOutput(log).start()
        try {
            process.outputStream.use {
                it.write(ByteBuffer.allocate(4).putInt(48).array())
                it.write(credential)
            }
            if (!process.waitFor(180, TimeUnit.SECONDS)) throw IOException("PATCH_TIMEOUT")
            if (process.exitValue() != 0) throw IOException("LITE_PATCH_FAILED")
            check(log.length() <= 16L * 1024 * 1024) { "PATCH_LOG_SIZE_LIMIT" }
            val results = Regex("(?m)^MAPLESU_PATCH_OK edits=([0-9]+)\\r?$")
                .findAll(log.readText()).toList()
            check(results.size == 1) { "PATCH_RESULT_INVALID" }
            return results.single().groupValues[1].toInt().also { check(it > 0) { "PATCH_RESULT_INVALID" } }
        } finally {
            if (process.isAlive) process.destroyForcibly()
            runCatching { process.outputStream.close() }
            runCatching { process.inputStream.close() }
            runCatching { process.errorStream.close() }
        }
    }

    private data class KernelIdentity(val size: Int, val sha256: String, val release: String)

    private fun decodeIdentity(
        image: File, report: BootImageInspector.Report, rawOutput: File? = null,
    ): KernelIdentity {
        val encoded = readKernelComponent(image, report)
        val raw = KernelCompression.decode(encoded, report.compression, KernelCompression.MAX_KERNEL_BYTES)
        check(raw.size >= 64 && raw.copyOfRange(56, 60).contentEquals(byteArrayOf(65, 82, 77, 100))) {
            "RAW_ARM64_REQUIRED"
        }
        val identity = KernelIdentity(raw.size, BootImageRoundTrip.sha256(raw), kernelRelease(raw))
        if (rawOutput != null) writeSynced(rawOutput, raw)
        return identity
    }

    private fun encodePatchedKernel(
        input: File, output: File, sourceBoot: File, report: BootImageInspector.Report, source: KernelIdentity,
    ): KernelIdentity {
        check(input.length() == source.size.toLong()) { "PATCH_KERNEL_SIZE_CHANGED" }
        val bytes = input.readBytes()
        val identity = KernelIdentity(bytes.size, BootImageRoundTrip.sha256(bytes), kernelRelease(bytes))
        check(identity.sha256 != source.sha256 && identity.release == source.release) { "PATCH_KERNEL_INVALID" }
        writeSynced(output, KernelCompression.encodeKernelComponent(bytes, readKernelComponent(sourceBoot, report), report.compression))
        return identity
    }

    private fun readKernelComponent(image: File, report: BootImageInspector.Report): ByteArray {
        check(report.kernelSize in 64..KernelCompression.MAX_KERNEL_BYTES.toLong()) { "KERNEL_SIZE_LIMIT" }
        val encoded = ByteArray(report.kernelSize.toInt())
        RandomAccessFile(image, "r").use { it.seek(report.kernelOffset); it.readFully(encoded) }
        return encoded
    }

    private fun kernelRelease(bytes: ByteArray): String {
        val marker = "Linux version ".toByteArray(Charsets.US_ASCII)
        var result: String? = null
        for (offset in 0..bytes.size - marker.size) {
            if (bytes[offset] != marker[0] || !marker.indices.all { bytes[offset + it] == marker[it] }) continue
            val start = offset + marker.size
            var end = start
            while (end < bytes.size && end - start < 128) {
                val c = bytes[end].toInt().toChar()
                if (c !in '0'..'9' && c !in 'A'..'Z' && c !in 'a'..'z' && c !in ".-_+") break
                end++
            }
            if (end == start) continue
            val release = String(bytes, start, end - start, Charsets.US_ASCII)
            check(result == null || result == release) { "KERNEL_RELEASE_AMBIGUOUS" }
            result = release
        }
        return checkNotNull(result) { "KERNEL_RELEASE_MISSING" }
    }

    private fun writeSynced(file: File, bytes: ByteArray) {
        file.outputStream().use { it.write(bytes); it.fd.sync() }
    }

    private fun cancelled() {
        if (Thread.currentThread().isInterrupted) throw IOException("CANCELLED")
    }

    companion object { private val operationLock = Any() }
}
