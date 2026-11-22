package dev.maplesu.manager

import android.content.Context
import android.net.Uri
import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.BootImageRebuilder
import dev.maplesu.image.BootImageRoundTrip
import dev.maplesu.image.KernelCompression
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/** Only app-private snapshots are analyzed. Never opens the selected document for writing. */
class ImageRepository(private val context: Context) {
    private val directory = File(context.filesDir, "images").apply { mkdirs() }
    private val imported = File(directory, "imported.img")
    private val roundTripReport = File(directory, "roundtrip.json")

    fun restore(): ImageResult? = synchronized(operationLock) {
        // A killed import never becomes the current image until its final atomic move.
        directory.listFiles { file -> file.name.endsWith(".pending") }?.forEach { it.delete() }
        if (!imported.isFile) return null
        val report = BootImageInspector.inspect(imported)
        val previous = if (roundTripReport.isFile) {
            try {
                val json = org.json.JSONObject(roundTripReport.readText())
                val decodedSize = json.opt("decodedKernelSize") as? Int
                val valid = json.opt("schemaVersion") == 1 && json.opt("operation") == "LOSSLESS_ROUNDTRIP" &&
                    json.opt("codecRoundTripVerified") == true && json.opt("containerByteIdentical") == true &&
                    json.opt("sourceUnchanged") == true && json.opt("flashableCandidate") == false &&
                    decodedSize != null && decodedSize in 1..KernelCompression.MAX_KERNEL_BYTES &&
                    (json.opt("decodedKernelSha256") as? String)?.matches(Regex("[0-9a-f]{64}")) == true &&
                    (json.opt("kernelRelease") as? String)?.isNotEmpty() == true &&
                    json.getJSONObject("image").getString("sha256") == report.sha256
                if (valid) json.toString() else null
            } catch (_: org.json.JSONException) {
                // A damaged cache does not invalidate the independently checked source image.
                null
            }
        } else null
        return ImageResult(report, previous)
    }

    fun import(uri: Uri): ImageResult = synchronized(operationLock) {
        context.contentResolver.openInputStream(uri)?.use { importStream(it) }
            ?: throw IOException("DOCUMENT_READ_FAILED")
    }

    internal fun importAndVerifyInstalledBoot(
        input: InputStream, size: Long, sha256: String, expectedKernelRelease: String,
    ): ImageResult =
        synchronized(operationLock) {
            require(size in 1..MAX_IMAGE_BYTES && sha256.matches(Regex("[0-9a-f]{64}")) &&
                expectedKernelRelease.isNotBlank())
            importStream(input, size, sha256, expectedKernelRelease)
        }

    internal fun importAndVerifyInstalledPartition(input: InputStream, size: Long, sha256: String,
                                                   partition: String, kernelRelease: String): ImageResult =
        synchronized(operationLock) {
            require(partition in setOf("boot", "init_boot") && size in 1..MAX_IMAGE_BYTES &&
                sha256.matches(Regex("[0-9a-f]{64}")))
            importStream(input, size, sha256, kernelRelease.takeIf { partition == "boot" }, partition)
        }

    private fun importStream(
        input: InputStream, expectedSize: Long? = null, expectedSha256: String? = null,
        expectedKernelRelease: String? = null,
        expectedPartition: String? = null,
    ): ImageResult {
        val pending = File.createTempFile("import-", ".pending", directory)
        var pendingReport: File? = null
        try {
            pending.outputStream().use { output ->
                val buffer = ByteArray(64 * 1024)
                var total = 0L
                while (true) {
                    if (Thread.currentThread().isInterrupted) throw IOException("CANCELLED")
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    if (expectedSize != null && total > expectedSize) throw IOException("INSTALLER_IMAGE_CHANGED")
                    if (total > MAX_IMAGE_BYTES) throw IOException("IMAGE_SIZE_LIMIT")
                    output.write(buffer, 0, count)
                }
                if (expectedSize != null && total != expectedSize) throw IOException("INSTALLER_IMAGE_CHANGED")
                output.fd.sync()
            }
            val report = BootImageInspector.inspect(pending)
            if (expectedPartition != null && (if (expectedPartition == "boot") report.kernelSize <= 0L
                    else report.headerVersion != 4 || report.kernelSize != 0L || report.ramdiskSize <= 0L)) {
                throw IOException("INSTALLER_IMAGE_PARTITION_MISMATCH")
            }
            if (expectedSha256 != null && report.sha256 != expectedSha256) throw IOException("INSTALLER_IMAGE_CHANGED")
            val verified = if (expectedKernelRelease != null) {
                BootImageRoundTrip.verify(pending, context.cacheDir).also {
                    if (it.image.sha256 != report.sha256 || it.kernelRelease != expectedKernelRelease) {
                        throw IOException("INSTALLER_IMAGE_CHANGED")
                    }
                }
            } else null
            val roundTripJson = verified?.toJson()
            if (roundTripJson != null) {
                pendingReport = File.createTempFile("roundtrip-", ".pending", directory)
                pendingReport.outputStream().use { stream ->
                    stream.write(roundTripJson.toByteArray(Charsets.UTF_8))
                    stream.fd.sync()
                }
            }
            if (Thread.currentThread().isInterrupted) throw IOException("CANCELLED")
            Files.move(pending.toPath(), imported.toPath(), StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING)
            if (pendingReport != null) {
                Files.move(pendingReport.toPath(), roundTripReport.toPath(), StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING)
            } else roundTripReport.delete()
            return ImageResult(report, roundTripJson)
        } finally {
            pending.delete()
            pendingReport?.delete()
        }
    }

    fun verify(): ImageResult = synchronized(operationLock) {
        val report = BootImageRoundTrip.verify(imported, context.cacheDir)
        val pending = File.createTempFile("roundtrip-", ".pending", directory)
        try {
            pending.outputStream().use { stream ->
                stream.write(report.toJson().toByteArray(Charsets.UTF_8))
                stream.fd.sync()
            }
            if (Thread.currentThread().isInterrupted) throw IOException("CANCELLED")
            Files.move(pending.toPath(), roundTripReport.toPath(), StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING)
        } finally {
            pending.delete()
        }
        return ImageResult(report.image, report.toJson())
    }

    /** Keep the selected source stable throughout patching and any installation transaction. */
    internal fun <T> withCurrentImage(expectedSha256: String, consume: (File) -> T): T =
        synchronized(operationLock) {
            check(BootImageInspector.inspect(imported).sha256 == expectedSha256) { "PATCH_SOURCE_CHANGED" }
            consume(imported)
        }

    /** Component-tool backend only. The callback owns export; no install candidate is issued. */
    internal fun <T> withRebuiltKernel(kernelUri: Uri, consume: (File, BootImageRebuilder.Report) -> T): T =
        synchronized(operationLock) {
            val kernel = File.createTempFile("kernel-", ".pending", directory)
            val output = File(directory, "rebuild-${java.util.UUID.randomUUID()}.pending")
            try {
                val input = context.contentResolver.openInputStream(kernelUri)
                    ?: throw IOException("DOCUMENT_READ_FAILED")
                input.use { stream ->
                    kernel.outputStream().use { destination ->
                        val buffer = ByteArray(64 * 1024)
                        var total = 0L
                        while (true) {
                            if (Thread.currentThread().isInterrupted) throw IOException("CANCELLED")
                            val count = stream.read(buffer)
                            if (count < 0) break
                            total += count
                            if (total > KernelCompression.MAX_KERNEL_BYTES) throw IOException("REPLACEMENT_KERNEL_SIZE_LIMIT")
                            destination.write(buffer, 0, count)
                        }
                        destination.fd.sync()
                    }
                }
                val report = BootImageRebuilder.rebuildV4(imported, kernel, output)
                consume(output, report)
            } finally {
                output.delete()
                kernel.delete()
            }
        }

    fun export(uri: Uri, json: String) {
        context.contentResolver.openOutputStream(uri, "wt")?.use {
            it.write(json.toByteArray(Charsets.UTF_8))
        } ?: throw IOException("DOCUMENT_WRITE_FAILED")
    }

    companion object {
        const val MAX_IMAGE_BYTES = 512L * 1024 * 1024
        // Repository instances share one app-private image and its pending-file directory.
        private val operationLock = Any()
    }
}

data class ImageResult(val report: BootImageInspector.Report, val roundTripJson: String? = null)
