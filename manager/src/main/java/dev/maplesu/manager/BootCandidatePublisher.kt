package dev.maplesu.manager

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Environment
import android.provider.MediaStore
import java.io.File
import java.io.IOException
import java.security.MessageDigest

/** Publish only a complete, independently read-back copy of the verified candidate. */
internal object BootCandidatePublisher {
    fun publish(context: Context, image: File, expectedSha256: String,
                name: String = "maplesu-patched-${expectedSha256.take(12)}.img"): String =
        publishAll(context, linkedMapOf(name to Image(image, expectedSha256))).getValue(name)

    data class Image(val file: File, val sha256: String)

    /** Stage and read back the entire AVB set before publishing; undo all rows on any failure. */
    fun publishAll(context: Context, images: Map<String, Image>): Map<String, String> {
        require(images.isNotEmpty() && images.keys.all { it.matches(Regex("[A-Za-z0-9_.-]+\\.img")) }) { "CANDIDATE_EXPORT_NAME_INVALID" }
        val resolver = context.contentResolver
        val rows = linkedMapOf<String, Uri>()
        var complete = false
        try {
            images.forEach { (name, image) ->
                val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, name)
                    put(MediaStore.Downloads.MIME_TYPE, "application/octet-stream")
                    put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                    put(MediaStore.Downloads.IS_PENDING, 1)
                }) ?: throw IOException("CANDIDATE_EXPORT_CREATE_FAILED")
                rows[name] = uri
                val descriptor = resolver.openFileDescriptor(uri, "w")
                    ?: throw IOException("CANDIDATE_EXPORT_WRITE_FAILED")
                android.os.ParcelFileDescriptor.AutoCloseOutputStream(descriptor).use { output ->
                    image.file.inputStream().use { it.copyTo(output) }
                    output.fd.sync()
                }
                verify(context, uri, image.file.length(), image.sha256)
            }
            val paths = rows.mapValues { (_, uri) ->
                check(resolver.update(uri, ContentValues().apply {
                    put(MediaStore.Downloads.IS_PENDING, 0)
                }, null, null) == 1) { "CANDIDATE_EXPORT_PUBLISH_FAILED" }
                resolver.query(uri, arrayOf(
                    MediaStore.Downloads.DISPLAY_NAME,
                    MediaStore.Downloads.RELATIVE_PATH,
                ), null, null, null)?.use { cursor ->
                    check(cursor.moveToFirst()) { "CANDIDATE_EXPORT_LOCATION_FAILED" }
                    publicDownloadPath(
                        Environment.getExternalStorageDirectory(),
                        cursor.getString(cursor.getColumnIndexOrThrow(MediaStore.Downloads.RELATIVE_PATH)),
                        cursor.getString(cursor.getColumnIndexOrThrow(MediaStore.Downloads.DISPLAY_NAME)),
                    )
                } ?: throw IOException("CANDIDATE_EXPORT_LOCATION_FAILED")
            }
            complete = true
            return paths
        } finally {
            if (!complete) rows.values.forEach { uri -> runCatching { resolver.delete(uri, null, null) } }
        }
    }

    private fun verify(context: Context, uri: Uri, expectedSize: Long, expectedSha256: String) {
        val digest = MessageDigest.getInstance("SHA-256")
        var size = 0L
        context.contentResolver.openInputStream(uri)?.use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                if (Thread.currentThread().isInterrupted) throw IOException("CANCELLED")
                val count = input.read(buffer)
                if (count < 0) break
                size += count
                check(size <= expectedSize) { "CANDIDATE_EXPORT_SIZE_MISMATCH" }
                digest.update(buffer, 0, count)
            }
        } ?: throw IOException("CANDIDATE_EXPORT_READ_FAILED")
        check(size == expectedSize && digest.digest().joinToString("") { "%02x".format(it) } == expectedSha256) {
            "CANDIDATE_EXPORT_READBACK_MISMATCH"
        }
    }
}

internal fun publicDownloadPath(storageRoot: File, relativePath: String, actualName: String): String =
    File(File(storageRoot, relativePath), actualName).absolutePath
