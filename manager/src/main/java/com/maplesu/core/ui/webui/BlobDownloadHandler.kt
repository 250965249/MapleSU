package com.maplesu.core.ui.webui

import android.net.Uri
import android.util.Base64
import android.util.Log
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FilterInputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/** A page owns its spooled downloads, including streams already handed to WebView. */
class BlobDownloadHandler {
    companion object {
        internal const val HOST = "blob-download.kernelsu.internal"
        private const val STALE_MS = 5 * 60 * 1000L
    }

    private data class PendingDownload(
        val fileName: String,
        val mimeType: String?,
        val tempFile: File,
        val output: OutputStream,
        val createdAt: Long = System.nanoTime(),
        var completed: Boolean = false,
        var input: InputStream? = null,
    )

    private val pending = mutableMapOf<String, PendingDownload>()
    private val destroyed = AtomicBoolean(false)

    private fun id(value: String): String? {
        if (!value.contains('/')) return value
        val uri = runCatching { Uri.parse(value) }.getOrNull() ?: return null
        if (uri.scheme != "https" || uri.host != HOST || uri.userInfo != null ||
            (uri.port != -1 && uri.port != 443)) return null
        return uri.path?.removePrefix("/")?.takeIf { it.isNotEmpty() && '/' !in it }
    }

    @Synchronized
    fun registerBlobDownload(fileName: String, mimeType: String?, cacheDir: File): String {
        check(!destroyed.get()) { "WebUI page closed" }
        val now = System.nanoTime()
        pending.filterValues { now - it.createdAt > STALE_MS * 1_000_000L }
            .keys.toList().forEach(::closeDownload)
        val tempFile = File.createTempFile("maplesu-blob-", ".download", cacheDir)
        val output = try { tempFile.outputStream().buffered(64 * 1024) }
            catch (error: Exception) { tempFile.delete(); throw error }
        val downloadId = UUID.randomUUID().toString()
        pending[downloadId] = PendingDownload(
            sanitizeWebUIDownloadFileName(fileName), mimeType, tempFile, output,
        )
        return "https://$HOST/$downloadId"
    }

    @Synchronized
    fun writeChunk(downloadId: String, base64Chunk: String): Boolean {
        val key = id(downloadId) ?: return false
        val download = pending[key] ?: return false
        if (destroyed.get() || download.completed) return false
        return try {
            download.output.write(Base64.decode(base64Chunk, Base64.DEFAULT))
            true
        } catch (error: Exception) {
            Log.e("BlobDownloadHandler", "Failed to write download chunk", error)
            closeDownload(key)
            false
        }
    }

    @Synchronized
    fun completeDownload(downloadId: String): Boolean {
        val key = id(downloadId) ?: return false
        val download = pending[key] ?: return false
        if (destroyed.get() || download.completed) return false
        return try {
            download.output.flush()
            download.output.close()
            download.completed = true
            true
        } catch (error: Exception) {
            Log.e("BlobDownloadHandler", "Failed to complete download", error)
            closeDownload(key)
            false
        }
    }

    @Synchronized
    fun cancelDownload(downloadId: String) {
        id(downloadId)?.let(::closeDownload)
    }

    data class CompletedDownload(val fileName: String, val mimeType: String?, val size: Long, val input: InputStream)

    @Synchronized
    fun takeDownload(downloadId: String): CompletedDownload? {
        val key = id(downloadId) ?: return null
        val download = pending[key] ?: return null
        if (destroyed.get() || !download.completed || download.input != null) return null
        val input = try { FileInputStream(download.tempFile) }
            catch (_: Exception) { closeDownload(key); return null }
        download.input = input
        val stream = object : FilterInputStream(input) {
            override fun close() {
                try { super.close() } finally { closeDownload(key) }
            }
        }
        return CompletedDownload(download.fileName, download.mimeType, download.tempFile.length(), stream)
    }

    @Synchronized
    fun shouldInterceptRequest(request: WebResourceRequest): WebResourceResponse? {
        val uri = request.url
        if (uri.scheme != "https" || uri.host != HOST) return null
        val download = takeDownload(uri.toString()) ?: return errorResponse("Download is not ready")
        return WebResourceResponse(download.mimeType ?: "application/octet-stream", null, download.input).apply {
            responseHeaders = mapOf(
                "Content-Disposition" to ("attachment; filename=\"" + download.fileName.replace("\"", "_") + "\""),
                "Access-Control-Allow-Origin" to "*",
                "Cache-Control" to "no-store",
            )
        }
    }

    @Synchronized
    private fun closeDownload(key: String) {
        pending.remove(key)?.let {
            runCatching { it.output.close() }
            runCatching { it.input?.close() }
            runCatching { it.tempFile.delete() }
        }
    }

    @Synchronized
    fun cleanup() = pending.keys.toList().forEach(::closeDownload)

    fun destroy() {
        if (!destroyed.compareAndSet(false, true)) return
        cleanupWebUiResources { cleanup() }
    }

    private fun errorResponse(message: String) = WebResourceResponse(
        "text/plain", "utf-8", 404, "Not Found", emptyMap(),
        ByteArrayInputStream(message.toByteArray(Charsets.UTF_8)),
    )
}

