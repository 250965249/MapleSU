package com.maplesu.core.ui.webui.file

import android.util.Base64
import android.util.Log
import android.webkit.JavascriptInterface
import com.topjohnwu.superuser.io.SuFileInputStream
import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.atomic.AtomicBoolean

class FileInputStreamInterface(private val owner: KsuIO) {
    @JavascriptInterface
    fun open(path: String): String = runCatching {
        owner.openInput { SuFileInputStream.open(owner.file(path)) }
    }.onFailure { Log.e(TAG, "FileInputStream open failed", it) }.getOrElse { "" }

    @JavascriptInterface
    fun read(id: String): String = runCatching {
        val stream = owner.inputStream(id) ?: return ""
        val bytesRead = stream.readInto()
        if (bytesRead > 0) {
            Base64.encodeToString(stream.buffer(), 0, bytesRead, Base64.NO_WRAP)
        } else {
            ""
        }
    }.onFailure { Log.e(TAG, "FileInputStream read failed", it) }.getOrElse { "" }

    @JavascriptInterface
    fun read(id: String, maxBytes: Int): String = runCatching {
        val stream = owner.inputStream(id) ?: return ""
        val bytesRead = stream.readInto(maxBytes)
        if (bytesRead > 0) {
            Base64.encodeToString(stream.buffer(), 0, bytesRead, Base64.NO_WRAP)
        } else {
            ""
        }
    }.onFailure { Log.e(TAG, "FileInputStream read(maxBytes) failed", it) }.getOrElse { "" }

    @JavascriptInterface
    fun available(id: String): Int = runCatching {
        val stream = owner.inputStream(id) ?: return 0
        stream.available()
    }.getOrDefault(0)

    @JavascriptInterface
    fun close(id: String): Boolean {
        val stream = owner.openInputStreams.remove(id) ?: return false
        return runCatching {
            stream.close()
            true
        }.getOrElse {
            Log.e(TAG, "FileInputStream close failed", it)
            false
        }
    }

    fun closeAll() {
        while (true) {
            val entry = owner.openInputStreams.entries.firstOrNull() ?: break
            val id = entry.key
            val stream = entry.value
            if (!owner.openInputStreams.remove(id, stream)) {
                continue
            }
            runCatching {
                stream.close()
            }.onFailure { Log.e(TAG, "closeAll failed for $id", it) }
        }
    }
}

internal class ManagedInputStream(
    private val inputStream: InputStream,
    private val defaultChunkSize: Int = DEFAULT_CHUNK_SIZE,
    private val maxChunkSize: Int = MAX_CHUNK_SIZE,
) : AutoCloseable {
    private val stream = BufferedInputStream(inputStream, maxChunkSize)
    private val closed = AtomicBoolean(false)
    private var buffer = ByteArray(defaultChunkSize)

    @Synchronized
    fun readInto(maxBytes: Int = defaultChunkSize): Int {
        checkOpen()
        val requestedSize = maxBytes.coerceIn(1, maxChunkSize)
        if (buffer.size < requestedSize) {
            buffer = ByteArray(requestedSize)
        }
        return stream.read(buffer, 0, requestedSize)
    }

    @Synchronized
    fun buffer(): ByteArray = buffer

    @Synchronized
    fun available(): Int {
        checkOpen()
        return stream.available()
    }

    private fun checkOpen() {
        if (closed.get()) throw IOException("Stream closed")
    }

    override fun close() {
        // Closing the source must not wait for a read holding the buffer lock.
        if (closed.compareAndSet(false, true)) inputStream.close()
    }

    companion object {
        const val DEFAULT_CHUNK_SIZE = 8 * 1024
        const val MAX_CHUNK_SIZE = 64 * 1024
    }
}
