package dev.maplesu.ghostlock.extract

import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.net.HttpURLConnection
import java.net.URL

/**
 * Random-access byte source. The user-triggered OTA path is a sequence of range
 * reads (never a full-file download), so the extractor can pull only the
 * payload metadata and the partitions it needs.
 */
interface RangeSource {
    /** Total length in bytes. */
    val length: Long

    /** Read up to [size] bytes at [start]; null when the range cannot be served. */
    fun read(start: Long, size: Int): ByteArray?

    /** Human-readable identity recorded as provenance. */
    val identity: String
}

/** Local file source (host tests and a locally picked OTA zip). */
class FileRangeSource(private val file: File) : RangeSource {
    override val length: Long get() = file.length()
    override val identity: String get() = file.absolutePath

    override fun read(start: Long, size: Int): ByteArray? {
        if (size <= 0) return ByteArray(0)
        if (start < 0 || start >= length) return null
        val wanted = minOf(size.toLong(), length - start).toInt()
        return try {
            RandomAccessFile(file, "r").use { handle ->
                handle.seek(start)
                val buffer = ByteArray(wanted)
                var read = 0
                while (read < wanted) {
                    val count = handle.read(buffer, read, wanted - read)
                    if (count < 0) break
                    read += count
                }
                buffer.copyOf(read)
            }
        } catch (error: IOException) {
            null
        }
    }
}

/**
 * HTTP Range reader over [HttpURLConnection], ported from GhostLock-App
 * `data/ota/HttpRangeReader.kt` (Apache-2.0, commit 437b3b2).
 *
 * It keeps the reference's redirect handling (6 hops), its rule that a `200`
 * response to a non-zero range means the server ignored `Range` and cannot be
 * trusted, and its short `Dalvik` user agent. Only the user-triggered parse path
 * constructs this class.
 */
class HttpRangeSource(
    rawUrl: String,
    private val connectTimeoutMs: Int = 15000,
    private val readTimeoutMs: Int = 30000,
    private val userAgent: String =
        "Dalvik/2.1.0 (Linux; W; Android 17; Android Build/CP2A.260605.016)",
    /** Hard upper bound for the remote file; an OTA larger than this is refused. */
    private val maximumBytes: Long = MAX_REMOTE_BYTES,
    /** Hard upper bound for one range request. */
    private val maximumRead: Int = MAX_RANGE_READ,
) : RangeSource {
    private val url: String = normalize(rawUrl)
    private var cachedLength: Long = -1

    override val identity: String get() = url

    override val length: Long
        get() {
            if (cachedLength >= 0) return cachedLength
            val measured = try {
                val connection = openConnection(mapOf("Range" to "bytes=0-0"))
                try {
                    var value = -1L
                    val contentRange = connection.getHeaderField("Content-Range")
                    if (contentRange != null) {
                        val slash = contentRange.lastIndexOf('/')
                        if (slash != -1) {
                            value = contentRange.substring(slash + 1).trim().toLongOrNull() ?: -1L
                        }
                    }
                    if (value <= 0) value = connection.contentLengthLong
                    value
                } finally {
                    connection.disconnect()
                }
            } catch (error: IOException) {
                -1L
            }
            if (measured <= 0) throw IOException("cannot determine remote file length")
            if (measured > maximumBytes) throw IOException("remote file exceeds size bound")
            cachedLength = measured
            return measured
        }

    override fun read(start: Long, size: Int): ByteArray? {
        if (size == 0) return ByteArray(0)
        if (size < 0 || start < 0 || size > maximumRead) return null
        return try {
            val end = start + size - 1
            val connection = openConnection(mapOf("Range" to "bytes=$start-$end"))
            try {
                val code = connection.responseCode
                // A 200 to a non-zero range means the server ignored Range and
                // sent from offset 0; the reference refuses that outright.
                if (code == 200 && start > 0) return null
                if (code !in 200..299) return null
                val stream = connection.inputStream
                val buffer = ByteArray(size)
                var total = 0
                while (total < size) {
                    val count = stream.read(buffer, total, size - total)
                    if (count < 0) break
                    total += count
                }
                if (total == size) buffer else buffer.copyOf(total)
            } finally {
                connection.disconnect()
            }
        } catch (error: IOException) {
            null
        }
    }

    private fun openConnection(headers: Map<String, String>): HttpURLConnection {
        var current = url
        var redirects = 0
        while (redirects < 6) {
            val parsed = URL(current)
            val connection = parsed.openConnection() as HttpURLConnection
            connection.connectTimeout = connectTimeoutMs
            connection.readTimeout = readTimeoutMs
            connection.instanceFollowRedirects = true
            connection.setRequestProperty("User-Agent", userAgent)
            for ((key, value) in headers) connection.setRequestProperty(key, value)
            connection.connect()
            val code = connection.responseCode
            if (code in 301..303 || code in 307..308) {
                val location = connection.getHeaderField("Location")
                connection.disconnect()
                if (!location.isNullOrBlank()) {
                    current = if (location.startsWith("http://", ignoreCase = true) ||
                        location.startsWith("https://", ignoreCase = true)
                    ) location else URL(parsed, location).toString()
                    redirects++
                    continue
                }
            }
            return connection
        }
        throw IOException("too many redirects: $url")
    }

    companion object {
        /** 8 GiB: larger than any published Android full OTA. */
        const val MAX_REMOTE_BYTES = 8L * 1024 * 1024 * 1024
        const val MAX_RANGE_READ = 64 * 1024 * 1024

        /** HTTP(S) only; anything else is refused before a socket is opened. */
        fun isSupported(raw: String): Boolean {
            val trimmed = raw.trim()
            return (trimmed.startsWith("http://", ignoreCase = true) ||
                trimmed.startsWith("https://", ignoreCase = true)) &&
                trimmed.length in 8..2048 && !trimmed.contains(' ')
        }

        private fun normalize(raw: String): String {
            val trimmed = raw.trim()
            if (!isSupported(trimmed)) throw IOException("not an http(s) URL")
            return trimmed
        }
    }
}
