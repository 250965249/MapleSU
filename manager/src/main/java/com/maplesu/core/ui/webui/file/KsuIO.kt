package com.maplesu.core.ui.webui.file

import android.webkit.JavascriptInterface
import com.maplesu.core.ui.util.createRootShell
import com.topjohnwu.superuser.Shell
import com.topjohnwu.superuser.io.SuFile
import com.maplesu.core.ui.webui.cleanupWebUiResources
import java.io.BufferedOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CompletableFuture

const val TAG = "KsuIO"

class KsuIO(
    private val shellFactory: () -> Shell = { createRootShell(true) },
    private val pageCurrent: () -> Boolean = { true },
) {
    private companion object {
        const val KSU_IO_VERSION = 1
        const val MAX_OPEN_STREAMS = 50
    }

    internal val openInputStreams = ConcurrentHashMap<String, ManagedInputStream>()
    internal val openOutputStreams = ConcurrentHashMap<String, OutputStream>()

    private val fileOutputStream = FileOutputStreamInterface(this)
    private val fileInputStream = FileInputStreamInterface(this)
    private val randomAccessFile = RandomAccessFileInterface(this)
    private val destroyed = AtomicBoolean(false)
    private var fileShell: Shell? = null
    private var openingShell: CompletableFuture<Shell>? = null
    private var openingStreams = 0

    internal fun isOpen(): Boolean = !destroyed.get() && pageCurrent()

    internal fun file(path: String): SuFile {
        val (pending, create) = synchronized(this) {
            check(isOpen()) { "WebUI page closed" }
            fileShell?.let { shell -> return SuFile(path).also { it.setShell(shell) } }
            openingShell?.let { return@synchronized it to false }
            CompletableFuture<Shell>().also { openingShell = it } to true
        }
        if (create) {
            runCatching(shellFactory).fold(onSuccess = { created ->
                val accepted = synchronized(this) {
                    if (openingShell === pending) {
                        openingShell = null
                        if (isOpen()) {
                            fileShell = created
                            true
                        } else false
                    } else false
                }
                if (accepted) pending.complete(created) else {
                    pending.completeExceptionally(IllegalStateException("WebUI page closed"))
                    runCatching { created.close() }
                }
            }, onFailure = { error ->
                synchronized(this) { if (openingShell === pending) openingShell = null }
                pending.completeExceptionally(error)
            })
        }
        val shell = pending.get()
        check(isOpen()) { "WebUI page closed" }
        return SuFile(path).also { it.setShell(shell) }
    }

    private fun <T : AutoCloseable> openStream(
        streams: MutableMap<String, T>,
        factory: () -> T,
    ): String {
        synchronized(this) {
            check(canOpenStream()) { "WebUI stream limit or closed page" }
            openingStreams++
        }
        val stream = try {
            factory()
        } catch (error: Throwable) {
            synchronized(this) { openingStreams-- }
            throw error
        }
        val id = UUID.randomUUID().toString()
        val accepted = synchronized(this) {
            openingStreams--
            if (isOpen()) {
                streams[id] = stream
                true
            } else false
        }
        if (!accepted) {
            runCatching { stream.close() }
            error("WebUI page closed")
        }
        return id
    }

    internal fun inputStream(id: String): ManagedInputStream? =
        if (isOpen()) openInputStreams[id] else null

    internal fun outputStream(id: String): OutputStream? =
        if (isOpen()) openOutputStreams[id] else null

    @JavascriptInterface
    fun version(): Int = KSU_IO_VERSION

    @JavascriptInterface
    fun File(path: String): FileInterface = FileInterface(path, this)

    @JavascriptInterface
    fun FileInputStream(): FileInputStreamInterface = fileInputStream

    @JavascriptInterface
    fun FileOutputStream(): FileOutputStreamInterface = fileOutputStream

    @JavascriptInterface
    fun RandomAccessFile(): RandomAccessFileInterface = randomAccessFile

    /**
     * Check if we can open a new stream without exceeding resource limits.
     * Returns true if under limit, false otherwise.
     */
    @Synchronized
    internal fun canOpenStream(): Boolean {
        return isOpen() && openInputStreams.size + openOutputStreams.size + openingStreams < MAX_OPEN_STREAMS
    }

    internal fun openInput(factory: () -> InputStream): String =
        openStream(openInputStreams) { ManagedInputStream(factory()) }

    internal fun openOutput(factory: () -> OutputStream): String =
        openStream(openOutputStreams) {
            BufferedOutputStream(factory(), ManagedInputStream.MAX_CHUNK_SIZE)
        }

    @Synchronized
    internal fun <T> whileOpen(action: () -> T): T {
        check(isOpen()) { "WebUI page closed" }
        return action()
    }

    fun destroy() {
        if (!destroyed.compareAndSet(false, true)) return
        val (shell, pending) = synchronized(this) {
            val owned = fileShell.also { fileShell = null }
            val opening = openingShell.also { openingShell = null }
            owned to opening
        }
        pending?.completeExceptionally(IllegalStateException("WebUI page closed"))
        cleanupWebUiResources {
            try {
                shell?.close()
            } finally {
                fileInputStream.closeAll()
                fileOutputStream.closeAll()
                randomAccessFile.closeAll()
            }
        }
    }
}
