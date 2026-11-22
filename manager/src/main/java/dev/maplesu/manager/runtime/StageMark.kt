package dev.maplesu.manager.runtime

import android.content.Context
import java.io.File
import java.io.FileOutputStream

/**
 * Per-attempt stage marks for the preparation path.
 *
 * The provider always returns a binder or throws, so a null answer from
 * `ContentResolver.call` means the call never completed. Guessing which stage
 * died is not acceptable, so each step appends one line to a device-protected
 * file that the App (and an observing shell) can read after the attempt. It
 * carries stage names only - no path, nonce, uid or credential.
 */
object StageMark {
    private const val FILE = "stage-marks"
    private const val LIMIT = 16 * 1024

    fun reset(context: Context) {
        runCatching { File(directory(context), FILE).delete() }
    }

    fun mark(context: Context, stage: String) {
        runCatching {
            val file = File(directory(context), FILE)
            if (file.length() > LIMIT) file.delete()
            FileOutputStream(file, true).use { output ->
                output.write((System.currentTimeMillis().toString() + " " + stage + "\n").toByteArray())
            }
            file.setReadable(true, false)
        }
    }

    /**
     * Bounded launcher output. libsu owns the shell's stdout/stderr, so anything
     * app_process prints is invisible unless it is teed here; a full pipe would
     * also block the launcher.
     */
    fun output(context: Context, text: String) {
        runCatching {
            val file = File(directory(context), "launcher-output")
            if (file.length() > LIMIT) return
            FileOutputStream(file, true).use { output -> output.write(text.toByteArray()) }
            file.setReadable(true, false)
        }
    }

    /** Diagnostic line for launcher-output, used by the proxy round-trips. */
    fun outputLine(text: String) {
        LINE_SINK?.invoke(text)
    }

    /** Set once by the launcher so proxy diagnostics reach the same file. */
    @Volatile
    var LINE_SINK: ((String) -> Unit)? = null

    fun readOutput(context: Context): String = runCatching {
        File(directory(context), "launcher-output").readText()
    }.getOrDefault("")

    fun read(context: Context): String = runCatching {
        File(directory(context), FILE).readText()
    }.getOrDefault("")

    private fun directory(context: Context): File {
        val protectedDirectory = context.createDeviceProtectedStorageContext().dataDir
        return protectedDirectory ?: context.filesDir.parentFile ?: context.filesDir
    }
}
