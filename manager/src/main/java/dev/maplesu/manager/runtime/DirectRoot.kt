package dev.maplesu.manager.runtime

import android.content.Context
import java.io.File

/**
 * One short-lived privileged operation, with no resident service behind it.
 *
 * <p>Every Manager operation that needs root (delivery, withdrawal, a status read) runs
 * as a single `libmaplesu_runtime.so --direct-stdin` process: the credential goes in on
 * stdin in the runtime's 4+48 frame, the process admits itself with `get_root`, runs one
 * fixed script and exits. Nothing is left running, no Binder endpoint is created and no
 * libsu connection is held - so an operation cannot be broken by, and cannot itself keep
 * alive, the resident chain that this migration is removing.
 *
 * <p>The credential never appears in argv, the environment or a log line, and the buffer
 * is cleared as soon as the frame has been written.
 */
object DirectRoot {
    data class Result(val code: Int, val output: String)

    fun run(context: Context, script: String): Result {
        val application = context.applicationContext
        val runtime = File(application.applicationInfo.nativeLibraryDir, "libmaplesu_runtime.so")
        if (!runtime.isFile || !runtime.canExecute()) return Result(-1, "runtime image unavailable")
        val credential = runCatching { MapleSuCredentialStore(application).load() }.getOrNull()
            ?: return Result(-1, "no paired credential")
        try {
            val process = ProcessBuilder(runtime.absolutePath, "--direct-stdin", "--",
                "/system/bin/sh", "-c", script).redirectErrorStream(true).start()
            process.outputStream.use { input ->
                input.write(byteArrayOf(0, 0, 0, 48))
                input.write(credential)
                input.flush()
            }
            val output = process.inputStream.bufferedReader().use { it.readText() }
            return Result(process.waitFor(), output)
        } catch (error: Exception) {
            return Result(-1, "direct operation failed: ${error.javaClass.simpleName}")
        } finally {
            credential.fill(0)
        }
    }
}
