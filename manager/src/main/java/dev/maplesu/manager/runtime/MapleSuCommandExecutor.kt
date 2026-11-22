package dev.maplesu.manager.runtime

import android.content.Context
import com.topjohnwu.superuser.Shell
import java.io.File
import java.nio.ByteBuffer

/**
 * Management primitive. A su client must go through the authorization backend.
 * After start returns, the caller owns the Process, its streams, cancellation and waiting.
 */
class MapleSuCommandExecutor(context: Context) {
    private val applicationContext = context.applicationContext
    private val executable = File(context.applicationInfo.nativeLibraryDir, "libmaplesu_runtime.so")

    /** Blocking management adapter. The caller owns the returned Shell and must close it. */
    fun openShell(credential: ByteArray, globalMnt: Boolean = false): Shell {
        val process = start(credential, listOf("/system/bin/sh"), globalMnt = globalMnt)
        var shell: Shell? = null
        var accepted = false
        try {
            val opened = Shell.Builder.create().setContext(applicationContext).setTimeout(10).build(process)
            shell = opened
            check(opened.isAlive && opened.isRoot) { "MapleSU management shell is unavailable" }
            accepted = true
            return opened
        } finally {
            if (!accepted) {
                runCatching { shell?.close() }
                destroyMapleSuProcess(process)
            }
        }
    }

    fun start(
        credential: ByteArray,
        command: List<String>,
        directory: File? = null,
        environment: Map<String, String> = emptyMap(),
        globalMnt: Boolean = false,
    ): Process {
        requireValidMapleSuCredential(credential)
        val mode = if (globalMnt) "--maplesu-global-stdin" else "--maplesu-stdin"
        return writeMapleSuCredential(launch(mode, command, directory, environment), credential)
    }

    internal fun startModule(credential: ByteArray, command: List<String>, environment: Array<String>): Process {
        requireValidMapleSuCredential(credential)
        return writeMapleSuCredential(launch("--maplesu-stdin", command, null, emptyMap(), environment), credential)
    }

    internal fun startUnprivileged(
        command: List<String>,
        directory: File? = null,
        environment: Map<String, String> = emptyMap(),
    ): Process = launch("--unprivileged", command, directory, environment)

    private fun launch(
        mode: String,
        command: List<String>,
        directory: File?,
        environment: Map<String, String>,
        moduleEnvironment: Array<String>? = null,
    ): Process {
        require(command.isNotEmpty() && command[0].startsWith("/") && command.all { '\u0000' !in it }) {
            "Expected absolute executable and literal arguments"
        }
        check(executable.isFile && executable.canExecute()) { "MapleSU runtime is unavailable for this ABI" }
        return ProcessBuilder(listOf(executable.absolutePath, mode, "--") + command).apply {
            if (directory != null) directory(directory)
            if (moduleEnvironment != null) ModuleTaskEnvironment.replace(environment(), moduleEnvironment)
            environment().putAll(environment)
        }.start()
    }
}

/** On failure no Process reaches the caller, so this function retains cleanup ownership. */
internal fun writeMapleSuCredential(process: Process, credential: ByteArray): Process {
    try {
        process.outputStream.write(ByteBuffer.allocate(4).putInt(48).array())
        process.outputStream.write(credential)
        process.outputStream.flush()
        return process
    } catch (error: Exception) {
        destroyMapleSuProcess(process)
        throw error
    }
}

private fun destroyMapleSuProcess(process: Process) {
    // A failed destroy/close must not prevent the remaining streams from closing or hide the original error.
    runCatching { process.destroyForcibly() }
    runCatching { process.outputStream.close() }
    runCatching { process.inputStream.close() }
    runCatching { process.errorStream.close() }
}
