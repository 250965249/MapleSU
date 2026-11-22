package dev.maplesu.manager.ksu

import java.io.IOException
import java.util.Collections
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/** Selected-file patching uses app permissions and preserves both process output streams. */
class KsuFileCommandRunner(
    private val shell: List<String> = listOf("/system/bin/sh", "-c"),
) : KsuRootCommandRunner {
    override fun run(commandLine: String, timeoutMs: Long): KsuShellResult =
        execute(shell + commandLine, timeoutMs)

    override fun run(argv: List<String>, timeoutMs: Long): KsuShellResult = execute(argv, timeoutMs)

    private fun execute(argv: List<String>, timeoutMs: Long): KsuShellResult {
        val process = try {
            ProcessBuilder(argv).start()
        } catch (error: IOException) {
            return KsuShellResult(127, emptyList(), listOf(error.message.orEmpty()))
        }
        process.outputStream.close()
        val out = Collections.synchronizedList(mutableListOf<String>())
        val err = Collections.synchronizedList(mutableListOf<String>())
        val readers = listOf(process.inputStream to out, process.errorStream to err).map { (stream, lines) ->
            thread(isDaemon = true) {
                try {
                    stream.bufferedReader().useLines { it.forEach(lines::add) }
                } catch (error: IOException) {
                    err.add(error.message.orEmpty())
                }
            }
        }
        var interrupted = false
        val code = try {
            if (process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) process.exitValue() else {
                err.add("boot-patch process timed out after ${timeoutMs}ms")
                interrupted = terminateAndWait(process)
                124
            }
        } catch (_: InterruptedException) {
            terminateAndWait(process)
            interrupted = true
            130
        }
        try {
            readers.forEach { it.join(2_000) }
        } catch (_: InterruptedException) {
            interrupted = true
        } finally {
            process.inputStream.close()
            process.errorStream.close()
        }
        if (interrupted) Thread.currentThread().interrupt()
        return KsuShellResult(code, synchronized(out) { out.toList() }, synchronized(err) { err.toList() })
    }

    private fun terminateAndWait(process: Process): Boolean {
        process.destroyForcibly()
        var interrupted = false
        while (true) {
            try {
                process.waitFor()
                return interrupted
            } catch (_: InterruptedException) {
                interrupted = true
            }
        }
    }
}
