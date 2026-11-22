package dev.maplesu.manager.workmode.service

import java.io.ByteArrayOutputStream
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** The helper already owns uid 0. This executor never contacts a root provider. */
internal class ModeSwitchRootCommandRunner(
    private val start: () -> Process = { ProcessBuilder("/system/bin/sh").redirectErrorStream(true).start() },
    private val timeoutMillis: Long = 120_000,
) {
    fun execute(script: String): ModeSwitchRootProtocol.Reply {
        val process = try { start() } catch (_: Exception) {
            return ModeSwitchRootProtocol.Reply(-1, detail = "MODE_SWITCH_ROOT_EXEC_START_FAILED")
        }
        val workers = Executors.newFixedThreadPool(2) { task ->
            Thread(task, "maplesu-mode-switch-io").apply { isDaemon = true }
        }
        val writer = workers.submit(Callable {
            process.outputStream.use {
                it.write(script.toByteArray(Charsets.UTF_8))
                it.write('\n'.code)
            }
        })
        val reader = workers.submit(Callable {
            val output = ByteArrayOutputStream()
            var truncated = false
            process.inputStream.use { input ->
                val bytes = ByteArray(8192)
                while (true) {
                    val count = input.read(bytes)
                    if (count < 0) break
                    val accepted = minOf(count, ModeSwitchRootProtocol.MAX_OUTPUT_BYTES - output.size())
                    if (accepted > 0) output.write(bytes, 0, accepted)
                    if (accepted < count) truncated = true
                }
            }
            val decoded = output.toString(Charsets.UTF_8.name())
            // Malformed UTF-8 can expand on replacement; bound the encoded response as well.
            val textLimit = ModeSwitchRootProtocol.MAX_OUTPUT_BYTES / 4
            Pair(decoded.take(textLimit), truncated || decoded.length > textLimit)
        })
        return try {
            if (!process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS)) {
                ModeSwitchRootProtocol.Reply(-1, detail = ModeSwitchRootProtocol.UNCERTAIN)
            } else {
                writer.get(1, TimeUnit.SECONDS)
                val captured = reader.get(1, TimeUnit.SECONDS)
                if (captured.second) ModeSwitchRootProtocol.Reply(-1, captured.first, "MODE_SWITCH_ROOT_OUTPUT_LIMIT")
                else ModeSwitchRootProtocol.Reply(process.exitValue(), captured.first)
            }
        } catch (_: Exception) {
            ModeSwitchRootProtocol.Reply(-1, detail = ModeSwitchRootProtocol.UNCERTAIN)
        } finally {
            // Killing a timed-out shell does not prove all descendants stopped. The caller
            // quarantines this helper after UNCERTAIN rather than racing a rollback against it.
            runCatching { process.destroyForcibly() }
            runCatching { process.outputStream.close() }
            runCatching { process.inputStream.close() }
            runCatching { process.errorStream.close() }
            writer.cancel(true)
            reader.cancel(true)
            workers.shutdownNow()
        }
    }
}
