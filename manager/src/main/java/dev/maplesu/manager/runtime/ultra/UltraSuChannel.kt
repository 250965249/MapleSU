// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime.ultra

import android.util.Log
import java.io.ByteArrayOutputStream
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class UltraSuChannel(
    private val exec: SuExec = ProcessSuExec,
    private val timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS,
) {

    @Volatile
    private var discoveredPath: String? = null

    private val probeLock = Any()
    private class RootObservation(val uid: Int?)
    @Volatile private var lastObservation: RootObservation? = null

    /**
     * 依次尝试 [SuCommands.probeCandidates]，返回 `id -u` 的数值（仅 0 视为根可用）；
     * 全失败返回 null。[lastFailure] 记录最后一次失败原因（不含敏感内容）。
     */
    @Volatile
    var lastFailure: String? = null
        private set

    fun rootUid(): Int? {
        val before = lastObservation
        return synchronized(probeLock) {
            val completed = lastObservation
            if (completed != null && completed !== before) completed.uid
            else probeRootUid().also { lastObservation = RootObservation(it) }
        }
    }

    private fun probeRootUid(): Int? {
        val started = System.nanoTime()
        val budget = TimeUnit.MILLISECONDS.toNanos(timeoutMillis.coerceAtLeast(1L))
        for (candidate in SuCommands.probeCandidates(discoveredPath)) {
            val remaining = budget - (System.nanoTime() - started)
            if (remaining <= 0L) {
                lastFailure = "SU_TIMEOUT"
                break
            }
            val result = runSafely(candidate, TimeUnit.NANOSECONDS.toMillis(remaining).coerceAtLeast(1L))
            if (result == null) {
                lastFailure = "SU_EXEC_EXCEPTION:${candidate.firstOrNull() ?: "?"}"
                continue
            }
            if (result.timedOut) {
                lastFailure = "SU_TIMEOUT"
                continue
            }
            if (result.failure != null) {
                lastFailure = result.failure
                continue
            }
            val uid = SuCommands.parseUid(result.output)
            if (uid == 0 && result.exitCode == 0) {
                discoveredPath = candidate.firstOrNull()
                lastFailure = null
                return 0
            }
            lastFailure = "SU_NOT_ROOT:exit=${result.exitCode}:uid=$uid"
        }
        discoveredPath = null
        return null
    }

    fun isRootAvailable(): Boolean = rootUid() != null

    /**
     * 用 root 执行一段脚本（`su -c <script>`）；[stdin] 非空时写入子进程标准输入。
     * 返回 null 表示通道不可用/异常（不是「命令失败」，命令失败在 [SuExecResult] 里）。
     */
    fun runRoot(script: String, stdin: String? = null, timeout: Long = timeoutMillis): SuExecResult? {
        val path = discoveredPath ?: run {
            if (rootUid() == null) return null
            discoveredPath ?: DEFAULT_SU_PATH
        }
        val result = runSafely(SuCommands.rootArgv(path, script), timeout, stdin)
        if (result == null || result.timedOut || result.failure != null) {
            synchronized(probeLock) {
                if (discoveredPath == path) discoveredPath = null
            }
        }
        return result
    }

    private fun runSafely(
        argv: List<String>,
        timeout: Long,
        stdin: String? = null,
    ): SuExecResult? = try {
        exec.exec(argv, timeout, stdin)
    } catch (error: Throwable) {
        // 日志本身绝不允许把「su 探测」变成异常（主机单测里 Log 是 stub，会抛）。
        runCatching { Log.w(TAG, "su exec failed: ${error.javaClass.simpleName}") }
        null
    }

    companion object {
        private const val TAG = "MapleSUUltraSu"
        const val DEFAULT_TIMEOUT_MILLIS = 5_000L

        /** 内核重定向只看「文件名是 su」，所以固定一个系统路径即可（文件不需要真的存在）。 */
        const val DEFAULT_SU_PATH = "/system/bin/su"
    }
}

/** 一次 `su` 进程执行的结果。 */
data class SuExecResult(
    val exitCode: Int,
    val output: String,
    val timedOut: Boolean = false,
    val failure: String? = null,
) {
    val ok: Boolean get() = failure == null && !timedOut && exitCode == 0
}

/** 可注入的 su 进程执行器（主机测试造假；生产用 [ProcessSuExec]）。 */
fun interface SuExec {
    fun exec(argv: List<String>, timeoutMillis: Long, stdin: String?): SuExecResult
}

/** 真实进程执行（`ProcessBuilder` + 合并 stderr + 超时强杀）。 */
object ProcessSuExec : SuExec {
    private val processSlot = Semaphore(1, true)

    override fun exec(argv: List<String>, timeoutMillis: Long, stdin: String?): SuExecResult {
        if (argv.isEmpty()) return SuExecResult(-1, "", failure = "EMPTY_ARGV")
        val started = System.nanoTime()
        val budget = TimeUnit.MILLISECONDS.toNanos(timeoutMillis.coerceAtLeast(1L))
        val acquired = try {
            processSlot.tryAcquire(budget, TimeUnit.NANOSECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return SuExecResult(-1, "", failure = "EXEC_INTERRUPTED")
        }
        if (!acquired) return SuExecResult(-1, "", timedOut = true)
        return try {
            if (System.nanoTime() - started >= budget) SuExecResult(-1, "", timedOut = true)
            else executeOwned(argv, stdin, started, budget)
        } finally {
            processSlot.release()
        }
    }

    private fun executeOwned(argv: List<String>, stdin: String?, started: Long, budget: Long): SuExecResult {
        val process = try {
            ProcessBuilder(argv).redirectErrorStream(true).start()
        } catch (error: Throwable) {
            // Preserve errno without logging argv, commands or private helper paths.
            val errno = Regex("\\berror=([0-9]{1,4})\\b").find(error.message.orEmpty())?.groupValues?.get(1)
            return SuExecResult(-1, "", failure = "START_FAILED:${error.javaClass.simpleName}" +
                (errno?.let { ":errno=$it" } ?: ""))
        }
        val buffer = ByteArrayOutputStream()
        val inputFailure = AtomicReference<Throwable?>()
        val outputFailure = AtomicReference<Throwable?>()
        val reader = Thread {
            try {
                process.inputStream.use { it.copyTo(buffer) }
            } catch (error: Throwable) {
                outputFailure.set(error)
            }
        }.apply {
            name = "maplesu-ultra-su-reader"
            isDaemon = true
        }
        val writer = Thread {
            try {
                process.outputStream.use { stream ->
                    if (stdin != null) stream.write(stdin.toByteArray(Charsets.UTF_8))
                }
            } catch (error: Throwable) {
                inputFailure.set(error)
            }
        }.apply {
            name = "maplesu-ultra-su-writer"
            isDaemon = true
        }
        return try {
            reader.start()
            writer.start()
            val remaining = (budget - (System.nanoTime() - started)).coerceAtLeast(0L)
            val finished = process.waitFor(remaining, TimeUnit.NANOSECONDS)
            if (!finished) {
                SuExecResult(-1, buffer.toString(Charsets.UTF_8.name()), timedOut = true)
            } else {
                writer.join(500)
                reader.join(500)
                val failure = when {
                    writer.isAlive || reader.isAlive -> "PROCESS_IO_INCOMPLETE"
                    inputFailure.get() != null -> "STDIN_FAILED:${inputFailure.get()!!.javaClass.simpleName}"
                    outputFailure.get() != null -> "STDOUT_FAILED:${outputFailure.get()!!.javaClass.simpleName}"
                    else -> null
                }
                SuExecResult(process.exitValue(), buffer.toString(Charsets.UTF_8.name()), failure = failure)
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            SuExecResult(-1, "", failure = "EXEC_INTERRUPTED")
        } catch (error: Throwable) {
            SuExecResult(-1, "", failure = "EXEC_FAILED:${error.javaClass.simpleName}")
        } finally {
            closeOwnedProcess(process, reader, writer)
        }
    }

    private fun closeOwnedProcess(process: Process, reader: Thread, writer: Thread) {
        // Closing a pipe held by a descendant can block. Keep cleanup bounded for the caller;
        // this executor owns the direct child, not the SDK's independent module processes.
        val closer = Thread {
            runCatching { if (process.isAlive) process.destroyForcibly() }
            runCatching { process.waitFor(500, TimeUnit.MILLISECONDS) }
            runCatching { process.outputStream.close() }
            runCatching { process.inputStream.close() }
            runCatching { process.errorStream.close() }
        }.apply {
            name = "maplesu-ultra-su-cleanup"
            isDaemon = true
            start()
        }
        var interrupted = Thread.interrupted()
        try {
            closer.join(750)
            writer.join(100)
            reader.join(100)
        } catch (_: InterruptedException) {
            interrupted = true
        } finally {
            if (interrupted) Thread.currentThread().interrupt()
        }
    }
}

/**
 * su 命令行与输出解析（纯函数，禁止 Android/IO）。单独放出来是为了让「哪一步失败」
 * 在主机测试里可枚举：候选顺序、uid 解析、脚本引用都必须能脱离真机验证。
 */
object SuCommands {

    fun probeCandidates(discovered: String? = null): List<List<String>> {
        val primary = discovered ?: UltraSuChannel.DEFAULT_SU_PATH
        return buildList {
            add(listOf(primary, "-c", "id -u"))
            add(listOf(primary, "0", "id", "-u"))
            add(listOf(primary, "-c", "id"))
            for (path in listOf("/system/xbin/su", "su")) {
                if (path != primary) add(listOf(path, "-c", "id -u"))
            }
        }
    }

    fun rootArgv(path: String, script: String): List<String> = listOf(path, "-c", script)

    /**
     * 解析 `id -u` / `id` 输出：
     *  - 任意一行 trim 后恰为 `0` → 0；
     *  - 出现 `uid=0(` / `uid=0 ` → 0（`id` 的整段输出）；
     *  - 否则返回最后一行里的十进制数（便于日志），没有数字返回 null。
     */
    fun parseUid(output: String?): Int? {
        val text = output.orEmpty()
        if (text.isBlank()) return null
        val lines = text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
        for (line in lines) {
            if (line == "0") return 0
        }
        if (UID_ZERO.containsMatchIn(text)) return 0
        val last = lines.lastOrNull() ?: return null
        val match = DECIMAL.find(last) ?: return null
        return match.value.toIntOrNull()
    }

    private val UID_ZERO = Regex("""\buid=0(?:\(|\s|$)""")
    private val DECIMAL = Regex("""\d{1,10}""")
}
