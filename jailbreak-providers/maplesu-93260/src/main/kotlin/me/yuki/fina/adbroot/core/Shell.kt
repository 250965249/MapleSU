package me.yuki.fina.adbroot.core

import java.io.File

/** 一次 shell 调用的结果。 */
data class ExecResult(val code: Int, val out: String, val err: String = "") {
    val text: String get() = (out + if (err.isEmpty()) "" else "\n" + err).trim()
    val stdout: String get() = out
    val ok: Boolean get() = code == 0
}

/**
 * 拿到 root 之前唯一的执行通道：Shizuku 提供的 shell（uid 2000 / u:r=shell:s0，等价 adb shell）。
 * 抽象成接口只是为了让流程代码不直接依赖 Shizuku 反射。
 */
interface Shell {
    suspend fun exec(cmd: String, timeoutMs: Long = 30_000): ExecResult
    suspend fun push(local: File, remote: String): Boolean
    fun isAvailable(): Boolean
}
