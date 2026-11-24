// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.workmode.detect

import java.io.File

/**
 * 调试版专用：把环境检查的判定轨迹写进 app 私有目录（`cache/env-diag.log`）。
 *
 * 为什么不是 `android.util.Log`：本机（vivo PD2509）上 untrusted_app 的日志在 logd 里
 * 拿不到，排查「环境检查未完成」时只能靠落盘。写入量极小（每次检查十余行），
 * 且只在调试构建里被 [dev.maplesu.manager.workmode.detect.probes.EnvironmentProbesAdapter]
 * 安装；正式包不安装 = 不产生任何文件。
 */
internal object EnvDiag {

    private val lock = Any()

    @Volatile
    private var target: File? = null

    @Volatile
    private var startedAtMillis: Long = Long.MIN_VALUE

    /** 只安装一次；每次新进程首次安装时清空旧文件。 */
    fun install(file: File, nowMillis: Long) {
        synchronized(lock) {
            if (target != null) return
            runCatching { file.delete() }
            target = file
            startedAtMillis = nowMillis
        }
    }

    fun log(message: String) {
        val file = target ?: return
        val relative = if (startedAtMillis == Long.MIN_VALUE) 0L else System.currentTimeMillis() - startedAtMillis
        synchronized(lock) {
            runCatching { file.appendText("+${relative}ms $message\n") }
        }
    }
}
