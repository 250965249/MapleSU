// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import com.topjohnwu.superuser.Shell

/**
 * 生产用 shell 执行器：libsu。
 *
 * 只做「起进程 / 拿 stdout+stderr+退出码」，不缓存 shell（ksud 是一次性进程；
 * 缓存由集成层的 KsuShellProvider 负责）。
 *
 * ⚠️ 与现有 Lite 行为保持一致：**不抛异常**，任何构建/执行失败都返回 code=-1 的结果。
 */
class LibsuShellRunner : KsuShellRunner {
    override fun run(command: List<String>, timeoutMs: Long): KsuShellResult {
        if (command.isEmpty()) {
            return KsuShellResult(-1, emptyList(), listOf("empty command"))
        }
        return try {
            val out = mutableListOf<String>()
            val err = mutableListOf<String>()
            val shell = Shell.Builder.create().build(*command.toTypedArray())
            val result = shell.newJob()
                .to(out, err)
                .exec()
            runCatching { shell.close() }
            KsuShellResult(result.code, out, err)
        } catch (t: Throwable) {
            KsuLog.record("shell-error", "${t.javaClass.simpleName}: ${t.message}")
            KsuShellResult(-1, emptyList(), listOf(t.message ?: "shell error"))
        }
    }
}
