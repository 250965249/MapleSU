// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import java.io.File

/**
 * 测试用的仓库路径解析（**不 skip**）。
 *
 * AGP 单元测试的工作目录是 **模块目录**（`manager/`），不是仓库根，也不是 `src/main`；
 * 因此不能用 `../third_party/...` 这类脆弱相对路径。这里从 `user.dir` 向上找
 * `settings.gradle.kts` 作为仓库根标记；找不到就**断言失败**（基线要求 skip=0，
 * 不允许把「路径不对」伪装成 skip）。
 */
object KsuTestPaths {
    private val repoRootCache: File by lazy { locateRepoRoot() }

    private fun locateRepoRoot(): File {
        val start = File(System.getProperty("user.dir") ?: ".").absoluteFile
        var cursor: File? = start
        repeat(8) {
            val dir = cursor ?: return@repeat
            if (File(dir, "settings.gradle.kts").isFile) return dir
            // 兼容直接在仓库根跑测试的情况
            if (File(dir, "third_party/kernelsu/manifest.json").isFile) return dir
            cursor = dir.parentFile
        }
        throw AssertionError(
            "repo root (settings.gradle.kts) not found upward from ${start.path}; " +
                "user.dir must be the manager module dir or repo root",
        )
    }

    fun repoRoot(): File = repoRootCache

    fun managerDir(): File {
        val dir = File(repoRoot(), "manager")
        check(dir.isDirectory) { "manager module dir missing: ${dir.path}" }
        return dir
    }

    fun kernelsuRoot(): File = File(repoRoot(), "third_party/kernelsu")

    fun manifest(): File = File(kernelsuRoot(), "manifest.json")

    fun payload(): File = File(kernelsuRoot(), "ksu-payload.json")

    fun applied(): File = File(kernelsuRoot(), "applied")
}
