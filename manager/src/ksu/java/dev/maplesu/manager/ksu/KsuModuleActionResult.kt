// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

/**
 * 一次 `ksud module action <id>` 的**真实**结果：退出码 + stdout + stderr。
 *
 * 为什么必须带 out/err（开发文档 §2.3 A2 / §10.3 D4）：
 * 上游用 `CallbackList` 把 `module action` 的 stdout/stderr 原样透传给 UI
 * （`upstream/manager/app/src/main/java/me/weishu/kernelsu/ui/util/KsuCli.kt:267-295`），
 * 而本实现过去只保留布尔、并回吐伪造字符串 `MODULE_ACTION_STARTED:<id>` —— 用户
 * 永远看不到脚本自己打印的失败原因。C3 禁止静默成功，也不允许"成功但无信息"。
 *
 * [code] 语义：
 * - `0`：脚本退出 0；
 * - `>0`：脚本自身退出码（透传，不翻译）；
 * - `<0`：后端在起进程之前就失败（`-1` = ksud 不可用/命令被拒），此时 [err]
 *   必带具名错误码（`KSUD_UNAVAILABLE` / `KSU_MODULE_ID_REJECTED` / `KSU_ROOT_SHELL_UNAVAILABLE`）。
 */
data class KsuModuleActionResult(
    val code: Int,
    val out: String,
    val err: String,
) {
    val ok: Boolean get() = code == 0

    companion object {
        /** 命令构造阶段被拒（模块 id 非法等）。 */
        fun rejected(reason: String): KsuModuleActionResult =
            KsuModuleActionResult(-1, "", "KSU_MODULE_ID_REJECTED:$reason")

        /** 后端不可用（ksud 缺失 / root shell 未装配）。 */
        fun unavailable(reason: String): KsuModuleActionResult =
            KsuModuleActionResult(-1, "", reason)
    }
}
