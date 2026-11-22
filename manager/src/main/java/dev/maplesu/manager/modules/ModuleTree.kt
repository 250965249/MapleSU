package dev.maplesu.manager.modules

import android.content.Context
import dev.maplesu.manager.runtime.RootManagement
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode

/**
 * Publishes the standard KernelSU module layout for an installed module.
 *
 * The compatibility contract (M07) is about the *path* modules and their scripts
 * assume, not about taking over another manager's tree:
 *
 * - `defs.rs` / `module.rs` place modules at `/data/adb/modules/<id>`.
 * - MapleSU keeps the authoritative revision tree in app-private storage, so the
 *   standard path is a Root-owned symlink to that exact revision directory.
 * - An existing entry that is not this module's link is a **conflict**, never
 *   overwritten: another manager's module must not be clobbered by ours.
 *
 * The tree itself is Root-owned (0:0) and 0755 so a Root script can traverse it; the
 * authoritative revision stays in the app-private directory, so publishing the path
 * does not expose module content to ordinary apps.
 */
object ModuleTree {
    const val ROOT = "/data/adb/modules"

    fun standardPath(id: String): String = "$ROOT/$id"

    /**
     * 谁可以往这个**共享标准路径**发布模块软链。
     *
     * 只有 LITE（Ultra）会走到这里：它把 app 私有的权威树以 root 软链的方式发布到模块脚本
     * 期望的路径。Normal（KSU）下 `/data/adb/modules` 是 **ksud 的模块树**（真实目录由
     * `ksud module install` 创建），MapleSU 再往里写软链就会让 ksud 把 Ultra 的模块当成
     * 自己的模块加载 —— 这正是"两套模块系统串味"。
     *
     * 纯函数 → 主机可测；未判定同样拒绝（fail-closed，绝不默认 LITE）。
     */
    fun allowsPublish(mode: WorkMode?): Boolean = mode == WorkMode.LITE

    private fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    /** Creates (or re-points) the standard path for [id] at [target]. */
    fun linkScript(id: String, target: String): String = """
        set -eu
        test "${'$'}(/system/bin/id -u)" = 0
        root=${quote(ROOT)}
        link=${quote(standardPath(id))}
        target=${quote(target)}
        test ! -L "${'$'}root"
        /system/bin/mkdir -p "${'$'}root"
        /system/bin/chown 0:0 "${'$'}root"
        /system/bin/chmod 0755 "${'$'}root"
        test -d "${'$'}target"
        if [ -e "${'$'}link" ] || [ -L "${'$'}link" ]; then
            current="${'$'}(/system/bin/readlink "${'$'}link" 2>/dev/null || /system/bin/echo none)"
            if [ "${'$'}current" = "${'$'}target" ]; then
                /system/bin/rm -f "${'$'}link"
            elif [ -L "${'$'}link" ]; then
                /system/bin/printf 'MAPLESU_TREE_CONFLICT:%s\n' "${'$'}current" >&2
                exit 3
            else
                # A real directory or file sits at the standard path: either a stale entry
                # from an earlier MapleSU build (before this path became a link) or another
                # manager's module. Move it aside rather than delete it, so no one else's
                # data is destroyed and the entry stays recoverable.
                stale="${'$'}link.maplesu-stale-${'$'}(/system/bin/date +%s)"
                /system/bin/mv "${'$'}link" "${'$'}stale" || exit 3
                /system/bin/printf 'MAPLESU_TREE_STALE_MOVED:%s\n' "${'$'}stale"
            fi
        fi
        /system/bin/ln -s "${'$'}target" "${'$'}link"
        test "${'$'}(/system/bin/readlink "${'$'}link")" = "${'$'}target"
        /system/bin/chown -h 0:0 "${'$'}link"
        /system/bin/printf 'MAPLESU_TREE:%s\n' "${'$'}link"
    """.trimIndent()

    /** Removes the standard path only when it still points at this revision. */
    fun unlinkScript(id: String, target: String): String = """
        set -eu
        link=${quote(standardPath(id))}
        target=${quote(target)}
        if [ -L "${'$'}link" ]; then
            current="${'$'}(/system/bin/readlink "${'$'}link" 2>/dev/null || /system/bin/echo none)"
            if [ "${'$'}current" = "${'$'}target" ]; then
                /system/bin/rm -f "${'$'}link"
                /system/bin/printf 'MAPLESU_TREE_REMOVED:%s\n' "${'$'}link"
            else
                /system/bin/printf 'MAPLESU_TREE_KEPT:%s\n' "${'$'}current"
            fi
        else
            /system/bin/printf 'MAPLESU_TREE_ABSENT:%s\n' "${'$'}link"
        fi
    """.trimIndent()

    fun link(context: Context, id: String, target: String): String {
        // 模式隔离：Normal 下 /data/adb/modules 归 ksud，Ultra 不得往里发布。
        // 显式失败（不静默跳过）：否则安装会"成功"但模块脚本永远找不到自己的路径。
        check(allowsPublish(ModeRuntime.active)) {
            "MODULE_TREE_MODE_REJECTED: ${standardPath(id)} belongs to ksud in " +
                "mode=${ModeRuntime.active}; Ultra publish is LITE-only"
        }
        Run(context).use { shell ->
            val result = shell.newJob().add(linkScript(id, target))
                .to(ArrayList<String>(), ArrayList<String>()).exec()
            check(result.isSuccess) {
                if (result.err.any { it.contains("MAPLESU_TREE_CONFLICT") }) {
                    "MODULE_TREE_CONFLICT: " + standardPath(id) +
                        " already points at another location (" + result.err.joinToString(" ") + ")"
                } else {
                    "MODULE_TREE_PUBLISH_FAILED: " + result.err.joinToString("\n")
                }
            }
            return result.out.firstOrNull { it.startsWith("MAPLESU_TREE:") }
                ?.removePrefix("MAPLESU_TREE:")?.trim()
                ?: error("MODULE_TREE_NOT_CONFIRMED")
        }
    }

    fun unlink(context: Context, id: String, target: String) {
        Run(context).use { shell ->
            shell.newJob().add(unlinkScript(id, target)).to(ArrayList<String>(), ArrayList<String>()).exec()
        }
    }

    /** Small adapter so callers do not repeat the shell plumbing. */
    private class Run(context: Context) : AutoCloseable {
        // P0：经 RootExecutionRouter（Lite 下 Ultra run_root_cmd 优先），不再依赖 libsu su。
        private val shell = ModuleRootShell(RootExecModuleScriptRunner)
        fun newJob() = shell.newJob()
        override fun close() { runCatching { shell.close() } }
    }
}
