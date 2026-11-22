package dev.maplesu.manager.modules

import android.content.Context
import dev.maplesu.manager.runtime.RootManagement

/**
 * T5: the single active metamodule pointer.
 *
 * Contract taken from the pinned KSU userspace, not invented:
 *
 * - `defs.rs:32` - the pointer is `/data/adb/metamodule`.
 * - `metamodule.rs:124-153` - installing a metamodule removes any previous pointer and
 *   creates `METAMODULE_DIR -> /data/adb/modules/<id>`.
 * - `metamodule.rs:19-24` - `metamodule=1` (or `true`) in `module.prop` is the marker.
 * - `init_event.rs:110-118` - the mount hook (`metamount.sh`) runs after the
 *   post-fs-data scripts.
 *
 * MapleSU dispatches the hook but never implements mounting: a metamodule whose script
 * needs overlayfs fails, and that failure is recorded in `stage.mount.*` instead of
 * being hidden. The pointer lives under `/data/adb` (0700 Root), so it adds no
 * ordinary-app observable surface.
 */
object Metamodule {
    const val PATH = "/data/adb/metamodule"

    private fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"

    /**
     * Points [PATH] at [target].
     *
     * Replacing a pointer is only allowed for this same module's previous revision
     * ([previousTargets]): that is an update. A pointer owned by anything else is a
     * conflict, because silently stealing another manager's (or another module's)
     * metamodule would change a device-wide contract that is not ours to change.
     */
    fun linkScript(target: String, previousTargets: List<String>): String {
        val allowed = (listOf(target) + previousTargets).distinct().joinToString("\n") {
            "                ${quote(it)}) ;;"
        }
        return """
        set -eu
        test "${'$'}(/system/bin/id -u)" = 0
        link=${quote(PATH)}
        target=${quote(target)}
        test -d "${'$'}target"
        if [ -L "${'$'}link" ]; then
            current="${'$'}(/system/bin/readlink "${'$'}link" 2>/dev/null || /system/bin/echo none)"
            case "${'$'}current" in
$allowed
                *)
                    /system/bin/printf 'MAPLESU_METAMODULE_CONFLICT:%s\n' "${'$'}current" >&2
                    exit 3
                    ;;
            esac
            /system/bin/rm -f "${'$'}link"
        elif [ -e "${'$'}link" ]; then
            /system/bin/printf 'MAPLESU_METAMODULE_CONFLICT:%s\n' "${'$'}link" >&2
            exit 3
        fi
        /system/bin/ln -s "${'$'}target" "${'$'}link"
        test "${'$'}(/system/bin/readlink "${'$'}link")" = "${'$'}target"
        /system/bin/chown -h 0:0 "${'$'}link"
        /system/bin/printf 'MAPLESU_METAMODULE:%s\n' "${'$'}link"
        """.trimIndent()
    }

    /** Removes [PATH] only while it still points at [target]. */
    fun unlinkScript(target: String): String = """
        set -eu
        link=${quote(PATH)}
        target=${quote(target)}
        if [ -L "${'$'}link" ] && [ "${'$'}(/system/bin/readlink "${'$'}link")" = "${'$'}target" ]; then
            /system/bin/rm -f "${'$'}link"
            /system/bin/printf 'MAPLESU_METAMODULE_REMOVED:%s\n' "${'$'}link"
        else
            /system/bin/printf 'MAPLESU_METAMODULE_KEPT:%s\n' "${'$'}link"
        fi
    """.trimIndent()

    fun link(context: Context, target: String, previousTargets: List<String> = emptyList()) {
        Run(context).use { shell ->
            val result = shell.newJob().add(linkScript(target, previousTargets))
                .to(ArrayList<String>(), ArrayList<String>()).exec()
            check(result.isSuccess) {
                if (result.err.any { it.contains("MAPLESU_METAMODULE_CONFLICT") }) {
                    "METAMODULE_CONFLICT: $PATH already belongs to another module (" +
                        result.err.joinToString(" ") + "). Uninstall it first."
                } else {
                    "METAMODULE_PUBLISH_FAILED: " + result.err.joinToString("\n")
                }
            }
            check(result.out.any { it.startsWith("MAPLESU_METAMODULE:") }) {
                "METAMODULE_NOT_CONFIRMED"
            }
        }
    }

    fun unlink(context: Context, target: String) {
        Run(context).use { shell ->
            shell.newJob().add(unlinkScript(target)).to(ArrayList<String>(), ArrayList<String>()).exec()
        }
    }

    private class Run(context: Context) : AutoCloseable {
        // P0：经 RootExecutionRouter（Lite 下 Ultra run_root_cmd 优先），不再依赖 libsu su。
        private val shell = ModuleRootShell(RootExecModuleScriptRunner)
        fun newJob() = shell.newJob()
        override fun close() { runCatching { shell.close() } }
    }
}
