// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import android.content.Context
import com.topjohnwu.superuser.Shell
import com.topjohnwu.superuser.CallbackList
import dev.maplesu.manager.installer.InstallerRootSourceRegistry
import dev.maplesu.manager.installer.NativeRootChannel
import dev.maplesu.manager.workmode.WorkMode
import java.io.File
import java.util.concurrent.TimeUnit
import java.util.concurrent.Executor
import java.util.concurrent.TimeoutException

/**
 * KernelSU 原生根通道（Normal 模式的产品入口）。
 *
 * 形态：`<nativeLibraryDir>/libksud_ksu.so debug su` —— APK 自带 ksud 的 `debug su`
 * 子命令，与 [KsuCommandBackend] / `LibsuRootCommandRunner` 使用的形态完全一致；
 * 需要全局挂载命名空间时追加 `-g`（[KsuCommands.su] 的受控构造）。
 *
 * 失败语义（fail-closed）：任何一步不成立都抛
 * `KSU_ROOT_CHANNEL_UNAVAILABLE:<cause>`，**绝不**返回不可用/非 root 的 shell，
 * 也绝不把失败吞成成功。`RootManagement` 只在 `ModeRuntime.active == KSU` 时尝试
 * 本通道，失败后回退既有凭据 transport（回退失败仍抛原错误）。
 *
 * 装配：`ModeBootstrap` 在模式激活为 [WorkMode.KSU] 时调用 [installIfKsu]，把本通道
 * 注册进 [InstallerRootSourceRegistry]；LITE/未判定不注册（保持 null = fail-closed）。
 */
internal class KsuRootChannel(
    private val daemonPathProvider: (Context) -> String = { context ->
        KsuCommands.daemonPath(File(context.applicationInfo.nativeLibraryDir))
    },
    private val launcher: KsuShellLauncher = LibsuKsuShellLauncher,
) : NativeRootChannel {

    override fun openShell(context: Context): Shell = openShell(context, globalMnt = false)

    override fun openShell(context: Context, globalMnt: Boolean): Shell {
        val daemon = daemonPathProvider(context)
        return openVerified(daemon, globalMnt) { tokens -> launcher.launch(context, tokens) }
    }

    /**
     * 最小命令 API：打开一条 root shell、执行一条命令、返回 `{code,out,err}`。
     *
     * shell 只活一条命令（与 [KsuCommandBackend]「一次调用一次进程」一致），不会常驻。
     */
    fun exec(context: Context, command: String, globalMnt: Boolean = false): KsuShellResult =
        openShell(context, globalMnt).use { shell -> execOn(shell, command) }

    fun exec(context: Context, command: String, globalMnt: Boolean, timeoutMs: Long): KsuShellResult =
        openShell(context, globalMnt).use { shell -> execOn(shell, command, timeoutMs) }

    fun execStreaming(
        context: Context, command: String, globalMnt: Boolean, timeoutMs: Long,
        onStdout: (String) -> Unit, onStderr: (String) -> Unit,
    ): KsuShellResult = openShell(context, globalMnt).use { shell ->
        execOn(shell, command, timeoutMs, onStdout, onStderr)
    }

    /**
     * 打开并校验一条 root shell；与 Android 解耦（宿主单测直接注入 [launch]）。
     *
     * 校验顺序：命令构造 → 起进程 → `isRoot` → `isAlive`。任一步失败：
     * 关掉已起的 shell（best-effort）并抛具名 token。
     */
    internal fun openVerified(
        daemon: String,
        globalMnt: Boolean,
        launch: (List<String>) -> Shell,
    ): Shell {
        val tokens = try {
            command(daemon, globalMnt)
        } catch (error: Exception) {
            throw unavailable("COMMAND_REJECTED:${error.message}", error)
        }
        val shell = try {
            launch(tokens)
        } catch (error: Exception) {
            throw unavailable("LAUNCH_FAILED:${error.javaClass.simpleName}", error)
        }
        val cause = unusableCause(shell.isRoot, shell.isAlive)
        if (cause != null) {
            runCatching { shell.close() }
            throw unavailable(cause)
        }
        return shell
    }

    companion object {
        /** 失败 token 前缀；`<cause>` 由 [unusableCause] / 起进程失败给出。 */
        const val UNAVAILABLE = "KSU_ROOT_CHANNEL_UNAVAILABLE"

        /** 与 `RootManagement`/`InstallerRootSession` 的既有 shell 超时保持一致。 */
        const val SHELL_TIMEOUT_SECONDS = 15L

        /** 命令形态的唯一构造入口（[KsuCommands.su] 内已有 daemon 与参数级硬拒绝）。 */
        fun command(daemon: String, globalMnt: Boolean): List<String> =
            KsuCommands.su(daemon, globalMnt)

        /** 在已打开的 shell 上执行一条命令；`{code,out,err}` 原样返回，不解释成败。 */
        fun execOn(shell: Shell, command: String, timeoutMs: Long = 120_000L): KsuShellResult =
            execOn(shell, command, timeoutMs, null, null)

        fun execOn(
            shell: Shell, command: String, timeoutMs: Long,
            onStdout: ((String) -> Unit)?, onStderr: ((String) -> Unit)?,
        ): KsuShellResult {
            val out = ArrayList<String>()
            val err = ArrayList<String>()
            val outputLock = Any()
            fun sink(lines: MutableList<String>, callback: ((String) -> Unit)?): MutableList<String> =
                if (callback == null) lines else object : CallbackList<String>(Executor { it.run() }) {
                    override fun onAddElement(line: String) {
                        synchronized(outputLock) {
                            lines.add(line)
                            callback(line)
                        }
                    }
                }
            // Scripts may exit/exec or change shell options; keep libsu's receipt shell alive.
            val pending = shell.newJob().add("(\n$command\n)")
                .to(sink(out, onStdout), sink(err, onStderr)).enqueue()
            val result = try {
                if (timeoutMs == 0L) pending.get() else pending.get(timeoutMs, TimeUnit.MILLISECONDS)
            } catch (error: TimeoutException) {
                pending.cancel(true)
                runCatching { shell.close() }
                throw unavailable("COMMAND_TIMEOUT", error)
            } catch (error: InterruptedException) {
                pending.cancel(true)
                runCatching { shell.close() }
                Thread.currentThread().interrupt()
                throw unavailable("COMMAND_INTERRUPTED", error)
            }
            return KsuShellResult(result.code, out, err)
        }

        /** `null` = shell 可用；否则是 token 的 `<cause>`（isRoot 优先于 isAlive）。 */
        fun unusableCause(isRoot: Boolean, isAlive: Boolean): String? = when {
            !isRoot -> "SHELL_NOT_ROOT"
            !isAlive -> "SHELL_NOT_ALIVE"
            else -> null
        }

        fun unavailable(cause: String, error: Throwable? = null): IllegalStateException =
            IllegalStateException("$UNAVAILABLE:$cause", error)

        /**
         * 模式装配点：**只在** [WorkMode.KSU] 注册生产通道；其它模式保持未注册
         * （`InstallerRootSourceRegistry.require()` 继续抛 `KSU_CHANNEL_UNAVAILABLE`）。
         *
         * 幂等：重复激活/重复调用只会把同一个形态的通道重新装一次。
         */
        fun installIfKsu(mode: WorkMode?): Boolean {
            if (mode != WorkMode.KSU) return false
            InstallerRootSourceRegistry.install(KsuRootChannel())
            return true
        }
    }
}

/** 起一条 root shell 的可注入接缝（生产 = libsu；宿主单测不需要 Context）。 */
internal fun interface KsuShellLauncher {
    fun launch(context: Context, tokens: List<String>): Shell
}

/** 生产 launcher：`Shell.Builder ... build(<libksud_ksu.so>, "debug", "su"[, "-g"])`。 */
private object LibsuKsuShellLauncher : KsuShellLauncher {
    override fun launch(context: Context, tokens: List<String>): Shell =
        Shell.Builder.create()
            .setContext(context.applicationContext)
            .setTimeout(KsuRootChannel.SHELL_TIMEOUT_SECONDS)
            .build(*tokens.toTypedArray())
}
