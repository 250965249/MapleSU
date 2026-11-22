// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import android.content.Context
import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootExecResult
import dev.maplesu.manager.runtime.RootExecutor
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import java.io.File

/**
 * Normal（KernelSU）模式的 [RootExecutor]：`RootExec` 在 KSU 下可用的唯一来源。
 *
 * 形态：与 [KsuRootChannel] 完全一致 —— `<nativeLibraryDir>/libksud_ksu.so debug su`，
 * 一次调用一条 shell（`ksud debug su` 起一个 root shell，执行一条脚本，随即关闭）。
 * 覆盖：`RootShellControlPlane` / `ModuleTree` / `LiteImplantBackup` 这些既有调用点
 * **不需要改**，它们在 KSU 模式下自动走这里。
 *
 * 失败语义（不伪造）：
 * - [available] 只在「模式 == KSU」且 launcher 二进制存在时为 true；
 * - [run] 真正执行；shell 起不来 / 不是 root → 返回负 code + 具名 detail
 *   （`KSU_ROOT_CHANNEL_UNAVAILABLE:<cause>`），**绝不**返回 code=0。
 */
internal class KsuRootExecutor(
    context: Context,
    private val modeProvider: () -> WorkMode? = { ModeRuntime.active },
    private val channel: KsuRootChannel = KsuRootChannel(),
) : RootExecutor {

    private val application = context.applicationContext

    override val backend: RootBackend = RootBackend.KSU

    /**
     * 便宜判据：模式必须是 KSU，且 APK 自带的 launcher 存在。
     * 这里**不**起进程（`available()` 会被 capability 轮询）；真正的可用性由 [run] 的
     * 真实退出码决定 —— 探测成功但执行失败仍然只会得到失败结果。
     */
    override fun available(): Boolean {
        if (runCatching { modeProvider() }.getOrNull() != WorkMode.KSU) return false
        return runCatching { launcherFile().isFile }.getOrDefault(false)
    }

    override fun run(script: String): RootExecResult {
        if (script.isBlank()) {
            return RootExecResult(RootBackend.KSU, -1, "", "EMPTY_SCRIPT")
        }
        val result = runCatching { channel.exec(application, script) }.getOrElse { error ->
            return RootExecResult(
                RootBackend.KSU, -1, "",
                "${KsuRootChannel.UNAVAILABLE}:${error.message ?: error.javaClass.simpleName}",
            )
        }
        return RootExecResult(RootBackend.KSU, result.code, result.outText, result.errText)
    }

    /** APK 内自带的 ksud（launcher）；**不是**部署后的 `/data/adb/ksud`。 */
    internal fun launcherFile(): File =
        File(KsuCommands.daemonPath(File(application.applicationInfo.nativeLibraryDir)))
}
