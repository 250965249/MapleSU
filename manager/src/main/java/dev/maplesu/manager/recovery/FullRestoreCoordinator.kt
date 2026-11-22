package dev.maplesu.manager.recovery

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import dev.maplesu.manager.litehidden.LiteHiddenPaths
import dev.maplesu.manager.runtime.RootExec
import dev.maplesu.manager.runtime.RootExecResult
import kotlinx.coroutines.runBlocking

/** 单步恢复结果（逐步返回 ok/fail+reason；UI/服务端分别展示，不合并成"成功"）。 */
data class RestoreStepResult(
    val step: String,
    val ok: Boolean,
    val reason: String = "",
)

data class FullRestoreResult(
    val ok: Boolean,
    val code: String = "",
    val steps: List<RestoreStepResult> = emptyList(),
)

object FullRestoreCodes {
    const val UNHIDE_FAILED = "RESTORE_UNHIDE_FAILED"
    const val MANAGER_MISSING = "RESTORE_MANAGER_MISSING"
    const val WEBUI_FAILED = "RESTORE_WEBUI_FAILED"
    const val COMPONENTS_FAILED = "RESTORE_COMPONENTS_FAILED"
    const val VERIFY_FAILED = "RESTORE_VERIFY_FAILED"
    const val STEP_EXCEPTION = "RESTORE_STEP_EXCEPTION"
    const val NOT_AUTHORIZED = "RESTORE_NOT_AUTHORIZED"
    const val NOT_ACTIVE = "RESTORE_NOT_ACTIVE"
    const val RATE_LIMITED = "RESTORE_RATE_LIMITED"
}

/**
 * 统一恢复事务（**WebUI 与 App 拨号密令共用同一份步骤/效果**）：
 * `unhide → ensure_manager → restore_webui → restore_components → verify`。
 *
 * 幂等：每步可重复执行；失败即停止并返回步骤明细（fail-closed）。
 * App 侧由拨号触发；WebUI 侧由 `LiteWebRestorePort` 适配（wm-installer 已留 501 注入点）。
 */
class FullRestoreCoordinator(
    private val unhide: () -> RestoreStepResult,
    private val ensureManager: () -> RestoreStepResult,
    private val restoreWebui: () -> RestoreStepResult,
    private val restoreComponents: () -> RestoreStepResult,
    private val verify: () -> RestoreStepResult,
) {
    fun restore(): FullRestoreResult {
        val steps = mutableListOf<RestoreStepResult>()
        val planned = listOf(
            "unhide" to unhide,
            "ensure_manager" to ensureManager,
            "restore_webui" to restoreWebui,
            "restore_components" to restoreComponents,
            "verify" to verify,
        )
        for ((name, action) in planned) {
            val result = runCatching(action).getOrElse { error ->
                RestoreStepResult(name, false, "${FullRestoreCodes.STEP_EXCEPTION}:${error.javaClass.simpleName}")
            }
            steps += result
            if (!result.ok) {
                return FullRestoreResult(false, result.reason.ifEmpty { FullRestoreCodes.STEP_EXCEPTION }, steps)
            }
        }
        return FullRestoreResult(true, steps = steps)
    }

    companion object {
        val STEP_NAMES: List<String> = listOf(
            "unhide", "ensure_manager", "restore_webui", "restore_components", "verify",
        )

        /**
         * App 侧生产装配（拨号路径）：unhide 走 root 写 OFF + 回读；ensure_manager 只检查本 App 已安装
         * （卸载场景由 WebUI 的 `pm install -r` 备份 APK 负责，本方法不伪造安装）；restore_webui
         * 按用户开关拉起 RootService/Ultra daemon；restore_components 恢复 LauncherAlias；verify 回读。
         */
        fun production(context: Context): FullRestoreCoordinator {
            val app = context.applicationContext
            val packageManager = app.packageManager
            return FullRestoreCoordinator(
                unhide = {
                    val out: RootExecResult = RootExec.execute(
                        "printf '0' > '${LiteHiddenPaths.STATE_PATH}' 2>/dev/null; " +
                            "mkdir -p '${LiteHiddenPaths.DATA_DIR}' 2>/dev/null; " +
                            "printf '0' > '${LiteHiddenPaths.STATE_PATH}' && " +
                            "chmod 600 '${LiteHiddenPaths.STATE_PATH}' && echo LITE_OK",
                    )
                    val readBack = RootExec.execute("cat '${LiteHiddenPaths.STATE_PATH}' 2>/dev/null")
                    val ok = out.ok && out.output.contains("LITE_OK") &&
                        readBack.ok && readBack.output.trim().startsWith("0")
                    RestoreStepResult("unhide", ok, if (ok) "" else FullRestoreCodes.UNHIDE_FAILED)
                },
                ensureManager = {
                    val installed = runCatching {
                        packageManager.getPackageInfo(app.packageName, 0)
                        true
                    }.getOrDefault(false)
                    RestoreStepResult(
                        "ensure_manager", installed,
                        if (installed) "" else FullRestoreCodes.MANAGER_MISSING,
                    )
                },
                restoreWebui = {
                    val controller = dev.maplesu.manager.liteweb.LiteWebAdminController(app)
                    if (!controller.isEnabled()) {
                        RestoreStepResult("restore_webui", true, "not_enabled")
                    } else {
                        val status = runBlocking { controller.start() }
                        RestoreStepResult(
                            "restore_webui", status.running,
                            if (status.running) "" else status.error.ifEmpty { FullRestoreCodes.WEBUI_FAILED },
                        )
                    }
                },
                restoreComponents = {
                    runCatching {
                        packageManager.setComponentEnabledSetting(
                            ComponentName(app.packageName, "com.maplesu.core.ui.LauncherAlias"),
                            PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
                            PackageManager.DONT_KILL_APP,
                        )
                        RestoreStepResult("restore_components", true)
                    }.getOrElse {
                        RestoreStepResult(
                            "restore_components", false,
                            "${FullRestoreCodes.COMPONENTS_FAILED}:${it.javaClass.simpleName}",
                        )
                    }
                },
                verify = {
                    val stateOut = RootExec.execute("cat '${LiteHiddenPaths.STATE_PATH}' 2>/dev/null")
                    val installed = runCatching {
                        packageManager.getPackageInfo(app.packageName, 0)
                        true
                    }.getOrDefault(false)
                    val ok = installed && stateOut.ok && stateOut.output.trim().startsWith("0")
                    RestoreStepResult("verify", ok, if (ok) "" else FullRestoreCodes.VERIFY_FAILED)
                },
            )
        }
    }
}
