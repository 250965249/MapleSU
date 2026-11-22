package dev.maplesu.manager.workmode.boot

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.gating.ModeComponentIds

/**
 * A 专属组件的启停。
 *
 * 规则（**顺序敏感**）：
 * - `LITE`：**什么都不做**。不主动 enable：用户可能手动禁用过某组件，A 不该替他改回来
 *   （`autoJailbreak` 的既有 setter 仍负责它自己的组件）。
 * - `KSU`：把 A 专属组件设为 DISABLED（`DONT_KILL_APP`）。`NativeSuBrokerService` 是
 *   `exported=true` 的公开发现服务，B 下必须禁用，且各组件入口仍要**代码二次门控**。
 * - `null`（未判定）：**什么都不做**，等激活后再调用（04 §1.6）。
 *
 * 组件级禁用只是辅助（主文档:392）：PackageManager 状态跨模式持久，代码门控才是主判据。
 */
object ModeComponentSwitcher {

    fun apply(context: Context, mode: WorkMode) {
        when (mode) {
            WorkMode.LITE -> Unit // 原实现不动；见类注释
            WorkMode.KSU -> disableAll(context)
        }
    }

    /** 诊断用：返回每个受控组件的 enabled 状态（未声明的组件不会出现）。 */
    fun snapshot(context: Context): Map<String, Int> {
        val pm = context.packageManager
        return ModeComponentIds.KSU_DISABLED_COMPONENTS.mapNotNull { className ->
            runCatching {
                val info = pm.getComponentEnabledSetting(ComponentName(context.packageName, className))
                className to info
            }.getOrNull()
        }.toMap()
    }

    private fun disableAll(context: Context) {
        context.stopService(Intent().setClassName(context, ModeComponentIds.COMPONENT_HOOK_SU_KEEPER_SERVICE))
        val pm = context.packageManager
        ModeComponentIds.KSU_DISABLED_COMPONENTS.forEach { className ->
            runCatching {
                pm.setComponentEnabledSetting(
                    ComponentName(context.packageName, className),
                    PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                    PackageManager.DONT_KILL_APP,
                )
            }
        }
    }
}
