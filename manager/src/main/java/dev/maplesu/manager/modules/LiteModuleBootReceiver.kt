package dev.maplesu.manager.modules

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import dev.maplesu.manager.workmode.ModeRuntime

/** CE storage and the Keystore credential are read only after the user has unlocked. */
class LiteModuleBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        // 模式门（2026-11-01）：Lite 脚本模块的 late-boot 只属于 LITE。Normal（KSU）的模块
        // 由 ksud 在内核侧处理；未判定也不得执行（fail-closed，绝不默认 LITE）。
        // 双保险：`LiteModuleBootService.request` 里还有一道同样的门。
        if (!LiteModuleBootService.allowsRun(ModeRuntime.active)) {
            Log.i(
                "MapleSUModules",
                "lite module worker receiver skipped: active mode=${ModeRuntime.active}",
            )
            return
        }
        runCatching { LiteModuleBootService.request(context) }
            .onFailure { Log.w("MapleSUModules", "Late module worker was not started", it) }
    }
}
