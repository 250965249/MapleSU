package dev.maplesu.manager.installer

import android.content.Context
import android.content.SharedPreferences
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.storage.SettingsPrefsRouter

/**
 * P1：installer prefs 的 Android 门面。每次访问重新解析（模式切换会重启进程），
 * 未判定时复用 [SettingsPrefsRouter] 的 lastKnown/证据裁决，不复制策略。
 */
internal class InstallerPrefsRouter(private val context: Context) {
    private val settings = SettingsPrefsRouter(context)

    fun prefsName(active: WorkMode? = ModeRuntime.active): String =
        if (active != null) {
            InstallerPrefsPolicy.nameForResolved(active)
        } else {
            InstallerPrefsPolicy.nameForUnresolved(settings.prefsName(null))
        }

    fun prefs(active: WorkMode? = ModeRuntime.active): SharedPreferences =
        context.getSharedPreferences(prefsName(active), Context.MODE_PRIVATE)
}
