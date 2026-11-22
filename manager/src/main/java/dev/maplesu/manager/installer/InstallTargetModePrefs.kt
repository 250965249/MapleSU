// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.installer

import android.content.Context
import dev.maplesu.manager.workmode.storage.ModeStorage

/**
 * 「目标工作模式」选择的 Android 持久化（中性 prefs `workmode_state`）。
 *
 * 为什么是**中性** prefs：选择与当前激活模式无关（Ultra 设备也能修补 Normal 目标），
 * 若落 `settings` / `settings_B` 就会随模式切换读到不同文件，选择会"丢"。
 * `ModeStorage.neutralPrefs()` 是 01 §3.3 规定的唯一带外入口（禁止在 workmode 之外
 * 直接打开 `settings` 这个 prefs 文件）。
 *
 * 默认 Ultra 由 [InstallTargetModeStore.load] 保证：读不到 / 坏值 / 升级后首次启动都是 Ultra。
 */
class InstallTargetModePrefs(context: Context) : InstallTargetPrefsPort {

    private val prefs = ModeStorage(context.applicationContext).neutralPrefs()

    override fun getString(key: String): String? = prefs.getString(key, null)

    override fun putString(key: String, value: String) {
        prefs.edit().putString(key, value).apply()
    }

    companion object {
        /** 页面用：只构造一个 store，不关心 Android 细节。 */
        fun store(context: Context): InstallTargetModeStore =
            InstallTargetModeStore(InstallTargetModePrefs(context))
    }
}
