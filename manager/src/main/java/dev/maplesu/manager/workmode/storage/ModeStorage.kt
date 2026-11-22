package dev.maplesu.manager.workmode.storage

import dev.maplesu.manager.compat.ultraPreferences

import android.content.Context
import android.content.SharedPreferences
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import java.io.File

/**
 * App 侧命名空间解析门面。
 *
 * 解析顺序：进程内 `ModeRuntime.active`（唯一权威）→ 中性 prefs 的"上次模式"提示
 * （`active_boot_id != 当前 bootId` → STALE_HINT，只影响骨架屏）→ 控制面（root 可读）。
 *
 * 禁止：直接 `getSharedPreferences("settings")`（现有 5 处绕过点，§3.3）；
 * 未判定时回落 LITE。未激活时 [prefs] 抛 MODE_NOT_RESOLVED。
 */
class ModeStorage(
    private val context: Context,
    /** 02 §5.5 的 pending 阻断查询（由切换服务注入；未接线时视为不阻断）。 */
    private val pendingSwitchProbe: (() -> Boolean)? = null,
) {
    private fun requireMode(mode: WorkMode?): WorkMode =
        mode ?: throw IllegalStateException("MODE_NOT_RESOLVED")

    /** 当前模式私有 prefs；[legacyName] 用 §3.2 的原名（如 "settings"）。 */
    fun prefs(legacyName: String, mode: WorkMode? = ModeRuntime.active): SharedPreferences {
        val resolved = requireMode(mode)
        val name = requireNotNull(ModePaths.prefsNameFor(legacyName, resolved)) {
            "PREFS_NOT_USED_BY_MODE:${resolved.suffix}:$legacyName"
        }
        return context.ultraPreferences(name, Context.MODE_PRIVATE)
    }

    /** 中性 prefs（唯一不带模式后缀的新 prefs）。 */
    fun neutralPrefs(): SharedPreferences =
        context.ultraPreferences(ModePaths.NEUTRAL_PREFS, Context.MODE_PRIVATE)

    /** filesDir 子目录：A 原名 / B filesDir/ksu/<sub>。 */
    fun filesDir(sub: String, mode: WorkMode? = ModeRuntime.active): File =
        File(ModePaths.filesDir(context.filesDir.path, sub, requireMode(mode)))

    /** 中性诊断/缓存目录（与模式无关）。 */
    fun neutralFilesDir(sub: String): File = File(context.filesDir, sub)

    fun noBackupFile(name: String): File = File(context.noBackupFilesDir, name)

    /** 启动瞬间的"上次模式"提示；bootId 不匹配 → STALE（只影响骨架屏）。 */
    fun lastKnownMode(currentBootId: String?): LastKnownHint {
        val prefs = neutralPrefs()
        val mode = WorkMode.fromWire(prefs.getString(ModePaths.KEY_ACTIVE_MODE, null))
        val bootId = prefs.getString(ModePaths.KEY_ACTIVE_BOOT_ID, null)
        return LastKnownHint(
            mode = mode,
            bootId = bootId,
            stale = bootId != null && currentBootId != null && bootId != currentBootId,
        )
    }

    /** 回写中性 prefs 的"上次模式"（控制面可读时以控制面为准，§3.1）。 */
    fun rememberActiveMode(mode: WorkMode, bootId: String) {
        neutralPrefs().edit()
            .putString(ModePaths.KEY_ACTIVE_MODE, mode.suffix)
            .putString(ModePaths.KEY_ACTIVE_BOOT_ID, bootId)
            .putInt(ModePaths.KEY_SCHEMA, 1)
            .apply()
    }

    /** 02 §5.5：有非终态切换 → 阻断普通写入与自动部署（恢复入口豁免）。 */
    fun isWriteBlocked(): Boolean = pendingSwitchProbe?.invoke() ?: false

    data class LastKnownHint(
        val mode: WorkMode?,
        val bootId: String?,
        /** active_boot_id != 当前 bootId → STALE_HINT。 */
        val stale: Boolean,
    )
}
