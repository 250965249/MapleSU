package com.maplesu.core.ui.util

import android.content.Context
import androidx.core.content.edit
import java.security.MessageDigest

/** 按公告内容指纹保存已读状态；新公告显示一次，旧公告不重复提示。 */
object AnnouncementPrefs {

    /** 与 `SettingsRepositoryImpl` / `WallpaperPrefs` 读的是同一份 prefs。 */
    private const val PREFS = "settings"

    /** 上一次"弹过并点掉"的公告指纹。 */
    private const val KEY_SEEN = "announcement_seen_key"

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** 已经弹过并点掉的公告指纹；从没弹过就是空串。 */
    fun seenKey(context: Context): String =
        prefs(context).getString(KEY_SEEN, "") ?: ""

    /** 记下"这条公告弹过了、用户点掉了"。 */
    fun markSeen(context: Context, key: String) {
        prefs(context).edit { putString(KEY_SEEN, key) }
    }

    /** 标题与正文的 SHA-256 前 16 位十六进制，沿用既有指纹格式。 */
    fun keyOf(title: String, content: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest("$title\n$content".toByteArray(Charsets.UTF_8))
        return digest.take(8).joinToString("") { "%02x".format(it) }
    }
}
