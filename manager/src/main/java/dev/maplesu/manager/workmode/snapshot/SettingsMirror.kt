package dev.maplesu.manager.workmode.snapshot

/**
 * 设置镜像的键表与敏感键排除。
 *
 * 绝不允许凭据/rootKey/stealth_code 进镜像（发布红线 7）。
 */
object SettingsMirror {
    /** 命中即排除（键名大小写不敏感的子串）。 */
    val SENSITIVE_KEY_TOKENS: List<String> = listOf(
        "stealth_code", "stealthcode", "rootkey", "root_key", "rootKey", "credential",
        "token", "password", "secret", "maplesu-ultra", "pro_key",
    )

    fun isSensitiveKey(key: String): Boolean {
        val lower = key.lowercase()
        return SENSITIVE_KEY_TOKENS.any { lower.contains(it.lowercase()) }
    }

    /** 只保留可镜像键（非敏感）；顺序按 key 排序保证稳定。 */
    fun mirrorable(entries: Map<String, String>): Map<String, String> =
        entries.filterKeys { !isSensitiveKey(it) }.toSortedMap()

    data class MergeResult(
        /** 需要写入本地的键（全量恢复或补缺/覆盖）。 */
        val restored: Map<String, String>,
        /** 保留本地值（镜像不覆盖）。 */
        val skipped: Map<String, String>,
        /** 冲突且镜像 revision 更新：需要用户确认后才覆盖。 */
        val requiresConfirmation: List<String>,
        val blocker: String?,
    )

    /**
     * merge 语义（01 §5.4）：
     * - 本地为空（典型：清数据后）→ 全量写入镜像值；
     * - 本地非空 → **只补缺键**，已有键保留本地值；
     * - 冲突且镜像 `revision > appPrefsRevision` → 需用户确认后才覆盖；
     * - 镜像损坏/缺 sha → 由调用方给 blocker，本函数不做 I/O。
     */
    fun merge(
        local: Map<String, String>,
        mirror: Map<String, String>,
        mirrorRevision: Long,
        localRevision: Long,
        allowOverwrite: Boolean,
    ): MergeResult {
        val safeMirror = mirrorable(mirror)
        if (local.isEmpty()) {
            return MergeResult(restored = safeMirror, skipped = emptyMap(), requiresConfirmation = emptyList(), blocker = null)
        }
        val restored = linkedMapOf<String, String>()
        val skipped = linkedMapOf<String, String>()
        val confirm = mutableListOf<String>()
        for ((key, value) in safeMirror) {
            val localValue = local[key]
            if (localValue == null) {
                restored[key] = value
            } else if (localValue == value) {
                skipped[key] = localValue
            } else if (mirrorRevision > localRevision) {
                if (allowOverwrite) restored[key] = value else confirm += key
            } else {
                skipped[key] = localValue
            }
        }
        return MergeResult(
            restored = restored,
            skipped = skipped,
            requiresConfirmation = confirm.sorted(),
            blocker = if (confirm.isNotEmpty()) SnapshotErrors.CONFIRM_REQUIRED else null,
        )
    }
}
