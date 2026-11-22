package dev.maplesu.manager.workmode.snapshot

import dev.maplesu.manager.workmode.control.schema.ExcludedEntry

/**
 * 快照白名单 / 排除 / 容量常量。
 *
 * 只快照"已登记"的路径；未登记路径一律不碰（主文档:294、:321）。
 */
object SnapshotScope {
    /** 单快照上限（05:573、05:847 Q8 未定，取默认值）。 */
    const val MAX_SNAPSHOT_BYTES: Long = 512L * 1024 * 1024

    /** App 私有模块实体（整树复制）。 */
    val APP_TREES: List<String> = listOf("module-catalog", "module-runtime")

    /** 图片/外观（默认只存 sha + 文件名；视频默认不入快照）。 */
    val APP_FILES: List<String> = listOf(
        "wallpaper", "wallpaper_land", "status_decoration.png",
        "module_icons", "module_cards", "nav_icons",
    )

    /** 明确排除的路径模式（含原因码）。 */
    data class ExcludedRule(val prefix: String, val suffix: String, val reason: String)

    val EXCLUDED_RULES: List<ExcludedRule> = listOf(
        ExcludedRule("module-catalog/staged/", ".zip", ExcludedEntryReasons.CACHE),
        ExcludedRule("module-catalog/staged/", ".tmp", ExcludedEntryReasons.CACHE),
        ExcludedRule("cache/", "", ExcludedEntryReasons.CACHE),
        ExcludedRule("tmp/", "", ExcludedEntryReasons.CACHE),
        ExcludedRule("", ".log", ExcludedEntryReasons.LOG),
        ExcludedRule("", ".mp4", ExcludedEntryReasons.TOO_LARGE),
        ExcludedRule("", ".webm", ExcludedEntryReasons.TOO_LARGE),
        ExcludedRule("", "maplesu-credential.bin", ExcludedEntryReasons.NO_BACKUP_SECRET),
        ExcludedRule("", dev.maplesu.manager.compat.StoredInputs.CREDENTIAL_FILE, ExcludedEntryReasons.NO_BACKUP_SECRET),
        ExcludedRule("", "authorizations.bin", ExcludedEntryReasons.NO_BACKUP_SECRET),
    )

    /** 排除原因码（ExcludedEntry.reason 的取值域）。 */
    object ExcludedEntryReasons {
        const val NO_BACKUP_SECRET = "NO_BACKUP_SECRET"
        const val TOO_LARGE = "TOO_LARGE"
        const val CACHE = "CACHE"
        const val LOG = "LOG"
        const val UNREGISTERED = "UNREGISTERED"
        val ALL: Set<String> = setOf(NO_BACKUP_SECRET, TOO_LARGE, CACHE, LOG, UNREGISTERED)
    }

    /** 归一化相对路径（'/' 分隔、无前导 '/'）。 */
    fun normalize(relativePath: String): String = relativePath.replace('\\', '/').trimStart('/')

    /** 该相对路径属于哪一类快照条目；null = 不在白名单。 */
    fun classify(relativePath: String): String? {
        val path = normalize(relativePath)
        for (tree in APP_TREES) {
            if (path == tree || path.startsWith("$tree/")) return KIND_APP_TREE
        }
        for (item in APP_FILES) {
            if (path == item || path.startsWith("$item/")) return KIND_APP_FILE
        }
        return null
    }

    /** 若路径被排除，返回带原因的条目（ExcludedEntry.reason 必须来自 [ExcludedEntryReasons]）。 */
    fun exclusionFor(relativePath: String): ExcludedEntry? {
        val path = normalize(relativePath)
        val rule = EXCLUDED_RULES.firstOrNull { rule ->
            (rule.prefix.isEmpty() || path.startsWith(rule.prefix)) &&
                (rule.suffix.isEmpty() || path.endsWith(rule.suffix) || path.contains("${rule.suffix}/"))
        } ?: return null
        return ExcludedEntry(livePath = path, reason = rule.reason)
    }

    /** 白名单内且未被排除 → 可进快照。 */
    fun isSnapshotCandidate(relativePath: String): Boolean =
        classify(relativePath) != null && exclusionFor(relativePath) == null

    const val KIND_APP_FILE = "APP_FILE"
    const val KIND_APP_TREE = "APP_TREE"
    const val KIND_ROOT_TREE = "ROOT_TREE"
    const val KIND_ROOT_SYMLINK = "ROOT_SYMLINK"
    const val KIND_EXTERNAL = "EXTERNAL"
    const val KIND_SECRET = "SECRET"

    const val TYPE_FILE = "FILE"
    const val TYPE_DIR = "DIR"
    const val TYPE_SYMLINK = "SYMLINK"

    const val ORIGIN_A = "A"
    const val ORIGIN_B = "B"
    const val ORIGIN_NEUTRAL = "NEUTRAL"
}
