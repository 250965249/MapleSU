package dev.maplesu.manager.workmode.control.schema

import kotlinx.serialization.Serializable

/** `control/publish.json`：`/data/<16hex>` 发布目录的镜像。 */
@Serializable
data class PublishFile(
    val schema: Int = SCHEMA,
    val updatedAt: Long,
    val bootId: String,
    /** 当前 /data/<16hex>。 */
    val current: String? = null,
    /** 已清理的旧名（上限 16）。 */
    val previous: List<String> = emptyList(),
    /** /data/<16hex>/authorized 的 sha。 */
    val authorizedSha256: String? = null,
    val entries: List<PublishEntry> = emptyList(),
) {
    companion object {
        const val SCHEMA = 1
        const val MAX_PREVIOUS = 16
    }
}

@Serializable
data class PublishEntry(
    val path: String,
    /** "SYMLINK" | "FILE" | "DIR"。 */
    val kind: String,
    val target: String? = null,
    val sha256: String? = null,
)

fun PublishFile.canonicalized(): PublishFile = copy(
    previous = previous.distinct().sorted(),
    entries = entries.sortedWith(compareBy({ it.path }, { it.kind })),
)
