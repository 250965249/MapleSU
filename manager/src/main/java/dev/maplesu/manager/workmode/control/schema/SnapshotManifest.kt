package dev.maplesu.manager.workmode.control.schema

import kotlinx.serialization.Serializable

/**
 * 完整快照 manifest。
 *
 * `sha256` 的三种语义必须区分：FILE=文件字节；DIR=子项排序拼接；SYMLINK=sha256(linkTarget)。
 */
@Serializable
data class SnapshotManifest(
    val schema: Int = SCHEMA,
    /** "rev-<revision>-<mode>"。 */
    val id: String,
    val revision: Long,
    val mode: String,
    val createdAt: Long,
    val bootId: String,
    val app: AppSnapshotFacts,
    /** 按 storePath 排序，保证字节稳定。 */
    val entries: List<SnapshotEntry>,
    val excluded: List<ExcludedEntry>,
    val totals: Totals,
    val integrity: Integrity,
) {
    companion object { const val SCHEMA = 1 }
}

@Serializable
data class AppSnapshotFacts(
    val packageName: String,
    val versionCode: Long,
    val apkSha256: String,
    val signerSha256: List<String>,
    val settingsRevision: Long,
    val appPrefsRevision: Long,
)

@Serializable
data class SnapshotEntry(
    /** "APP_FILE" | "APP_TREE" | "ROOT_TREE" | "ROOT_SYMLINK" | "EXTERNAL" | "SECRET"。 */
    val kind: String,
    /** App 私有项写相对 filesDir 的路径，root 项写绝对路径。 */
    val livePath: String,
    /** 相对 modes/<M>/。 */
    val storePath: String,
    /** "FILE" | "DIR" | "SYMLINK"。 */
    val type: String,
    val size: Long,
    val sha256: String,
    val linkTarget: String? = null,
    /** 权限位（如 0x1A4 = 0644）。 */
    val mode: Int,
    val uid: Int,
    val gid: Int,
    /** 读到才写（跨挂载恢复必需）。 */
    val selinux: String? = null,
    /** "A" | "B" | "NEUTRAL"。 */
    val origin: String,
)

@Serializable
data class ExcludedEntry(val livePath: String, val reason: String)

@Serializable
data class Totals(val entryCount: Int, val fileCount: Int, val bytes: Long)

@Serializable
data class Integrity(val canonicalSha256: String, val algorithm: String = "sha256")

/** manifest canonical 形态（entries 按 storePath 排序、签名列表排序）。 */
fun SnapshotManifest.canonicalized(): SnapshotManifest = copy(
    app = app.copy(signerSha256 = app.signerSha256.sorted()),
    entries = entries.sortedWith(compareBy({ it.storePath }, { it.type })),
    excluded = excluded.sortedWith(compareBy({ it.livePath }, { it.reason })),
)
