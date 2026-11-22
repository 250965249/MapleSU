package dev.maplesu.manager.workmode.control.schema

import kotlinx.serialization.Serializable

/** `control/selinux.json`：SELinux label 记录。 */
@Serializable
data class SelinuxFile(
    val schema: Int = SCHEMA,
    val updatedAt: Long,
    val bootId: String,
    val entries: List<SelinuxEntry>,
    /**
     * 恒为 false：本产品从不写 `/sys/fs/selinux/load`（主文档:604）。
     * 读到时为 true → 视为损坏/被篡改。
     */
    val policyWritten: Boolean = false,
) {
    companion object { const val SCHEMA = 1 }
}

@Serializable
data class SelinuxEntry(
    val path: String,
    /** `u:object_r:<type>:s0`。 */
    val label: String,
    val owner: Int,
    val mode: Int,
    /** "FILE" | "DIR" | "SYMLINK"。 */
    val kind: String,
    val recordedAt: Long,
)

fun SelinuxFile.canonicalized(): SelinuxFile = copy(
    entries = entries.sortedWith(compareBy({ it.path }, { it.kind })),
)

/** 只允许现有 SELinux type（不新增 type/allow、不得 permissive）。 */
object SelinuxLabels {
    const val SYSTEM_FILE = "u:object_r:system_file:s0"
    const val KSU_FILE = "u:object_r:ksu_file:s0"
    const val ADB_DATA_FILE = "u:object_r:adb_data_file:s0"

    private val allowedTypes = setOf("system_file", "ksu_file", "adb_data_file", "su_file", "magisk_file")

    /** `ls -Z` 输出提取标签；格式不符返回 null。 */
    fun parseLsZ(raw: String): String? {
        val match = Regex("u:object_r:([a-z0-9_]+):s0").find(raw) ?: return null
        if (match.groupValues[1] !in allowedTypes) return null
        return match.value
    }
}
