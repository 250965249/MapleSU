package dev.maplesu.manager.workmode.snapshot

import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.control.schema.SnapshotManifest

/** 快照服务接口。 */
interface SnapshotService {
    /** 生成快照；成功后才允许进入切换的 S4。 */
    suspend fun create(request: SnapshotRequest): SnapshotResult

    /** App 数据被清后从控制面恢复；merge 语义见 §5.4。 */
    suspend fun restore(request: RestoreRequest): RestoreResult
}

data class SnapshotRequest(
    val mode: WorkMode,
    val switchId: String?,
    val reason: SnapshotReason,
    val includeSecrets: Boolean,
)

enum class SnapshotReason { PRE_SWITCH, PERIODIC, BOOT_COMPLETED, MANUAL }

sealed interface SnapshotResult {
    data class Ok(val manifest: SnapshotManifest, val storePath: String) : SnapshotResult
    /** 无 root / 非活动模式。 */
    data class Skipped(val reason: String) : SnapshotResult
    data class Failed(val code: String, val detail: String) : SnapshotResult
}

data class RestoreRequest(
    val mode: WorkMode,
    val allowOverwrite: Boolean,
    val reason: RestoreReason,
    /** 不传则取该模式下最新可用快照。 */
    val revision: Long? = null,
)

enum class RestoreReason { AFTER_CLEAR_DATA, USER_REQUEST, SWITCH_COMMITTED }

data class RestoreResult(
    val settingsRestored: Int,
    val settingsSkipped: Int,
    val secretsRestored: Boolean,
    val moduleLinksRebuilt: Int,
    val superuserApplied: Boolean,
    /** NO_KEYSTORE / SNAPSHOT_MISSING / SHA_MISMATCH / NO_ROOT / CONFIRM_REQUIRED。 */
    val blockers: List<String>,
)

object SnapshotErrors {
    const val SNAPSHOT_TOO_LARGE = "SNAPSHOT_TOO_LARGE"
    const val SNAPSHOT_COPY_FAILED = "SNAPSHOT_COPY_FAILED"
    const val SNAPSHOT_MANIFEST_FAILED = "SNAPSHOT_MANIFEST_FAILED"
    const val SNAPSHOT_ENTRIES_UNSORTED = "SNAPSHOT_ENTRIES_UNSORTED"
    const val SNAPSHOT_NOT_FOUND = "SNAPSHOT_MISSING"
    const val SNAPSHOT_CORRUPT = "SHA_MISMATCH"
    const val CONFIRM_REQUIRED = "CONFIRM_REQUIRED"
    const val NO_ROOT = "NO_ROOT"
    const val NO_KEYSTORE = "NO_KEYSTORE"
}
