package dev.maplesu.manager.workmode.detect

import dev.maplesu.manager.workmode.WorkMode

/**
 * 判定输出的"可恢复性"摘要：
 * UI 恢复页与 E7 验收需要，blockers 必须原样进 evidence.jsonl 与恢复页，
 * 绝不允许"静默恢复失败"。
 */
data class RecoveryReadiness(
    val controlPlaneReachable: Boolean,
    val restorableMode: WorkMode?,
    val restorableSettingsRevision: Long?,
    val restorableSuperuserRevision: Long?,
    val hasSnapshot: Boolean,
    val blockers: List<String>,
) {
    companion object {
        val NONE: RecoveryReadiness =
            RecoveryReadiness(false, null, null, null, false, emptyList())

        const val NO_ROOT_CHANNEL = "NO_ROOT_CHANNEL"
        const val CONTROL_MODES_MISSING = "CONTROL_MODES_MISSING"
        const val LITE_CREDENTIAL_UNUSABLE = "LITE_CREDENTIAL_UNUSABLE"
        const val KEYSTORE_LOST = "KEYSTORE_LOST"
        const val SNAPSHOT_MISSING = "SNAPSHOT_MISSING"
    }
}
