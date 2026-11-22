package com.maplesu.core.ui.screen.module

/** Reserve an independent toggle row before text becomes cramped at larger font scales. */
internal fun moduleCardNeedsOwnToggleRow(availableWidthDp: Float, fontScale: Float): Boolean =
    availableWidthDp / fontScale.coerceAtLeast(1f) < 340f

internal enum class ModuleCardStatus(val isError: Boolean = false) {
    NONE, MODULE_RUNNING, MODULE_NOT_RUNNING, MODULE_ABNORMAL(true), MODULE_UNKNOWN,
    STORED_ULTRA, STORED, REMOVE_PENDING, DISABLED, FAILED(true),
    SCRIPT_RUNNING, INSTALLED, LATE_COMPLETED, LATE_PENDING;

    val needsAttention: Boolean
        get() = when (this) {
            STORED_ULTRA, STORED, REMOVE_PENDING -> true
            else -> isError
        }
}

/** SDK module lifecycle and script-task lifecycle have different meanings for “running”. */
internal fun moduleCardStatus(runtimeStatus: String, isMapleSu: Boolean): ModuleCardStatus {
    if (isMapleSu) {
        return when (runtimeStatus) {
            "running" -> ModuleCardStatus.MODULE_RUNNING
            "not_running" -> ModuleCardStatus.MODULE_NOT_RUNNING
            "abnormal" -> ModuleCardStatus.MODULE_ABNORMAL
            "removed_pending_reboot", "remove_pending" -> ModuleCardStatus.REMOVE_PENDING
            "stored_ultra" -> ModuleCardStatus.STORED_ULTRA
            "stored" -> ModuleCardStatus.STORED
            else -> ModuleCardStatus.MODULE_UNKNOWN
        }
    }
    return when (runtimeStatus) {
        "stored_ultra" -> ModuleCardStatus.STORED_ULTRA
        "stored" -> ModuleCardStatus.STORED
        "remove_pending" -> ModuleCardStatus.REMOVE_PENDING
        "disabled" -> ModuleCardStatus.DISABLED
        "failed" -> ModuleCardStatus.FAILED
        "running" -> ModuleCardStatus.SCRIPT_RUNNING
        "installed" -> ModuleCardStatus.INSTALLED
        "late_completed" -> ModuleCardStatus.LATE_COMPLETED
        "late_pending" -> ModuleCardStatus.LATE_PENDING
        else -> ModuleCardStatus.NONE
    }
}
