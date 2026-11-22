package dev.maplesu.manager.runtime

import dev.maplesu.manager.jailbreak.JailbreakController
import dev.maplesu.manager.jailbreak.JailbreakStatus

/** A recovery reply must distinguish an absent carrier from a failed recovery. */
internal data class HookReproofResult(
    val eligible: Boolean?,
    val reproved: Boolean,
    val attemptId: String?,
    val bootId: String?,
    val failure: String?,
) {
    fun outcome(expectedAttemptId: String?, currentBootId: String?): JailbreakController.Outcome? {
        if (eligible == false && !reproved && failure == null) return null
        val reason = failure ?: when {
            eligible != true -> "HOOK_BACKEND_NOT_READY:reproof_reply_invalid"
            attemptId.isNullOrBlank() || attemptId != expectedAttemptId ->
                "HOOK_BACKEND_NOT_READY:reproof_attempt_mismatch"
            bootId.isNullOrBlank() || bootId != currentBootId ->
                "HOOK_BACKEND_NOT_READY:reproof_boot_mismatch"
            !reproved -> "HOOK_BACKEND_NOT_READY:reproof_failed"
            else -> null
        }
        return JailbreakController.Outcome(
            if (reason == null) JailbreakStatus.STAGE_DAEMON_READY else JailbreakStatus.STAGE_FAILED,
            reason ?: "existing session re-proved after reboot", reason, attemptId)
    }
}
