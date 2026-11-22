package dev.maplesu.manager.workmode.ui

import androidx.annotation.StringRes
import com.maplesu.core.R
import dev.maplesu.manager.workmode.migration.MigrationFamilyKeys
import dev.maplesu.manager.workmode.migration.MigrationBlockerKeys
import dev.maplesu.manager.workmode.migration.MigrationResultKind
import dev.maplesu.manager.workmode.migration.MigrationStage
import dev.maplesu.manager.workmode.recovery.RecoveryAction
import dev.maplesu.manager.workmode.recovery.RecoveryReason
import dev.maplesu.manager.workmode.switch.BaselineState

internal object MigrationStrings {
    @StringRes fun stage(stage: MigrationStage): Int = when (stage) {
        MigrationStage.IDLE -> R.string.migration_stage_idle
        MigrationStage.DETECTING -> R.string.migration_stage_detecting
        MigrationStage.DETECTED -> R.string.migration_stage_detected
        MigrationStage.CONFIRMING -> R.string.migration_stage_confirming
        MigrationStage.BACKING_UP -> R.string.migration_stage_backing_up
        MigrationStage.RESTORING_EXTERNAL -> R.string.migration_stage_restoring
        MigrationStage.WRITING_TARGET -> R.string.migration_stage_writing
        MigrationStage.DEPLOYING -> R.string.migration_stage_deploying
        MigrationStage.PENDING_REBOOT -> R.string.migration_stage_pending_reboot
        MigrationStage.VERIFYING -> R.string.migration_stage_verifying
        MigrationStage.COMPLETED -> R.string.migration_stage_completed
        MigrationStage.FAILED -> R.string.migration_stage_failed
        MigrationStage.ROLLED_BACK -> R.string.migration_stage_rolled_back
        MigrationStage.RECOVERY_REQUIRED -> R.string.migration_stage_recovery
        MigrationStage.UNAVAILABLE -> R.string.migration_stage_unavailable
    }
    @StringRes fun family(key: String): Int = when (key) {
        MigrationFamilyKeys.KSU -> R.string.migration_family_ksu
        MigrationFamilyKeys.MAPLESU -> R.string.migration_family_maplesu
        MigrationFamilyKeys.MAGISK -> R.string.migration_family_magisk
        MigrationFamilyKeys.APATCH -> R.string.migration_family_apatch
        else -> R.string.migration_family_unknown
    }
    @StringRes fun blocker(key: String): Int = when (key) {
        MigrationBlockerKeys.NO_ROOT -> R.string.migration_blocker_no_root
        MigrationBlockerKeys.NO_SPACE -> R.string.migration_blocker_no_space
        MigrationBlockerKeys.PENDING -> R.string.migration_blocker_pending
        MigrationBlockerKeys.LAYOUT -> R.string.migration_blocker_layout
        MigrationBlockerKeys.CANDIDATE -> R.string.migration_blocker_candidate
        MigrationBlockerKeys.CLEAN_IMAGE -> R.string.migration_blocker_clean_image
        MigrationBlockerKeys.OWN_MANAGER -> R.string.migration_blocker_own_manager
        else -> R.string.migration_blocker_unknown
    }
    @StringRes fun result(kind: MigrationResultKind): Int = when (kind) {
        MigrationResultKind.VERIFIED -> R.string.migration_result_verified
        MigrationResultKind.FAILED -> R.string.migration_result_failed
        MigrationResultKind.ROLLED_BACK -> R.string.migration_result_rolled_back
        MigrationResultKind.RECOVERY_REQUIRED -> R.string.migration_result_recovery
    }
}

internal object RecoveryStrings {
    @StringRes fun action(action: RecoveryAction?): Int = when (action) {
        RecoveryAction.NONE -> R.string.recovery_action_none
        RecoveryAction.IN_PROGRESS -> R.string.recovery_action_in_progress
        RecoveryAction.RESUME_REBOOT -> R.string.recovery_action_resume_reboot
        RecoveryAction.AUTO_VERIFY -> R.string.recovery_action_auto_verify
        RecoveryAction.AUTO_ROLLBACK -> R.string.recovery_action_auto_rollback
        RecoveryAction.EXTERNAL_RECOVERY -> R.string.recovery_action_external
        RecoveryAction.FORBIDDEN -> R.string.recovery_action_forbidden
        null -> R.string.recovery_unavailable
    }

    @StringRes fun next(key: String?): Int = when (key) {
        "recovery_next_none" -> R.string.recovery_next_none
        "recovery_next_wait" -> R.string.recovery_next_wait
        "recovery_next_reboot" -> R.string.recovery_next_reboot
        "recovery_next_verify" -> R.string.recovery_next_verify
        "recovery_next_rollback" -> R.string.recovery_next_rollback
        "recovery_next_import_baseline" -> R.string.recovery_next_import_baseline
        "recovery_next_external" -> R.string.recovery_external_hint
        else -> R.string.recovery_next_diagnosis
    }

    @StringRes fun baseline(state: BaselineState): Int = when (state) {
        BaselineState.PRESENT_OK -> R.string.recovery_baseline_ok
        BaselineState.MISSING_NEVER_CAPTURED -> R.string.recovery_baseline_missing
        BaselineState.IMPORT_REQUIRED -> R.string.recovery_baseline_import
        BaselineState.STALE -> R.string.recovery_baseline_stale
        BaselineState.CORRUPT -> R.string.recovery_baseline_corrupt
    }

    @StringRes fun reason(reason: RecoveryReason): Int = when (reason) {
        RecoveryReason.NO_PENDING_SWITCH -> R.string.recovery_reason_none
        RecoveryReason.SWITCH_ACTIVE -> R.string.recovery_reason_active
        RecoveryReason.ROLLBACK_ACTIVE -> R.string.recovery_reason_rolling_back
        RecoveryReason.REBOOT_REQUIRED -> R.string.recovery_reason_reboot
        RecoveryReason.REBOOT_OBSERVED -> R.string.recovery_reason_reboot_observed
        RecoveryReason.REBOOT_NOT_OBSERVED -> R.string.recovery_reason_reboot_missing
        RecoveryReason.REBOOT_LIMIT_REACHED -> R.string.recovery_reason_reboot_limit
        RecoveryReason.VERIFY_PENDING -> R.string.recovery_reason_verify
        RecoveryReason.VERIFIED -> R.string.recovery_reason_verified
        RecoveryReason.ROLLED_BACK -> R.string.recovery_reason_rolled_back
        RecoveryReason.FAILED_PRE_WRITE -> R.string.recovery_reason_failed_pre_write
        RecoveryReason.CANCELLED -> R.string.recovery_reason_cancelled
        RecoveryReason.RECOVERY_REQUIRED -> R.string.recovery_reason_required
        RecoveryReason.ROLLBACK_AVAILABLE -> R.string.recovery_reason_rollback_available
        RecoveryReason.VERIFY_FAILED_TWICE -> R.string.recovery_reason_verify_failed_twice
        RecoveryReason.BASELINE_OK -> R.string.recovery_reason_baseline_ok
        RecoveryReason.BASELINE_MISSING -> R.string.recovery_reason_baseline_missing
        RecoveryReason.BASELINE_STALE -> R.string.recovery_reason_baseline_stale
        RecoveryReason.BASELINE_CORRUPT -> R.string.recovery_reason_baseline_corrupt
        RecoveryReason.BASELINE_IMPORT_REQUIRED -> R.string.recovery_reason_baseline_import
        RecoveryReason.NO_ROOT_CHANNEL -> R.string.recovery_reason_no_root
        RecoveryReason.DEVICE_MISMATCH -> R.string.recovery_reason_device_changed
        RecoveryReason.JOURNAL_CORRUPT -> R.string.recovery_reason_journal_corrupt
        RecoveryReason.JOURNAL_MISSING -> R.string.recovery_reason_journal_missing
        RecoveryReason.UNKNOWN_STATE -> R.string.recovery_reason_unknown
        RecoveryReason.MIGRATION_PENDING -> R.string.recovery_reason_migration
        RecoveryReason.INVALID_INPUT -> R.string.recovery_reason_invalid
    }
}
