package dev.maplesu.manager.workmode.ui

import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.maplesu.core.R
import dev.maplesu.manager.workmode.migration.MigrationStage

import androidx.compose.material3.*

@Composable
fun MigrationScreenMaterial(state: MigrationUiState, actions: MigrationActions) {
    var targetSheet by rememberSaveable { mutableStateOf(false) }
    WorkModePageMaterial(
        title = stringResource(R.string.migration_page_title),
        onBack = actions.onBack, backEnabled = !state.blocksBack,
    ) {
        WorkModeSectionMaterial {
            Text(style = MaterialTheme.typography.titleMedium, text = stringResource(MigrationStrings.stage(state.stage)))
            if (state.stage == MigrationStage.DETECTING || state.stage == MigrationStage.IDLE) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            } else if (state.unavailable) {
                Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(
                    if (state.snapshot.unavailableCode == "MIGRATION_NO_ROOT") R.string.migration_no_root
                    else R.string.migration_unavailable,
                ))
            }
            state.detection?.let { detection ->
                Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(MigrationStrings.family(detection.familyKey)) +
                    detection.versionLabel?.takeIf { it.isNotBlank() }?.let { " · $it" }.orEmpty())
                if (detection.bestEffort) Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(R.string.migration_best_effort))
                detection.blockerKeys.distinct().forEach {
                    Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(MigrationStrings.blocker(it)))
                }
            }
            if (state.blocksBack) {
                Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(R.string.work_mode_headline_running_hint))
                val progress = state.snapshot.progress
                if (progress.stepIndex > 0 && progress.stepCount > 0) {
                    Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(R.string.migration_step_of, progress.stepIndex, progress.stepCount))
                }
                if (state.stage == MigrationStage.PENDING_REBOOT) {
                    Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(R.string.migration_pending_reboot))
                } else { LinearProgressIndicator(modifier = Modifier.fillMaxWidth()) }
            }
        }
        if (state.stage == MigrationStage.DETECTED || state.stage == MigrationStage.CONFIRMING) {
            WorkModeTargetRow(
                value = state.selectedTarget?.let { stringResource(WorkModeStrings.modeNameRes(it)) }
                    ?: stringResource(R.string.work_mode_target_none),
                enabled = state.stage == MigrationStage.DETECTED,
                onClick = { targetSheet = true },
            )
            WorkModeSectionMaterial {
                Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(R.string.migration_backup_not_started))
                Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(R.string.migration_keep_manager))
                Button(onClick = actions.onRequestConfirm, enabled = state.canStart, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.migration_start)) }
            }
        }
        state.snapshot.backup?.let { backup ->
            WorkModeSectionMaterial {
                Text(style = MaterialTheme.typography.titleMedium, text = stringResource(R.string.migration_section_backup))
                Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(if (backup.complete) R.string.migration_backup_verified
                    else R.string.migration_backup_incomplete))
            }
        }
        state.failure?.let { failure ->
            WorkModeSectionMaterial {
                Text(style = MaterialTheme.typography.titleMedium, text = stringResource(R.string.migration_result_failed))
                Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(when {
                    failure.recoveryRequired -> R.string.migration_failed_recovery
                    failure.rolledBack -> R.string.migration_failed_rolled_back
                    else -> R.string.migration_failed_generic
                }))
                if (failure.recoveryRequired && !actions.recoveryAvailable) {
                    Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(R.string.migration_manual_recovery_hint))
                }
            }
        }
        state.result?.let { result ->
            WorkModeSectionMaterial {
                Text(style = MaterialTheme.typography.titleMedium, text = stringResource(MigrationStrings.result(result.kind)))
                Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(R.string.migration_modules_summary,
                    result.importedModules, result.unsupportedModules, result.failedModules))
                Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(R.string.migration_auth_counts,
                    result.auth.intents, result.auth.applied, result.auth.pending, result.auth.stale))
                if (result.residual) Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(R.string.migration_residual_warning))
                OutlinedButton(onClick = actions.onDismissResult, enabled = true, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.migration_dismiss)) }
            }
        }
        if (state.canAbort) { OutlinedButton(onClick = actions.onAbort, enabled = true, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.migration_abort)) } }
        if (!state.blocksBack) {
            OutlinedButton(onClick = actions.onRefresh, enabled = state.stage != MigrationStage.DETECTING, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.migration_refresh)) }
            if (actions.diagnosticsAvailable) { OutlinedButton(onClick = actions.onOpenDiagnosis, enabled = true, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.migration_open_diagnosis)) } }
            if (actions.recoveryAvailable && (state.failure?.recoveryRequired == true ||
                state.stage == MigrationStage.RECOVERY_REQUIRED)) { OutlinedButton(onClick = actions.onOpenRecovery, enabled = true, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.migration_open_recovery)) } }
        }
        WorkModeTechnicalInfoMaterial(state.technicalLines())
    }
    WorkModeTargetSheet(
        show = targetSheet, selected = state.selectedTarget, current = null,
        onSelect = actions.onSelectTarget, onDismiss = { targetSheet = false },
        note = stringResource(R.string.work_mode_target_migration_note),
        options = state.snapshot.targetOptions.map {
            WorkModeSheetOption(it.mode, enabled = it.enabled, recommended = it.recommended)
        },
    )

    if (state.stage == MigrationStage.CONFIRMING) {
        AlertDialog(
            onDismissRequest = actions.onDismissConfirm,
            title = { Text(stringResource(R.string.migration_confirm_title)) },
            text = { Text(stringResource(R.string.migration_confirm_body)) },
            confirmButton = {
                TextButton(onClick = actions.onStart) { Text(stringResource(R.string.migration_confirm_start)) }
            },
            dismissButton = {
                TextButton(onClick = actions.onDismissConfirm) { Text(stringResource(R.string.migration_cancel)) }
            },
        )
    }
}
