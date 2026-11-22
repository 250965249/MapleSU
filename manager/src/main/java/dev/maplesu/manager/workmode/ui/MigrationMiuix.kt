package dev.maplesu.manager.workmode.ui

import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.maplesu.core.R
import dev.maplesu.manager.workmode.migration.MigrationStage

import androidx.compose.ui.unit.sp
import com.maplesu.core.ui.theme.miuixDialogColor
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.InfiniteProgressIndicator
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme

@Composable
fun MigrationScreenMiuix(state: MigrationUiState, actions: MigrationActions) {
    var targetSheet by rememberSaveable { mutableStateOf(false) }
    WorkModePageMiuix(
        title = stringResource(R.string.migration_page_title),
        onBack = actions.onBack, backEnabled = !state.blocksBack,
    ) {
        WorkModeSectionMiuix {
            Text(fontSize = 18.sp, color = colorScheme.onSurface, text = stringResource(MigrationStrings.stage(state.stage)))
            if (state.stage == MigrationStage.DETECTING || state.stage == MigrationStage.IDLE) {
                InfiniteProgressIndicator(size = 24.dp)
            } else if (state.unavailable) {
                Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(
                    if (state.snapshot.unavailableCode == "MIGRATION_NO_ROOT") R.string.migration_no_root
                    else R.string.migration_unavailable,
                ))
            }
            state.detection?.let { detection ->
                Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(MigrationStrings.family(detection.familyKey)) +
                    detection.versionLabel?.takeIf { it.isNotBlank() }?.let { " · $it" }.orEmpty())
                if (detection.bestEffort) Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(R.string.migration_best_effort))
                detection.blockerKeys.distinct().forEach {
                    Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(MigrationStrings.blocker(it)))
                }
            }
            if (state.blocksBack) {
                Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(R.string.work_mode_headline_running_hint))
                val progress = state.snapshot.progress
                if (progress.stepIndex > 0 && progress.stepCount > 0) {
                    Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(R.string.migration_step_of, progress.stepIndex, progress.stepCount))
                }
                if (state.stage == MigrationStage.PENDING_REBOOT) {
                    Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(R.string.migration_pending_reboot))
                } else { InfiniteProgressIndicator(size = 24.dp) }
            }
        }
        if (state.stage == MigrationStage.DETECTED || state.stage == MigrationStage.CONFIRMING) {
            WorkModeTargetRow(
                value = state.selectedTarget?.let { stringResource(WorkModeStrings.modeNameRes(it)) }
                    ?: stringResource(R.string.work_mode_target_none),
                enabled = state.stage == MigrationStage.DETECTED,
                onClick = { targetSheet = true },
            )
            WorkModeSectionMiuix {
                Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(R.string.migration_backup_not_started))
                Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(R.string.migration_keep_manager))
                Button(onClick = actions.onRequestConfirm, enabled = state.canStart, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.migration_start)) }
            }
        }
        state.snapshot.backup?.let { backup ->
            WorkModeSectionMiuix {
                Text(fontSize = 18.sp, color = colorScheme.onSurface, text = stringResource(R.string.migration_section_backup))
                Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(if (backup.complete) R.string.migration_backup_verified
                    else R.string.migration_backup_incomplete))
            }
        }
        state.failure?.let { failure ->
            WorkModeSectionMiuix {
                Text(fontSize = 18.sp, color = colorScheme.onSurface, text = stringResource(R.string.migration_result_failed))
                Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(when {
                    failure.recoveryRequired -> R.string.migration_failed_recovery
                    failure.rolledBack -> R.string.migration_failed_rolled_back
                    else -> R.string.migration_failed_generic
                }))
                if (failure.recoveryRequired && !actions.recoveryAvailable) {
                    Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(R.string.migration_manual_recovery_hint))
                }
            }
        }
        state.result?.let { result ->
            WorkModeSectionMiuix {
                Text(fontSize = 18.sp, color = colorScheme.onSurface, text = stringResource(MigrationStrings.result(result.kind)))
                Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(R.string.migration_modules_summary,
                    result.importedModules, result.unsupportedModules, result.failedModules))
                Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(R.string.migration_auth_counts,
                    result.auth.intents, result.auth.applied, result.auth.pending, result.auth.stale))
                if (result.residual) Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(R.string.migration_residual_warning))
                TextButton(text = stringResource(R.string.migration_dismiss), onClick = actions.onDismissResult, enabled = true, modifier = Modifier.fillMaxWidth())
            }
        }
        if (state.canAbort) { TextButton(text = stringResource(R.string.migration_abort), onClick = actions.onAbort, enabled = true, modifier = Modifier.fillMaxWidth()) }
        if (!state.blocksBack) {
            TextButton(text = stringResource(R.string.migration_refresh), onClick = actions.onRefresh, enabled = state.stage != MigrationStage.DETECTING, modifier = Modifier.fillMaxWidth())
            if (actions.diagnosticsAvailable) { TextButton(text = stringResource(R.string.migration_open_diagnosis), onClick = actions.onOpenDiagnosis, enabled = true, modifier = Modifier.fillMaxWidth()) }
            if (actions.recoveryAvailable && (state.failure?.recoveryRequired == true ||
                state.stage == MigrationStage.RECOVERY_REQUIRED)) { TextButton(text = stringResource(R.string.migration_open_recovery), onClick = actions.onOpenRecovery, enabled = true, modifier = Modifier.fillMaxWidth()) }
        }
        WorkModeTechnicalInfoMiuix(state.technicalLines())
    }
    WorkModeTargetSheet(
        show = targetSheet, selected = state.selectedTarget, current = null,
        onSelect = actions.onSelectTarget, onDismiss = { targetSheet = false },
        note = stringResource(R.string.work_mode_target_migration_note),
        options = state.snapshot.targetOptions.map {
            WorkModeSheetOption(it.mode, enabled = it.enabled, recommended = it.recommended)
        },
    )

    OverlayDialog(
        show = state.stage == MigrationStage.CONFIRMING,
        title = stringResource(R.string.migration_confirm_title),
        backgroundColor = miuixDialogColor(),
        onDismissRequest = actions.onDismissConfirm,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text(stringResource(R.string.migration_confirm_body), color = colorScheme.onSurfaceVariantSummary)
            Button(onClick = actions.onStart, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.migration_confirm_start))
            }
            TextButton(text = stringResource(R.string.migration_cancel),
                onClick = actions.onDismissConfirm, modifier = Modifier.fillMaxWidth())
        }
    }
}
