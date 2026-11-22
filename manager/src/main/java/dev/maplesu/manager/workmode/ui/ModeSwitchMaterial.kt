package dev.maplesu.manager.workmode.ui

import androidx.compose.foundation.layout.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.maplesu.core.R

import androidx.compose.ui.unit.dp
import androidx.compose.material3.*

@Composable
fun ModeSwitchScreenMaterial(state: ModeSwitchUiState, actions: ModeSwitchActions) {
    val copy = modeSwitchCopy(state)
    WorkModePageMaterial(
        title = stringResource(R.string.work_mode_switch_page_title),
        onBack = actions.onBack, backEnabled = !state.blocksBack,
    ) {
        WorkModeSectionMaterial {
            Text(style = MaterialTheme.typography.titleMedium, text = copy.title)
            Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = copy.hint)
            if (state.phase == ModeSwitchPhase.RUNNING || state.phase == ModeSwitchPhase.ATTACHING ||
                state.actionRunning) { LinearProgressIndicator(modifier = Modifier.fillMaxWidth()) }
            if (state.phase == ModeSwitchPhase.FAILED && state.code.isNotBlank()) {
                Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(WorkModeStrings.failureRes(state.code)))
            }
        }
        if (state.phase != ModeSwitchPhase.MISSING) {
            WorkModeSectionMaterial {
                val rows = modeSwitchStepRows(
                    modeSwitchStepOf(state.stateWire, state.stage, state.step),
                    failed = state.phase == ModeSwitchPhase.FAILED ||
                        state.phase == ModeSwitchPhase.NEEDS_RECOVERY,
                    finished = state.phase == ModeSwitchPhase.SUCCEEDED && !state.rebootRequired,
                )
                rows.forEach { row ->
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text(
                            text = when (row.status) { StepStatus.DONE -> "✓"; StepStatus.ACTIVE -> "●";
                                StepStatus.FAILED -> "!"; StepStatus.PENDING -> "○" },
                            color = when (row.status) { StepStatus.PENDING -> MaterialTheme.colorScheme.onSurfaceVariant;
                                StepStatus.FAILED -> MaterialTheme.colorScheme.error; else -> MaterialTheme.colorScheme.primary },
                        )
                        Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(WorkModeStrings.stepRes(row.step)))
                    }
                }
            }
        }
        WorkModeSectionMaterial {
            if (state.rebootRequired && !state.blocksBack) { OutlinedButton(onClick = actions.onReboot, enabled = true, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.reboot)) } }
            if (state.canRetry) { OutlinedButton(onClick = actions.onRetry, enabled = true, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.work_mode_retry)) } }
            if (state.canAbort) { OutlinedButton(onClick = actions.onAbort, enabled = true, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.work_mode_abort)) } }
            if (state.canRollback && !state.blocksBack) { OutlinedButton(onClick = actions.onRollback, enabled = true, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.work_mode_rollback)) } }
            if (state.requiresExternalRecovery) { OutlinedButton(onClick = actions.onOpenRecovery, enabled = true, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.work_mode_open_recovery)) } }
            if (!state.blocksBack) { OutlinedButton(onClick = actions.onSaveLog, enabled = true, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.work_mode_open_diagnosis)) } }
            OutlinedButton(onClick = actions.onBack, enabled = !state.blocksBack, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.work_mode_back)) }
        }
        if (!state.blocksBack) WorkModeTechnicalInfoMaterial(buildList {
            add("switch.id=${state.switchId}; state=${state.stateWire}")
            add("stage=${state.stage}; step=${state.step}")
            if (state.code.isNotBlank()) add("error=${state.code}")
            if (state.detail.isNotBlank()) add(state.detail)
        })
    }
}
