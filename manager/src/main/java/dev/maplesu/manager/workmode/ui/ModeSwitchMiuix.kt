package dev.maplesu.manager.workmode.ui

import androidx.compose.foundation.layout.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.maplesu.core.R

import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import top.yukonga.miuix.kmp.basic.InfiniteProgressIndicator
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme

@Composable
fun ModeSwitchScreenMiuix(state: ModeSwitchUiState, actions: ModeSwitchActions) {
    val copy = modeSwitchCopy(state)
    WorkModePageMiuix(
        title = stringResource(R.string.work_mode_switch_page_title),
        onBack = actions.onBack, backEnabled = !state.blocksBack,
    ) {
        WorkModeSectionMiuix {
            Text(fontSize = 18.sp, color = colorScheme.onSurface, text = copy.title)
            Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = copy.hint)
            if (state.phase == ModeSwitchPhase.RUNNING || state.phase == ModeSwitchPhase.ATTACHING ||
                state.actionRunning) { InfiniteProgressIndicator(size = 24.dp) }
            if (state.phase == ModeSwitchPhase.FAILED && state.code.isNotBlank()) {
                Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(WorkModeStrings.failureRes(state.code)))
            }
        }
        if (state.phase != ModeSwitchPhase.MISSING) {
            WorkModeSectionMiuix {
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
                            color = if (row.status == StepStatus.PENDING) colorScheme.onSurfaceVariantSummary else colorScheme.primary,
                        )
                        Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(WorkModeStrings.stepRes(row.step)))
                    }
                }
            }
        }
        WorkModeSectionMiuix {
            if (state.rebootRequired && !state.blocksBack) { TextButton(text = stringResource(R.string.reboot), onClick = actions.onReboot, enabled = true, modifier = Modifier.fillMaxWidth()) }
            if (state.canRetry) { TextButton(text = stringResource(R.string.work_mode_retry), onClick = actions.onRetry, enabled = true, modifier = Modifier.fillMaxWidth()) }
            if (state.canAbort) { TextButton(text = stringResource(R.string.work_mode_abort), onClick = actions.onAbort, enabled = true, modifier = Modifier.fillMaxWidth()) }
            if (state.canRollback && !state.blocksBack) { TextButton(text = stringResource(R.string.work_mode_rollback), onClick = actions.onRollback, enabled = true, modifier = Modifier.fillMaxWidth()) }
            if (state.requiresExternalRecovery) { TextButton(text = stringResource(R.string.work_mode_open_recovery), onClick = actions.onOpenRecovery, enabled = true, modifier = Modifier.fillMaxWidth()) }
            if (!state.blocksBack) { TextButton(text = stringResource(R.string.work_mode_open_diagnosis), onClick = actions.onSaveLog, enabled = true, modifier = Modifier.fillMaxWidth()) }
            TextButton(text = stringResource(R.string.work_mode_back), onClick = actions.onBack, enabled = !state.blocksBack, modifier = Modifier.fillMaxWidth())
        }
        if (!state.blocksBack) WorkModeTechnicalInfoMiuix(buildList {
            add("switch.id=${state.switchId}; state=${state.stateWire}")
            add("stage=${state.stage}; step=${state.step}")
            if (state.code.isNotBlank()) add("error=${state.code}")
            if (state.detail.isNotBlank()) add(state.detail)
        })
    }
}
