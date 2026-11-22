package dev.maplesu.manager.workmode.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.maplesu.core.R

import androidx.compose.material3.*

@Composable
fun DiagnosisScreenMaterial(state: DiagnosisUiState, actions: DiagnosisActions) {
    WorkModePageMaterial(title = stringResource(R.string.diagnosis_title), onBack = actions.onBack) {
        WorkModeSectionMaterial {
            Text(style = MaterialTheme.typography.titleMedium, text = stringResource(if (state.loading) R.string.diagnosis_loading else when (state.summary) {
                DiagnosisSummary.UNAVAILABLE -> R.string.diagnosis_unavailable
                DiagnosisSummary.EMPTY -> R.string.diagnosis_summary_no_switch
                DiagnosisSummary.PENDING -> R.string.diagnosis_summary_pending
                DiagnosisSummary.FINISHED -> R.string.diagnosis_summary_finished
                DiagnosisSummary.UNKNOWN -> R.string.diagnosis_summary_unknown
            }))
            if (state.loading) { LinearProgressIndicator(modifier = Modifier.fillMaxWidth()) }
            Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(R.string.diagnosis_hint))
            Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(R.string.diagnosis_no_secrets))
            if (state.error != null) Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(R.string.diagnosis_operation_failed))
            Button(onClick = actions.onExport, enabled = state.backendAvailable && !state.loading && !state.exporting, modifier = Modifier.fillMaxWidth()) { Text(stringResource(if (state.exporting) R.string.diagnosis_exporting else R.string.diagnosis_export)) }
            OutlinedButton(onClick = actions.onRefresh, enabled = !state.loading, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.diagnosis_refresh)) }
        }
        state.exportedPath?.let { path ->
            WorkModeSectionMaterial {
                Text(style = MaterialTheme.typography.titleMedium, text = stringResource(R.string.diagnosis_export_ready))
                Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = stringResource(R.string.diagnosis_export_partial_hint))
                SelectionContainer { Text(style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, text = path) }
                OutlinedButton(onClick = actions.onShare, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.diagnosis_share)) }
            }
        }
        WorkModeTechnicalInfoMaterial(state.lines + listOfNotNull(
            state.exportedSha256?.let { "sha256=$it" },
            state.error?.takeIf(String::isNotBlank),
        ))
    }
}
