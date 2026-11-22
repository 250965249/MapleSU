package dev.maplesu.manager.workmode.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.maplesu.core.R

import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.InfiniteProgressIndicator
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme

@Composable
fun DiagnosisScreenMiuix(state: DiagnosisUiState, actions: DiagnosisActions) {
    WorkModePageMiuix(title = stringResource(R.string.diagnosis_title), onBack = actions.onBack) {
        WorkModeSectionMiuix {
            Text(fontSize = 18.sp, color = colorScheme.onSurface, text = stringResource(if (state.loading) R.string.diagnosis_loading else when (state.summary) {
                DiagnosisSummary.UNAVAILABLE -> R.string.diagnosis_unavailable
                DiagnosisSummary.EMPTY -> R.string.diagnosis_summary_no_switch
                DiagnosisSummary.PENDING -> R.string.diagnosis_summary_pending
                DiagnosisSummary.FINISHED -> R.string.diagnosis_summary_finished
                DiagnosisSummary.UNKNOWN -> R.string.diagnosis_summary_unknown
            }))
            if (state.loading) { InfiniteProgressIndicator(size = 24.dp) }
            Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(R.string.diagnosis_hint))
            Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(R.string.diagnosis_no_secrets))
            if (state.error != null) Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(R.string.diagnosis_operation_failed))
            Button(onClick = actions.onExport, enabled = state.backendAvailable && !state.loading && !state.exporting, modifier = Modifier.fillMaxWidth()) { Text(stringResource(if (state.exporting) R.string.diagnosis_exporting else R.string.diagnosis_export)) }
            TextButton(text = stringResource(R.string.diagnosis_refresh), onClick = actions.onRefresh, enabled = !state.loading, modifier = Modifier.fillMaxWidth())
        }
        state.exportedPath?.let { path ->
            WorkModeSectionMiuix {
                Text(fontSize = 18.sp, color = colorScheme.onSurface, text = stringResource(R.string.diagnosis_export_ready))
                Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = stringResource(R.string.diagnosis_export_partial_hint))
                SelectionContainer { Text(fontSize = 14.sp, color = colorScheme.onSurfaceVariantSummary, text = path) }
                TextButton(text = stringResource(R.string.diagnosis_share), onClick = actions.onShare, modifier = Modifier.fillMaxWidth())
            }
        }
        WorkModeTechnicalInfoMiuix(state.lines + listOfNotNull(
            state.exportedSha256?.let { "sha256=$it" },
            state.error?.takeIf(String::isNotBlank),
        ))
    }
}
