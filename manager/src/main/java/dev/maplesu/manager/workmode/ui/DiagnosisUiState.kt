package dev.maplesu.manager.workmode.ui

import androidx.compose.runtime.Immutable

enum class DiagnosisSummary { UNAVAILABLE, EMPTY, PENDING, FINISHED, UNKNOWN }

@Immutable
data class DiagnosisUiState(
    val switchId: String = "",
    val loading: Boolean = true,
    val exporting: Boolean = false,
    val summary: DiagnosisSummary = DiagnosisSummary.UNAVAILABLE,
    val lines: List<String> = emptyList(),
    val exportedPath: String? = null,
    val exportedSha256: String? = null,
    val redactions: Int = 0,
    val error: String? = null,
    val backendAvailable: Boolean = false,
)
