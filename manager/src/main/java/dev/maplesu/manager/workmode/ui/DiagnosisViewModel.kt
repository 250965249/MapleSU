package dev.maplesu.manager.workmode.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.maplesu.core.ksuApp
import dev.maplesu.manager.workmode.control.ControlPaths
import dev.maplesu.manager.workmode.recovery.DiagnosticsExporter
import dev.maplesu.manager.workmode.recovery.DiagnosticsSnapshot
import dev.maplesu.manager.workmode.recovery.RootDiagnosticsReader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import kotlin.coroutines.cancellation.CancellationException

class DiagnosisViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(DiagnosisUiState())
    val uiState: StateFlow<DiagnosisUiState> = _uiState.asStateFlow()
    private var attachedId: String = ""
    private var root: File = ControlPaths.ROOT_FILE
    private var refreshJob: Job? = null
    private var exportJob: Job? = null
    private var snapshot: DiagnosticsSnapshot? = null

    fun attach(switchId: String, root: File = ControlPaths.ROOT_FILE) {
        if (attachedId != switchId || this.root != root) {
            exportJob?.cancel()
            _uiState.value = DiagnosisUiState(switchId = switchId)
            snapshot = null
        }
        attachedId = switchId
        this.root = root
        refresh()
    }

    fun refresh() {
        refreshJob?.cancel()
        val id = attachedId
        val sourceRoot = root
        snapshot = null
        _uiState.update { it.copy(loading = true, error = null) }
        refreshJob = viewModelScope.launch {
            try {
                val observed = withContext(Dispatchers.IO) {
                    RootDiagnosticsReader(sourceRoot, ksuApp.cacheDir).read(id)
                }
                if (attachedId != id || root != sourceRoot) return@launch
                snapshot = observed
                _uiState.update { it.copy(
                    loading = false, switchId = id, backendAvailable = true,
                    summary = diagnosisSummary(observed, id, readable = true),
                    lines = summarize(observed), redactions = observed.redactions, error = null,
                ) }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                if (attachedId != id || root != sourceRoot) return@launch
                _uiState.update { it.copy(
                    loading = false, backendAvailable = false, summary = DiagnosisSummary.UNAVAILABLE,
                    lines = emptyList(), error = failure.message.orEmpty(),
                ) }
            }
        }
    }

    fun export(exporter: DiagnosticsExporter) {
        if (exportJob?.isActive == true) return
        val observed = snapshot ?: run {
            _uiState.update { it.copy(error = it.error ?: "DIAGNOSTICS_NOT_READY") }
            return
        }
        val id = attachedId
        _uiState.update { it.copy(exporting = true, error = null) }
        exportJob = viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) { exporter.export(observed) }
                if (attachedId != id) return@launch
                _uiState.update { it.copy(
                    exporting = false, exportedPath = result.file.absolutePath,
                    exportedSha256 = result.sha256, redactions = result.redactions, error = null,
                ) }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                _uiState.update { it.copy(exporting = false, error = failure.message.orEmpty()) }
            }
        }
    }

    fun clearExport() { _uiState.update { it.copy(exportedPath = null, exportedSha256 = null) } }

    private fun summarize(snapshot: DiagnosticsSnapshot): List<String> = buildList {
        add("generator=${snapshot.generator}; schema=${snapshot.schema}")
        snapshot.switchHead?.let {
            add("switch.id=${it.switchId}; state=${it.state}; pending=${it.pending}")
            add("switch.error=${it.errorCode}/${it.errorStage}; attempts=${it.attempts}")
        }
        add("journal.present=${snapshot.journal.present}; corrupt=${snapshot.journal.corrupt}; lines=${snapshot.journal.lines.size}")
        add("baseline.entries=${snapshot.baseline.size}; evidence.lines=${snapshot.evidence.size}")
        add("redactions=${snapshot.redactions}")
        snapshot.recovery?.let { add("recovery.action=${it.action}; reasons=${it.reasons.joinToString("|")}") }
        snapshot.notes.forEach { add("note=$it") }
    }
}

/** Only a readable control directory and a matching record can produce a conclusive summary. */
internal fun diagnosisSummary(snapshot: DiagnosticsSnapshot, requestedId: String, readable: Boolean): DiagnosisSummary {
    if (!readable) return DiagnosisSummary.UNAVAILABLE
    if (snapshot.journal.corrupt) return DiagnosisSummary.UNKNOWN
    val head = snapshot.switchHead
    if (head == null) return if (requestedId.isBlank() && !snapshot.journal.present)
        DiagnosisSummary.EMPTY else DiagnosisSummary.UNKNOWN
    if (requestedId.isNotBlank() && head.switchId != requestedId) return DiagnosisSummary.UNKNOWN
    return when (head.state) {
        "VERIFIED", "ROLLED_BACK", "FAILED_PRE_WRITE", "CANCELLED" -> DiagnosisSummary.FINISHED
        "BEGIN", "SNAPSHOT", "PRODUCE", "COMMIT", "REBOOT_REQUIRED", "VERIFYING", "ROLLING_BACK",
        "RECOVERY_REQUIRED" -> DiagnosisSummary.PENDING
        else -> DiagnosisSummary.UNKNOWN
    }
}
