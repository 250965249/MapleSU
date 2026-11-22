package dev.maplesu.manager.workmode.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.maplesu.manager.workmode.recovery.RecoveryDecisionEngine
import dev.maplesu.manager.workmode.recovery.RecoveryInput
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.coroutines.cancellation.CancellationException

fun interface RecoveryFactsSource {
    /** null means unreadable facts, not an empty recovery queue. */
    fun load(switchId: String): RecoveryInput?
}

object UnavailableRecoveryFactsSource : RecoveryFactsSource {
    override fun load(switchId: String): RecoveryInput? = null
}

class RecoveryViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(RecoveryUiState())
    val uiState: StateFlow<RecoveryUiState> = _uiState.asStateFlow()
    private var attachedId: String? = null
    private var attachedSource: RecoveryFactsSource = UnavailableRecoveryFactsSource
    private var refreshJob: Job? = null

    fun attach(switchId: String, source: RecoveryFactsSource = UnavailableRecoveryFactsSource) {
        if (attachedId != switchId || attachedSource !== source) {
            _uiState.value = RecoveryUiState(switchId = switchId)
        }
        attachedId = switchId
        attachedSource = source
        refresh()
    }

    fun setSource(source: RecoveryFactsSource) {
        attachedSource = source
        if (attachedId != null) refresh()
    }

    fun refresh() {
        refreshJob?.cancel()
        val id = attachedId ?: return
        val source = attachedSource
        _uiState.update { it.copy(switchId = id, loading = true, error = null) }
        refreshJob = viewModelScope.launch {
            try {
                val facts = withContext(Dispatchers.IO) {
                    source.load(id)?.let { it to RecoveryDecisionEngine.decide(it) }
                }
                if (attachedId != id || attachedSource !== source) return@launch
                if (facts == null) {
                    _uiState.update { it.copy(loading = false, readFailed = true) }
                } else {
                    _uiState.update { it.copy(
                        loading = false, decision = facts.second, baselineState = facts.first.baselineState,
                        readFailed = false, error = null,
                    ) }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                _uiState.update { it.copy(loading = false, readFailed = true, error = failure.message.orEmpty()) }
            }
        }
    }

    fun setExportStatus(status: String) { _uiState.update { it.copy(exportStatus = status) } }
    fun clearError() { _uiState.update { it.copy(error = null) } }
}
