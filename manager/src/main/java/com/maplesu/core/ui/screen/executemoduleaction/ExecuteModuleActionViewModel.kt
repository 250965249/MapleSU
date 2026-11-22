package com.maplesu.core.ui.screen.executemoduleaction

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.maplesu.core.ui.util.runModuleAction
import com.maplesu.core.ksuApp
import dev.maplesu.manager.modules.ModuleOperationService
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible

internal data class ModuleActionMessages(
    val failed: String,
    val interrupted: String,
    val restoredComplete: String,
)

class ExecuteModuleActionViewModel(private val savedState: SavedStateHandle) : ViewModel() {
    private val gate = ModuleActionStartGate(savedState["started"] ?: false, savedState["complete"] ?: false)
    private val _state = MutableStateFlow(ExecuteModuleActionUiState(""))
    val state = _state.asStateFlow()
    private val log = StringBuffer()
    private val display = StringBuilder()
    private val displayUpdates = Channel<Unit>(Channel.CONFLATED)
    private var outputClosed = false

    init {
        viewModelScope.launch(Dispatchers.Default) {
            for (ignored in displayUpdates) {
                delay(16L)
                publishDisplay()
            }
        }
    }

    @Synchronized
    fun logSnapshot(): String = log.toString()

    internal fun start(moduleId: String, messages: ModuleActionMessages) {
        when (gate.claim()) {
            ModuleActionStart.ALREADY_STARTED -> return
            ModuleActionStart.RESTORED_RUNNING -> {
                append(messages.interrupted)
                finishOutput()
                _state.update { it.copy(isComplete = true) }
                return
            }
            ModuleActionStart.RESTORED_COMPLETE -> {
                append(messages.restoredComplete)
                finishOutput()
                _state.update { it.copy(isComplete = true) }
                return
            }
            ModuleActionStart.START -> Unit
        }
        savedState["started"] = true
        viewModelScope.launch {
            try {
                // The execution backend validates the live target when it runs.
                // A full display inventory adds I/O and can describe a pending revision.
                val success = ModuleOperationService.run(ksuApp) {
                    runInterruptible { runModuleAction(moduleId, ::append, ::append) }
                }
                if (!success) append(messages.failed)
                _state.update { it.copy(succeeded = success) }
            } catch (error: CancellationException) {
                throw error
            } catch (_: Exception) {
                append(messages.failed)
            } finally {
                finishOutput()
                savedState["complete"] = true
                _state.update { it.copy(isComplete = true) }
            }
        }
    }

    @Synchronized
    private fun append(line: String) {
        log.append(line).append('\n')
        if (outputClosed) return
        if (line.startsWith("\u001b[H\u001b[J")) {
            display.setLength(0)
            display.append(line.substring(6))
        } else display.append(line)
        display.append('\n')
        displayUpdates.trySend(Unit)
    }

    @Synchronized
    private fun publishDisplay() {
        if (!outputClosed) _state.update { it.copy(text = display.toString()) }
    }

    @Synchronized
    private fun finishOutput() {
        if (outputClosed) return
        outputClosed = true
        displayUpdates.close()
        _state.update { it.copy(text = display.toString()) }
    }
}
