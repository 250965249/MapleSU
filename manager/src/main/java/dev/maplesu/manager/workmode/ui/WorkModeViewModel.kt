package dev.maplesu.manager.workmode.ui

import androidx.lifecycle.ViewModel
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.detect.ModeState
import java.util.UUID
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/** 选择框只读取已有本地状态并打开进度页；设备操作全部由进度页持有。 */
class WorkModeViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(WorkModeUiState())
    val uiState: StateFlow<WorkModeUiState> = _uiState.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        val current = ModeRuntime.active
        val pendingId = WorkModeSwitchSession.switchId
        val state = WorkModeUiState().reduce(
            WorkModeEvent.Detected(
                state = ModeRuntime.latestDetection?.state ?: ModeState.INDETERMINATE,
                capabilities = ModeRuntime.capabilities,
                current = current,
                masked = runCatching { currentWorkModeHiddenMask() }.getOrDefault(true),
                switchSupported = true,
            ),
        ).reduce(WorkModeEvent.PendingSwitch(
            pendingId.takeIf { WorkModeSwitchSession.pending },
        ))
        _uiState.value = if (WorkModeSwitchSession.executing && pendingId != null) {
            state.reduce(WorkModeEvent.Started(pendingId))
        } else state
    }

    fun onSheetOpened() = refresh()

    /** 同步接受用户选中的目标，不等待服务连接、预检或刷写。 */
    fun onConfirmSwitch(target: WorkMode) {
        _uiState.update { state ->
            val accepted = state.reduce(WorkModeEvent.StartSwitch(target))
            if (accepted !== state) accepted.reduce(WorkModeEvent.Started(UUID.randomUUID().toString())) else state
        }
    }

    fun onProgressOpened(switchId: String) {
        _uiState.update { it.reduce(WorkModeEvent.ProgressOpened(switchId)) }
    }
}
