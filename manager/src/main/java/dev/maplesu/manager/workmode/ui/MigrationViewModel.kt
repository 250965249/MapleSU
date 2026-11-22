package dev.maplesu.manager.workmode.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.migration.MigrationDetectionResult
import dev.maplesu.manager.workmode.migration.MigrationFacade
import dev.maplesu.manager.workmode.migration.MigrationFailureUi
import dev.maplesu.manager.workmode.migration.MigrationObservation
import dev.maplesu.manager.workmode.migration.MigrationRuntime
import dev.maplesu.manager.workmode.migration.MigrationStartResult
import dev.maplesu.manager.workmode.migration.MigrationStage
import dev.maplesu.manager.workmode.migration.MigrationUiEvent
import dev.maplesu.manager.workmode.migration.MigrationUiReducer
import dev.maplesu.manager.workmode.migration.MigrationUiSnapshot
import dev.maplesu.manager.workmode.migration.UnavailableMigrationFacade
import kotlinx.coroutines.Job
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext
import kotlin.coroutines.cancellation.CancellationException

/**
 * 迁移页 ViewModel：把 [MigrationFacade] 事件喂给纯 reducer，页面只读 [MigrationUiState]。
 *
 * facade 解析顺序：显式注入 → [MigrationRuntime.current]（App 启动时由 `MigrationRuntime.initialize`
 * 组装生产实现）→ [UnavailableMigrationFacade]（诚实降级，不出现开始按钮）。
 * UI 不直连分区写入。
 */
class MigrationViewModel : ViewModel() {

    private val _uiState = MutableStateFlow(MigrationUiState())
    val uiState: StateFlow<MigrationUiState> = _uiState.asStateFlow()

    private var facade: MigrationFacade = defaultFacade()
    private var observationJob: Job? = null
    private var detectionJob: Job? = null
    private var startJob: Job? = null
    private var attachedMigrationId: String = ""
    private var initialTarget: WorkMode? = null
    private var confirmAfterDetection: Boolean = false

    fun attach(
        migrationId: String = "",
        facade: MigrationFacade = defaultFacade(),
        initialTarget: WorkMode? = null,
        confirmOnOpen: Boolean = false,
    ) {
        if (_uiState.value.blocksBack) return
        this.facade = facade
        this.initialTarget = initialTarget
        confirmAfterDetection = confirmOnOpen
        attachedMigrationId = migrationId
        if (migrationId.isBlank()) {
            detect()
        } else {
            // The pure reducer deliberately ignores progress after IDLE. An attached id is an
            // existing operation, not a freshly detected (pre-created) migration id.
            _uiState.value = MigrationUiState(MigrationUiSnapshot(
                stage = MigrationStage.BACKING_UP, migrationId = migrationId,
            ))
            observe(migrationId)
        }
    }

    fun refresh() {
        if (attachedMigrationId.isBlank()) detect() else observe(attachedMigrationId)
    }

    fun detect() {
        if (_uiState.value.blocksBack) return
        detectionJob?.cancel()
        observationJob?.cancel()
        attachedMigrationId = ""
        dispatch(MigrationUiEvent.DetectStarted)
        val source = facade
        detectionJob = viewModelScope.launch {
            val result = try {
                withContext(Dispatchers.IO) { source.detect() }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                MigrationDetectionResult.Unavailable("MIGRATION_DETECT_FAILED")
            }
            when (result) {
                is MigrationDetectionResult.Ready -> {
                    dispatch(MigrationUiEvent.Detected(result.info, result.eligibility))
                    // detect() may allocate an id, but it has not started a transaction.
                    // Only Accepted / an explicit route id enables observation.
                    _uiState.value = MigrationUiState(migrationEntrySelection(
                        _uiState.value.snapshot, initialTarget, confirmAfterDetection,
                    ))
                    confirmAfterDetection = false
                }
                is MigrationDetectionResult.Unavailable ->
                    dispatch(MigrationUiEvent.DetectionUnavailable(result.code))
            }
        }
    }

    fun selectTarget(mode: WorkMode) = dispatch(MigrationUiEvent.TargetSelected(mode))

    fun requestConfirm() = dispatch(MigrationUiEvent.ConfirmRequested)

    fun dismissConfirm() = dispatch(MigrationUiEvent.ConfirmDismissed)

    fun start() {
        if (startJob?.isActive == true) return
        // Confirmation is a UI stage; return to DETECTED before using the existing gate.
        if (_uiState.value.stage == MigrationStage.CONFIRMING) dismissConfirm()
        val snapshot = _uiState.value.snapshot
        if (!snapshot.canStart) return
        val target = snapshot.selectedTarget ?: return
        dispatch(MigrationUiEvent.StartRequested)
        startJob = viewModelScope.launch {
            val result = try {
                withContext(Dispatchers.IO) { facade.start(target) }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                MigrationStartResult.Failed("MIGRATION_START_FAILED")
            }
            when (result) {
                is MigrationStartResult.Accepted -> {
                    attachedMigrationId = result.migrationId
                    dispatch(MigrationUiEvent.Started(result.migrationId))
                    observe(result.migrationId)
                }
                is MigrationStartResult.Refused -> dispatch(
                    MigrationUiEvent.Failed(
                        MigrationFailureUi(
                            code = result.code,
                            stage = MigrationStage.IDLE,
                            detailKey = "migration_start_refused",
                        ),
                    ),
                )
                is MigrationStartResult.Failed -> dispatch(
                    MigrationUiEvent.Failed(
                        MigrationFailureUi(code = result.code, stage = result.stage),
                    ),
                )
            }
        }
    }

    fun abort() {
        if (_uiState.value.stage.destructiveStarted) return
        val id = attachedMigrationId
        if (id.isBlank()) return
        viewModelScope.launch {
            val accepted = try {
                withContext(Dispatchers.IO) { facade.abort(id) }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) { false }
            if (accepted) {
                dispatch(MigrationUiEvent.Aborted)
            }
        }
    }

    fun dismissResult() = dispatch(MigrationUiEvent.Dismissed)

    fun reset() {
        observationJob?.cancel()
        detectionJob?.cancel()
        observationJob = null
        attachedMigrationId = ""
        dispatch(MigrationUiEvent.Reset)
    }

    private fun observe(migrationId: String) {
        observationJob?.cancel()
        observationJob = viewModelScope.launch {
            try {
                facade.observe(migrationId).flowOn(Dispatchers.IO).collect { observation ->
                    if (attachedMigrationId == migrationId) dispatch(observation.toEvent())
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                // Observation failure is not evidence of completion: preserve the running lock.
            }
        }
    }

    private fun MigrationObservation.toEvent(): MigrationUiEvent = when (this) {
        is MigrationObservation.Progress -> MigrationUiEvent.Progress(stage, stepIndex, stepCount, stepKey, logLine)
        is MigrationObservation.Backup -> MigrationUiEvent.BackupCaptured(summary)
        is MigrationObservation.Completed -> MigrationUiEvent.Completed(result)
        is MigrationObservation.Failed -> MigrationUiEvent.Failed(failure)
    }

    private fun dispatch(event: MigrationUiEvent) {
        _uiState.value = MigrationUiState(
            MigrationUiReducer.reduce(_uiState.value.snapshot, event),
        )
    }

    companion object {
        /** 生产 facade 由 [MigrationRuntime] 在 App 启动时组装；缺失时诚实降级。 */
        fun defaultFacade(): MigrationFacade = MigrationRuntime.current() ?: UnavailableMigrationFacade

        fun reduce(snapshot: MigrationUiSnapshot, event: MigrationUiEvent): MigrationUiSnapshot =
            MigrationUiReducer.reduce(snapshot, event)
    }
}
