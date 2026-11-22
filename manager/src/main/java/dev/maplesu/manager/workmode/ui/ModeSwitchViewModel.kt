package dev.maplesu.manager.workmode.ui

import android.net.Uri
import android.widget.Toast
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.maplesu.core.R
import com.maplesu.core.ksuApp
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.service.ClientResult
import dev.maplesu.manager.workmode.service.ClientStatus
import dev.maplesu.manager.workmode.service.ModeSwitchFacade
import dev.maplesu.manager.workmode.service.ModeSwitchImages
import dev.maplesu.manager.workmode.service.ModeSwitchRootProtocol
import dev.maplesu.manager.workmode.service.SwitchOutcome
import java.io.File
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.coroutines.cancellation.CancellationException

/** 新请求在本页执行；已有任务只观察服务记录。完整门面返回才展示最终结果。 */
class ModeSwitchViewModel(
    private val facadeProvider: () -> ModeSwitchFacade? = SwitchFacadeProvider::current,
) : ViewModel() {
    private val _uiState = MutableStateFlow(ModeSwitchUiState())
    val uiState: StateFlow<ModeSwitchUiState> = _uiState.asStateFlow()
    private val _imageRequest = MutableStateFlow<SwitchOutcome.ImagesRequired?>(null)
    val imageRequest = _imageRequest.asStateFlow()
    private val _imageError = MutableStateFlow<String?>(null)
    val imageError = _imageError.asStateFlow()

    private var attachedId: String? = null
    private var initialTarget: WorkMode? = null
    private var retryStart = false
    private var serviceRecordStarted = false
    private var operationUncertain = false
    private var observeJob: Job? = null
    private var actionJob: Job? = null

    fun attach(switchId: String, target: WorkMode? = null) {
        if (switchId.isBlank() || attachedId == switchId) return
        attachedId = switchId
        initialTarget = target
        serviceRecordStarted = false
        operationUncertain = false
        _uiState.value = ModeSwitchUiState(switchId = switchId, to = target)
        if (target != null) start(target) else observe(switchId)
    }

    private fun observe(switchId: String) {
        observeJob?.cancel()
        observeJob = viewModelScope.launch {
            while (true) {
                apply(readStatus(), switchId)
                if (!_uiState.value.blocksBack) break
                delay(POLL_INTERVAL_MS)
            }
        }
    }

    fun refresh() {
        if (actionJob?.isActive == true || retryStart || _imageRequest.value != null) return
        val switchId = attachedId ?: return
        viewModelScope.launch { apply(readStatus(), switchId) }
    }

    /** status() 要求后台线程；读取失败也不证明一次已观测到的写入结束。 */
    private suspend fun readStatus(): ClientStatus? = try {
        facadeProvider()?.statusAsync()
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (_: Exception) {
        null
    }

    private fun start(target: WorkMode) {
        if (actionJob?.isActive == true) return
        actionJob = viewModelScope.launch {
            try {
                executeStart(target)
            } finally {
                _uiState.update { it.copy(actionRunning = false) }
            }
        }
    }

    private suspend fun executeStart(target: WorkMode, images: ModeSwitchImages? = null) {
        val switchId = attachedId ?: return
        observeJob?.cancel()
        retryStart = false
        serviceRecordStarted = false
        operationUncertain = false
        _uiState.update { it.copy(
            phase = ModeSwitchPhase.RUNNING, to = target, code = "", detail = "", stage = "",
            stateWire = "", step = "", rebootRequired = false, canRollback = false,
            canResumeReboot = false, requiresExternalRecovery = false, actionRunning = true,
            hasServiceRecord = false,
        ) }
        WorkModeSwitchSession.begin(switchId)
        val outcome = try {
            withContext(Dispatchers.IO) {
                val facade = facadeProvider() ?: return@withContext SwitchOutcome.Blocked(
                    CODE_SERVICE_NOT_READY, "facade not initialized", emptyList(),
                )
                // 打开进度页本身就是用户确认后的模式切换动作；保持与安装入口相同的
                // hidden 协议，仍由 Facade/HiddenSwitchCoordinator 执行真正的持久化、关闭
                // 与回读，不在 UI 层复制隐藏逻辑。
                facade.startSwitch(target, confirmHidden = true, requestedSwitchId = switchId,
                    images = images, useDefaultSigning = true, onProgress = { stage ->
                    if (stage == "S2") serviceRecordStarted = true
                    _uiState.update { it.copy(stage = stage) }
                })
            }
        } catch (cancelled: CancellationException) {
            withContext(NonCancellable) {
                val status = readStatus()?.takeIf { it.switchId == switchId }
                WorkModeSwitchSession.finish(SwitchOutcome.Failed(status?.switchId ?: switchId.takeIf { serviceRecordStarted },
                    CODE_SERVICE_FAILED, "switch cancelled", status))
            }
            throw cancelled
        } catch (failure: Exception) {
            val status = readStatus()?.takeIf { it.switchId == switchId }
            SwitchOutcome.Failed(status?.switchId ?: switchId.takeIf { serviceRecordStarted },
                CODE_SERVICE_FAILED, failure.message.orEmpty(), status)
        }
        applyOutcome(outcome)
    }

    fun cancelImageSelection() {
        if (_uiState.value.actionRunning) return
        _imageRequest.value = null
        _imageError.value = null
        _uiState.update { it.copy(phase = ModeSwitchPhase.FAILED, stateWire = "CANCELLED", code = "", detail = "") }
    }

    fun continueWithImages(boot: Uri?, initBoot: Uri?) {
        val request = _imageRequest.value ?: return
        if (actionJob?.isActive == true || request.requiresBoot && boot == null ||
            request.restoreInitBoot && initBoot == null) return
        _imageError.value = null
        _uiState.update { it.copy(actionRunning = true) }
        actionJob = viewModelScope.launch {
            var directory: File? = null
            try {
                val images = try {
                    withContext(Dispatchers.IO) {
                        val cache = File(ksuApp.cacheDir, "switch-images-${UUID.randomUUID()}")
                        directory = cache
                        check(cache.mkdirs())
                        fun copy(uri: Uri?, name: String): File? = uri?.let {
                            File(cache, name).also { destination ->
                                requireNotNull(ksuApp.contentResolver.openInputStream(uri)).use { input ->
                                    destination.outputStream().use { output ->
                                        val buffer = ByteArray(64 * 1024)
                                        var size = 0L
                                        while (true) {
                                            coroutineContext.ensureActive()
                                            val count = input.read(buffer)
                                            if (count < 0) break
                                            size += count
                                            check(size <= dev.maplesu.manager.ultrakernel.UltraKernelCatalog.MAX_IMAGE_BYTES)
                                            output.write(buffer, 0, count)
                                        }
                                    }
                                }
                            }
                        }
                        ModeSwitchImages(copy(boot, "boot.img"), copy(initBoot, "init_boot.img"))
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    _imageError.value = failure.message.orEmpty()
                    return@launch
                }
                _imageRequest.value = null
                executeStart(request.target, images)
            } finally {
                withContext(NonCancellable + Dispatchers.IO) { directory?.deleteRecursively() }
                _uiState.update { it.copy(actionRunning = false) }
            }
        }
    }

    private fun applyOutcome(received: SwitchOutcome) {
        val outcome = if (received is SwitchOutcome.Failed) {
            val record = received.status?.takeIf { it.switchId == attachedId }
            if (record != null) serviceRecordStarted = true
            if (received.code == ModeSwitchRootProtocol.UNCERTAIN) operationUncertain = true
            received.copy(
                switchId = record?.switchId ?: received.switchId.takeIf {
                    serviceRecordStarted || operationUncertain || received.detail.startsWith("RECOVERY_REQUIRED:")
                },
                status = record,
            )
        } else received
        WorkModeSwitchSession.finish(outcome)
        when (outcome) {
            is SwitchOutcome.ImagesRequired -> {
                retryStart = true
                _imageRequest.value = outcome
                localFailure("BASELINE_MISSING", "")
            }
            is SwitchOutcome.Blocked -> {
                retryStart = initialTarget != null
                localFailure(outcome.code, outcome.detail)
            }
            is SwitchOutcome.AwaitingReboot -> complete(outcome.switchId, outcome.status, reboot = true)
            is SwitchOutcome.Verified -> complete(outcome.switchId, outcome.status, reboot = false)
            is SwitchOutcome.Incomplete -> fail(outcome.switchId, outcome.status, outcome.code, outcome.detail)
            is SwitchOutcome.Failed -> {
                retryStart = initialTarget != null && outcome.switchId == null
                fail(outcome.switchId, outcome.status, outcome.code, outcome.detail)
            }
        }
    }

    private fun localFailure(code: String, detail: String) {
        _uiState.update { it.copy(phase = ModeSwitchPhase.FAILED, stateWire = "FAILED_PRE_WRITE",
            code = code, detail = detail, pending = false, rebootRequired = false,
            hasServiceRecord = false, canRollback = false, requiresExternalRecovery = false) }
    }

    private fun complete(switchId: String, status: ClientStatus?, reboot: Boolean) {
        status?.let { apply(it, switchId) }
        _uiState.update { it.copy(phase = ModeSwitchPhase.SUCCEEDED, pending = reboot,
            rebootRequired = reboot, hasServiceRecord = true) }
    }

    private fun fail(switchId: String?, status: ClientStatus?, code: String, detail: String) {
        status?.let { apply(it, attachedId ?: return) }
        val recovery = status?.state == "RECOVERY_REQUIRED" || detail.startsWith("RECOVERY_REQUIRED:")
        _uiState.update { it.copy(phase = if (recovery) ModeSwitchPhase.NEEDS_RECOVERY else ModeSwitchPhase.FAILED,
            code = code, detail = detail, hasServiceRecord = serviceRecordStarted || status != null,
            pending = WorkModeSwitchSession.pending && switchId != null,
            requiresExternalRecovery = recovery) }
    }

    fun retry() {
        if (!_uiState.value.canRetry) return
        val target = initialTarget
        if (retryStart && target != null) {
            _imageRequest.value = null
            _imageError.value = null
            start(target)
        } else {
            val switchId = attachedId ?: return
            perform { it.retryVerify(switchId) }
        }
    }

    fun abort() {
        if (_uiState.value.canAbort) perform { it.abort() }
    }

    fun rollback() {
        if (!_uiState.value.canRollback || _uiState.value.blocksBack) return
        perform { it.rollback() }
    }

    private fun perform(action: suspend (ModeSwitchFacade) -> Any?) {
        if (actionJob?.isActive == true) return
        actionJob = viewModelScope.launch {
            _uiState.update { it.copy(actionRunning = true) }
            try {
                when (val result = withContext(Dispatchers.IO) { facadeProvider()?.let { action(it) } }) {
                    is SwitchOutcome -> applyOutcome(result)
                    is ClientResult -> {
                        result.status?.let(WorkModeSwitchSession::observe)
                        attachedId?.let { apply(readStatus(), it) }
                    }
                    false -> Toast.makeText(ksuApp, R.string.reboot_request_failed, Toast.LENGTH_LONG).show()
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                // Retain the authoritative state; an RPC error is not a completion signal.
            } finally {
                _uiState.update { it.copy(actionRunning = false) }
                if (_uiState.value.blocksBack && observeJob?.isActive != true) attachedId?.let(::observe)
            }
        }
    }

    fun requestReboot() {
        if (!_uiState.value.rebootRequired || _uiState.value.blocksBack) return
        val switchId = attachedId ?: return
        perform { it.reboot(switchId) }
    }

    fun dismiss() {
        observeJob?.cancel()
        observeJob = null
        attachedId = null
    }

    private fun apply(status: ClientStatus?, switchId: String) {
        if (attachedId != switchId) return
        if (status?.switchId == switchId) {
            serviceRecordStarted = true
            WorkModeSwitchSession.observe(status)
        }
        val ownsSession = WorkModeSwitchSession.switchId == switchId
        _uiState.update { previous ->
            projectModeSwitchStatus(previous, status, switchId,
                facadeExecuting = ownsSession && WorkModeSwitchSession.executing,
                completionFailureCode = WorkModeSwitchSession.failureCode.takeIf { ownsSession }.orEmpty(),
                completionFailureDetail = WorkModeSwitchSession.failureDetail.takeIf { ownsSession }.orEmpty(),
                knownPending = ownsSession && WorkModeSwitchSession.pending,
            ).copy(actionRunning = previous.actionRunning)
        }
    }

    private companion object {
        const val POLL_INTERVAL_MS = 500L
        const val CODE_SERVICE_NOT_READY = "SWITCH_SERVICE_NOT_READY"
        const val CODE_SERVICE_FAILED = "SWITCH_SERVICE_FAILED"
    }
}
