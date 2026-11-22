package dev.maplesu.manager.workmode.ui

import androidx.compose.runtime.Immutable
import dev.maplesu.manager.workmode.ModeCapabilities
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.detect.ModeState

/**
 * 工作模式页交互状态机。
 *
 * 与 `ModeState`（设备是什么）正交：本状态描述"页面走到哪一步"。纯 Kotlin、无 Android 依赖
 * → 主机单测（T1 `WorkModeStateMachineTest`）。
 */
enum class WorkModePhase {
    /** 正在判定/自检；所有按钮禁用。 */
    ANALYZING,

    /** 判定完成，可切换（或只读，见 04 §2.5 表格）。 */
    READY,

    /** S1–S4 进行中（进度页接管）。 */
    RUNNING,

    /** 完成，等待重启（rebootRequired=true）。 */
    SUCCEEDED,

    /** 失败：已回滚 / 需人工（failure.rolledBack 区分）。 */
    FAILED,
}

@Immutable
data class GateItem(val code: String, val title: String, val detail: String? = null)

@Immutable
data class SwitchProgress(val stage: String, val step: String, val fraction: Float?, val text: String)

@Immutable
data class WorkModeFailure(
    val code: String,
    val detail: String?,
    /** true=已自动回滚；false/null=需要人工恢复。 */
    val rolledBack: Boolean,
    val restoredPartitions: List<String> = emptyList(),
)

@Immutable
data class WorkModeUiState(
    val detection: ModeState = ModeState.INDETERMINATE,
    val capabilities: ModeCapabilities = ModeCapabilities.NONE,
    val phase: WorkModePhase = WorkModePhase.ANALYZING,
    /** 来自 ModeRuntime.active；未判定为 null。 */
    val current: WorkMode? = null,
    /** 用户选择的目标模式。 */
    val target: WorkMode? = null,
    /** 隐身伪装：任何模式信息都不得出现（主文档:431）。 */
    val masked: Boolean = false,
    /** 切换事务后端是否已接入；当前恒 false（W08 未落地），页面按只读态渲染。 */
    val switchSupported: Boolean = false,
    val blockers: List<GateItem> = emptyList(),
    val warnings: List<GateItem> = emptyList(),
    val progress: SwitchProgress? = null,
    val rebootRequired: Boolean = false,
    val failure: WorkModeFailure? = null,
    val logText: String = "",
    /** 一次性提示（例如"切换后端未接入"），由 ViewModel 侧文案填充。 */
    val notice: String? = null,
    /** 切换可用性（W08）：由 ViewModel 用 [SwitchAvailabilityPolicy] 计算后注入。 */
    val availability: SwitchAvailability = SwitchAvailability.BLOCKED,
    /** 已接受的本地请求或已有任务 ID，用于进入进度页。 */
    val runningSwitchId: String? = null,
    /** 已经跳转过进度页的 switchId（同一次切换只自动跳一次）。 */
    val openedSwitchId: String? = null,
    /** 设备上尚未结束的切换（上次中断 / 本进程之外发起）；null = 没有。 */
    val pendingSwitchId: String? = null,
) {
    /** 可切换的目标；null = 当前没有可切换的目标（未判定/外来 Root/内核-only）。 */
    val switchTarget: WorkMode?
        get() = if (masked) {
            null
        } else {
            when (current) {
                WorkMode.LITE -> WorkMode.KSU
                WorkMode.KSU -> WorkMode.LITE
                null -> null
            }
        }

    /** 主按钮是否可用：READY + 有目标 + 无阻断 + 切换后端已接入。 */
    val switchable: Boolean
        get() = phase == WorkModePhase.READY &&
            !masked &&
            switchTarget != null &&
            blockers.isEmpty()

    /** 需要人工恢复（自动回滚未完成）。 */
    val needsManualRecovery: Boolean
        get() = phase == WorkModePhase.FAILED && failure?.rolledBack != true

    /** 页面是否处于不可返回的进行态。 */
    val blocksBack: Boolean
        get() = phase == WorkModePhase.RUNNING

    /** 本地接受显式目标并打开进度页；后端执行结果不作为导航前置条件。 */
    val canStartSwitch: Boolean
        get() = !masked && phase in setOf(WorkModePhase.ANALYZING, WorkModePhase.READY, WorkModePhase.FAILED)

    /** 待自动跳转的进度页 switchId；null = 没有或已经跳过。 */
    val progressToOpen: String?
        get() = runningSwitchId?.takeIf { it != openedSwitchId }

    /** 恢复入口可用的 switchId：本次切换优先，其次是设备上未结束的切换。 */
    val recoverySwitchId: String?
        get() = runningSwitchId ?: pendingSwitchId

    /** 当前不可切换的原因码（空 = 可切换）。 */
    val availabilityCodes: List<String>
        get() = availability.blockers.map { it.code }
}

sealed interface WorkModeEvent {
    data class Detected(
        val state: ModeState,
        val capabilities: ModeCapabilities,
        val current: WorkMode?,
        val masked: Boolean,
        val switchSupported: Boolean,
    ) : WorkModeEvent

    data class Preflight(val blockers: List<GateItem>, val warnings: List<GateItem>) : WorkModeEvent
    /** W08：ViewModel 计算的真实可用性（含 S0 阻断码）。 */
    data class Availability(val availability: SwitchAvailability) : WorkModeEvent

    /**
     * 点主 CTA：READY → RUNNING，一次点击即开始切换（2026-11-01 取消第二层确认）。
     * 不满足条件时 reducer 原样返回（无副作用）。
     */
    data class StartSwitch(val target: WorkMode) : WorkModeEvent
    /** 请求已接受：进入进度页（runningSwitchId 由宿主 push Route.ModeSwitch）。 */
    data class Started(val switchId: String) : WorkModeEvent
    /** begin()/进度失败但无需人工恢复（预写失败 / 已自动回滚）。 */
    data class Incomplete(val code: String, val detail: String) : WorkModeEvent
    data class Stage(val progress: SwitchProgress) : WorkModeEvent
    data class Completed(val journalId: String, val rebootRequired: Boolean) : WorkModeEvent
    data class Failed(val failure: WorkModeFailure) : WorkModeEvent
    data class Notice(val message: String?) : WorkModeEvent

    /** 选择框打开时的首帧事实：只在判定完成前生效，让界面不等预检就能画出当前模式。 */
    data class Seed(val current: WorkMode?) : WorkModeEvent

    /** 进度页已经打开（[WorkModeUiState.progressToOpen] 只产出一次）。 */
    data class ProgressOpened(val switchId: String) : WorkModeEvent

    /** 设备上尚未结束的切换。 */
    data class PendingSwitch(val switchId: String?) : WorkModeEvent
    data object DismissResult : WorkModeEvent
    data object Retry : WorkModeEvent
}

/** 唯一允许改状态的地方；ViewModel 只是它的驱动。 */
fun WorkModeUiState.reduce(event: WorkModeEvent): WorkModeUiState = when (event) {
    is WorkModeEvent.Detected -> {
        // 防御：RUNNING 期间后台刷新不得打断进度页（04 T1 #13）。
        if (phase == WorkModePhase.RUNNING) {
            this
        } else {
            copy(
                detection = event.state,
                capabilities = event.capabilities,
                current = event.current,
                masked = event.masked,
                switchSupported = event.switchSupported,
                phase = WorkModePhase.READY,
                target = null,
                progress = null,
                failure = null,
                rebootRequired = false,
                // 页面态初值：真正可切换性由随后的 Availability 事件（含 S0 阻断）覆盖。
                availability = SwitchAvailability(
                    canSwitch = !event.masked && event.current != null,
                    current = event.current,
                    target = SwitchAvailabilityPolicy.targetOf(event.current),
                ),
            )
        }
    }

    is WorkModeEvent.Preflight -> copy(blockers = event.blockers, warnings = event.warnings)

    is WorkModeEvent.Availability -> copy(
        availability = event.availability,
        switchSupported = event.availability.blockers.none {
            it.code == SwitchBlockerCodes.BACKEND_UNAVAILABLE
        },
    )

    /**
     * D (2026-11-01): 一次点击即开始。没有 CONFIRM 阶段 —— 风险文案常驻在按钮旁，用户不需要再点
     * 第二下"确认切换"。真正进入 RUNNING 由本事件驱动（begin 成功由 [WorkModeEvent.Started] 补
     * switchId）；`startSwitch` 的失败仍由 Incomplete/Failed 显式落到 FAILED。
     */
    is WorkModeEvent.StartSwitch -> {
        val allowed = canStartSwitch && event.target != current
        if (allowed) {
            copy(
                phase = WorkModePhase.RUNNING,
                target = event.target,
                progress = null,
                failure = null,
                rebootRequired = false,
                logText = "",
                notice = null,
            )
        } else {
            this
        }
    }

    is WorkModeEvent.Started -> copy(
        phase = WorkModePhase.RUNNING,
        runningSwitchId = event.switchId,
        notice = null,
    )

    is WorkModeEvent.Incomplete -> copy(
        phase = WorkModePhase.FAILED,
        failure = WorkModeFailure(code = event.code, detail = event.detail, rolledBack = true),
        progress = null,
    )

    is WorkModeEvent.Stage -> if (phase == WorkModePhase.RUNNING) {
        copy(progress = event.progress, logText = appendLog(event.progress.text))
    } else {
        this
    }

    is WorkModeEvent.Completed -> if (phase == WorkModePhase.RUNNING) {
        copy(
            phase = WorkModePhase.SUCCEEDED,
            rebootRequired = event.rebootRequired,
            progress = null,
        )
    } else {
        this
    }

    is WorkModeEvent.Failed -> if (phase == WorkModePhase.RUNNING) {
        copy(phase = WorkModePhase.FAILED, failure = event.failure, progress = null)
    } else {
        this
    }

    is WorkModeEvent.DismissResult -> when (phase) {
        WorkModePhase.SUCCEEDED, WorkModePhase.FAILED -> copy(
            phase = WorkModePhase.READY,
            target = null,
            failure = null,
            rebootRequired = false,
            progress = null,
            runningSwitchId = null,
        )

        WorkModePhase.ANALYZING,
        WorkModePhase.READY,
        WorkModePhase.RUNNING -> this
    }

    is WorkModeEvent.Retry -> copy(
        phase = WorkModePhase.ANALYZING,
        target = null,
        progress = null,
        failure = null,
        rebootRequired = false,
        notice = null,
        runningSwitchId = null,
    )

    is WorkModeEvent.Notice -> copy(notice = event.message)

    is WorkModeEvent.Seed -> if (phase == WorkModePhase.ANALYZING && current == null) {
        copy(current = event.current)
    } else {
        this
    }

    is WorkModeEvent.ProgressOpened -> copy(openedSwitchId = event.switchId)

    is WorkModeEvent.PendingSwitch -> copy(pendingSwitchId = event.switchId)
}

private fun WorkModeUiState.appendLog(line: String): String =
    if (line.isBlank()) logText else if (logText.isEmpty()) line else "$logText\n$line"
