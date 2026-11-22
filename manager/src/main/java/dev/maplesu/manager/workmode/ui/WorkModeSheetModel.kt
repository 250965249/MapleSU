package dev.maplesu.manager.workmode.ui

import androidx.compose.runtime.Immutable
import dev.maplesu.manager.workmode.WorkMode

/**
 * 工作模式选择框的纯投影：`WorkModeUiState + 选中项 → 按钮 / 提示`。
 *
 * 选中项是选择框的本地 UI 状态，状态机只描述切换本身；两者在这里合成，皮肤只负责绘制。
 * 纯 Kotlin，主机可测。
 */
sealed interface WorkModeSheetCta {
    /** 没有可选的模式（当前模式未判定）。灰色禁用。 */
    data object NoSelection : WorkModeSheetCta

    /** 选中 = 当前模式。灰色禁用。 */
    data object CurrentMode : WorkModeSheetCta

    /** 选中另一模式。[enabled] 为 false 时灰色禁用，原因见 [WorkModeSheetNotice]。 */
    data class SwitchTo(val target: WorkMode, val enabled: Boolean) : WorkModeSheetCta

    /** 切换已开始、进度页尚未打开：按钮内转圈，选择框不可关闭。 */
    data object Switching : WorkModeSheetCta

    /** 上一次失败，点击重新发起。 */
    data class Retry(val target: WorkMode) : WorkModeSheetCta

    /** 已有进行中的切换，点击回到进度页。 */
    data class ViewProgress(val switchId: String) : WorkModeSheetCta
}

/** 确认按钮上方的一行提示；null = 没有需要说明的内容。 */
sealed interface WorkModeSheetNotice {
    /** 切换失败：[code] 经 `WorkModeStrings.failureRes` 转成人话；[recoverySwitchId] 非空时给恢复入口。 */
    data class Failed(val code: String, val recoverySwitchId: String?, val needsManualRecovery: Boolean) : WorkModeSheetNotice

    /** 设备上有尚未结束的切换：给进度入口。 */
    data class Pending(val switchId: String) : WorkModeSheetNotice
}

@Immutable
data class WorkModeSheetOption(
    val mode: WorkMode,
    val enabled: Boolean = true,
    val recommended: Boolean = false,
)

fun workModeSheetCta(selected: WorkMode?, state: WorkModeUiState): WorkModeSheetCta {
    if (state.masked) return WorkModeSheetCta.NoSelection
    val runningId = state.runningSwitchId
    return when {
        state.phase == WorkModePhase.RUNNING ->
            if (runningId != null) WorkModeSheetCta.ViewProgress(runningId) else WorkModeSheetCta.Switching

        state.phase == WorkModePhase.SUCCEEDED && runningId != null -> WorkModeSheetCta.ViewProgress(runningId)
        selected == null -> WorkModeSheetCta.NoSelection
        selected == state.current -> WorkModeSheetCta.CurrentMode
        state.phase == WorkModePhase.FAILED -> WorkModeSheetCta.Retry(selected)
        else -> WorkModeSheetCta.SwitchTo(selected, enabled = state.canStartSwitch)
    }
}

fun workModeSheetNotice(selected: WorkMode?, state: WorkModeUiState): WorkModeSheetNotice? {
    val failure = state.failure
    return when {
        state.phase == WorkModePhase.FAILED && failure != null ->
            WorkModeSheetNotice.Failed(failure.code, state.recoverySwitchId, state.needsManualRecovery)

        state.phase == WorkModePhase.RUNNING || state.phase == WorkModePhase.ANALYZING -> null
        state.pendingSwitchId != null -> WorkModeSheetNotice.Pending(state.pendingSwitchId)
        selected != null && selected == state.current -> null
        else -> null
    }
}

/** 切换真正开始后、进度页打开前不可关闭；其余情况返回键和遮罩都能关。 */
fun workModeSheetDismissible(state: WorkModeUiState): Boolean =
    !(state.phase == WorkModePhase.RUNNING && state.runningSwitchId == null)
