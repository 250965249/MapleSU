package dev.maplesu.manager.workmode.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.navigation3.LocalNavigator
import com.maplesu.core.ui.navigation3.WorkModeNavigation
import dev.maplesu.manager.workmode.WorkMode

/** 选择框确认按钮的外观：皮肤只看这份，不再判断业务状态。 */
enum class WorkModeSheetButtonStyle {
    /** 用户主题色。 */
    PRIMARY,

    /** 灰色禁用。 */
    DISABLED,

    /** 主题色 + 按钮内转圈，点击无效。 */
    LOADING,
}

/** 确认按钮上方的提示及其可选的动作。 */
@Immutable
data class WorkModeSheetHint(
    val text: String,
    val isError: Boolean,
    val actionText: String? = null,
    val onAction: (() -> Unit)? = null,
)

/** 选择框的展示模型（两个皮肤共用一份）。 */
@Immutable
data class WorkModeSheetUi(
    val title: String,
    val current: WorkMode?,
    val selected: WorkMode?,
    val options: List<WorkModeSheetOption>,
    val confirmText: String,
    val confirmStyle: WorkModeSheetButtonStyle,
    val note: String?,
    val hint: WorkModeSheetHint?,
    val dismissible: Boolean,
)

/**
 * 切换工作模式的选择框。首页、设置等入口的唯一落点，由调用方持有开关。
 *
 * ViewModel 只读取已有本地状态；用户确认后立即打开进度页，再由进度页执行。
 */
@Composable
fun WorkModeSwitchSheet(show: Boolean, onDismiss: () -> Unit) {
    var activated by remember { mutableStateOf(show) }
    if (show && !activated) activated = true
    if (activated) WorkModeSwitchSheetHost(show, onDismiss)
}

@Composable
private fun WorkModeSwitchSheetHost(show: Boolean, onDismiss: () -> Unit) {
    val navigator = LocalNavigator.current
    val viewModel = viewModel<WorkModeViewModel>()
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    var selected by rememberSaveable { mutableStateOf(state.current) }

    LaunchedEffect(show) {
        if (show) {
            selected = state.current
            viewModel.onSheetOpened()
        }
    }
    // 预检回来后才知道当前模式时，补上默认选中。
    LaunchedEffect(state.current) {
        if (selected == null) selected = state.current
    }
    // 本地请求已接受：收起选择框并进入进度页，同一次请求只跳一次。
    val progressId = state.progressToOpen
    LaunchedEffect(progressId) {
        if (progressId != null) {
            viewModel.onProgressOpened(progressId)
            onDismiss()
            WorkModeNavigation.openProgress(navigator, progressId, state.target)
        }
    }
    // 隐藏/隐身优先：一旦判定为遮蔽，不留下任何模式信息。
    LaunchedEffect(state.masked, show) {
        if (state.masked && show) onDismiss()
    }
    if (state.masked) return

    val cta = workModeSheetCta(selected, state)
    val dismissible = workModeSheetDismissible(state)
    val openProgress: (String) -> Unit = { switchId ->
        onDismiss()
        WorkModeNavigation.openProgress(navigator, switchId)
    }
    val ui = WorkModeSheetUi(
        title = stringResource(R.string.work_mode_switch_button),
        current = state.current,
        selected = selected,
        options = WorkMode.entries.map { WorkModeSheetOption(it) },
        confirmText = confirmText(cta),
        confirmStyle = confirmStyle(cta),
        note = stringResource(R.string.work_mode_confirm_body),
        hint = sheetHint(
            notice = workModeSheetNotice(selected, state),
            onOpenProgress = openProgress,
            onOpenRecovery = { switchId ->
                onDismiss()
                WorkModeNavigation.openRecovery(navigator, switchId)
            },
        ),
        dismissible = dismissible,
    )

    WorkModeSheet(
        show = show,
        ui = ui,
        onSelect = {
            if (!state.blocksBack) {
                selected = it
            }
        },
        onConfirm = {
            when (cta) {
                is WorkModeSheetCta.SwitchTo -> if (cta.enabled) viewModel.onConfirmSwitch(cta.target)
                is WorkModeSheetCta.Retry -> viewModel.onConfirmSwitch(cta.target)
                is WorkModeSheetCta.ViewProgress -> openProgress(cta.switchId)
                WorkModeSheetCta.CurrentMode,
                WorkModeSheetCta.NoSelection,
                WorkModeSheetCta.Switching -> Unit
            }
        },
        onDismiss = onDismiss,
    )
}

@Composable
private fun confirmText(cta: WorkModeSheetCta): String = when (cta) {
    WorkModeSheetCta.NoSelection -> stringResource(R.string.work_mode_target_row_title)
    WorkModeSheetCta.CurrentMode -> stringResource(R.string.work_mode_cta_current)
    is WorkModeSheetCta.SwitchTo -> switchToText(cta.target)
    WorkModeSheetCta.Switching -> stringResource(R.string.work_mode_cta_switching)
    is WorkModeSheetCta.Retry -> stringResource(R.string.work_mode_retry)
    is WorkModeSheetCta.ViewProgress -> stringResource(R.string.work_mode_open_progress)
}

@Composable
private fun switchToText(target: WorkMode): String = stringResource(
    R.string.work_mode_switch_to,
    stringResource(WorkModeStrings.modeNameRes(target)),
)

private fun confirmStyle(cta: WorkModeSheetCta): WorkModeSheetButtonStyle = when (cta) {
    WorkModeSheetCta.NoSelection,
    WorkModeSheetCta.CurrentMode -> WorkModeSheetButtonStyle.DISABLED

    is WorkModeSheetCta.SwitchTo ->
        if (cta.enabled) WorkModeSheetButtonStyle.PRIMARY else WorkModeSheetButtonStyle.DISABLED

    WorkModeSheetCta.Switching -> WorkModeSheetButtonStyle.LOADING

    is WorkModeSheetCta.Retry,
    is WorkModeSheetCta.ViewProgress -> WorkModeSheetButtonStyle.PRIMARY
}

@Composable
private fun sheetHint(
    notice: WorkModeSheetNotice?,
    onOpenProgress: (String) -> Unit,
    onOpenRecovery: (String) -> Unit,
): WorkModeSheetHint? = when (notice) {
    null -> null

    is WorkModeSheetNotice.Failed -> WorkModeSheetHint(
        text = stringResource(
            if (notice.needsManualRecovery) R.string.work_mode_switch_recovery_required else WorkModeStrings.failureRes(notice.code),
        ),
        isError = true,
        actionText = notice.recoverySwitchId?.let { stringResource(R.string.work_mode_open_recovery) },
        onAction = notice.recoverySwitchId?.let { switchId -> { onOpenRecovery(switchId) } },
    )

    is WorkModeSheetNotice.Pending -> WorkModeSheetHint(
        text = stringResource(R.string.work_mode_pending_banner),
        isError = false,
        actionText = stringResource(R.string.work_mode_open_progress),
        onAction = { onOpenProgress(notice.switchId) },
    )
}

/**
 * 只选目标模式的选择框：安装页、迁移共用。点确认只回传结果，不触发切换。
 *
 * @param selected 打开时默认选中的模式
 * @param current 设备当前运行的模式，用于「当前」标签；未知时不显示
 * @param note 确认按钮上方的说明
 */
@Composable
fun WorkModeTargetSheet(
    show: Boolean,
    selected: WorkMode?,
    current: WorkMode?,
    onSelect: (WorkMode) -> Unit,
    onDismiss: () -> Unit,
    note: String? = stringResource(R.string.work_mode_target_install_note),
    options: List<WorkModeSheetOption> = remember { WorkMode.entries.map { WorkModeSheetOption(it) } },
) {
    var picked by remember(show) { mutableStateOf(selected) }
    val canSelect = options.any { it.mode == picked && it.enabled }
    val ui = WorkModeSheetUi(
        title = stringResource(R.string.work_mode_target_row_title),
        current = current,
        selected = picked,
        options = options,
        confirmText = stringResource(R.string.work_mode_cta_select),
        confirmStyle = if (canSelect) WorkModeSheetButtonStyle.PRIMARY else WorkModeSheetButtonStyle.DISABLED,
        note = note,
        hint = null,
        dismissible = true,
    )
    WorkModeSheet(
        show = show,
        ui = ui,
        onSelect = { picked = it },
        onConfirm = {
            if (canSelect) {
                picked?.let(onSelect)
                onDismiss()
            }
        },
        onDismiss = onDismiss,
    )
}

/** 选择框 + 模式介绍小窗，按皮肤分发。 */
@Composable
private fun WorkModeSheet(
    show: Boolean,
    ui: WorkModeSheetUi,
    onSelect: (WorkMode) -> Unit,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    var introMode by rememberSaveable { mutableStateOf<WorkMode?>(null) }
    LaunchedEffect(show) { if (!show) introMode = null }
    val visibleIntro = introMode.takeIf { show }
    when (LocalUiMode.current) {
        UiMode.Miuix -> {
            WorkModeSheetMiuix(show, ui, onSelect, { introMode = it }, onConfirm, onDismiss)
            WorkModeIntroDialogMiuix(mode = visibleIntro, onDismiss = { introMode = null })
        }

        UiMode.Material -> {
            WorkModeSheetMaterial(show, ui, onSelect, { introMode = it }, onConfirm, onDismiss)
            WorkModeIntroDialogMaterial(mode = visibleIntro, onDismiss = { introMode = null })
        }
    }
}

/**
 * 「选择目标模式」入口行：左侧图标 + 标题 + 右侧模式名 + 上下展开箭头，比普通设置行更厚。
 *
 * @param value 右侧显示的模式名
 */
@Composable
fun WorkModeTargetRow(
    value: String,
    enabled: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    title: String = stringResource(R.string.work_mode_target_row_title),
) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> WorkModeTargetRowMiuix(value, enabled, onClick, modifier, title)
        UiMode.Material -> WorkModeTargetRowMaterial(value, enabled, onClick, modifier, title)
    }
}

/** 模式介绍的一段：`标签：正文`，供皮肤把标签加粗。 */
internal fun splitIntroLine(line: String): Pair<String, String> {
    val index = line.indexOfFirst { it == '：' || it == ':' }
    if (index <= 0 || index + 1 >= line.length) return "" to line
    return line.substring(0, index + 1) to line.substring(index + 1)
}
