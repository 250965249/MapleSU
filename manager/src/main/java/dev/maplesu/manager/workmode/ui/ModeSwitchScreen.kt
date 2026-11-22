package dev.maplesu.manager.workmode.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.dropUnlessResumed
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigationevent.NavigationEventInfo
import androidx.navigationevent.compose.NavigationBackHandler
import androidx.navigationevent.compose.rememberNavigationEventState
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.navigation3.LocalNavigator
import com.maplesu.core.ui.navigation3.Route
import dev.maplesu.manager.workmode.WorkMode

/**
 * 切换进度页宿主（W08 真实阶段投影）：`switchId` 只来自 `Route.ModeSwitch`（内部 push）。
 *
 * - 运行中禁用返回（路由级 + 手势级，照抄 FlashScreen 范式）；
 * - 失败/需恢复：重试、中止（仅预写）、回滚、进入恢复页、导出诊断；
 * - 重启：通过 facade 完成已提交事务的卸载与重启。
 */
@Composable
fun ModeSwitchScreen(switchId: String, initialTarget: WorkMode? = null, onBackEnabledChange: (Boolean) -> Unit = {}) {
    val navigator = LocalNavigator.current
    val viewModel = viewModel<ModeSwitchViewModel>()
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val imageRequest by viewModel.imageRequest.collectAsStateWithLifecycle()
    val imageError by viewModel.imageError.collectAsStateWithLifecycle()
    var submitted by rememberSaveable(switchId) { mutableStateOf(false) }

    LaunchedEffect(switchId) {
        val target = initialTarget.takeUnless { submitted }
        // 恢复保存后的导航只接管记录，避免进程重建再次提交刷写。
        submitted = true
        viewModel.attach(switchId, target)
    }
    SideEffect { onBackEnabledChange(!state.blocksBack) }
    NavigationBackHandler(
        state = rememberNavigationEventState(NavigationEventInfo.None),
        // 返回拦截器：true = 吞掉返回。只有进行中才拦截（对照 FlashScreen）。
        isBackEnabled = state.blocksBack,
        onBackCompleted = {},
    )

    val actions = ModeSwitchActions(
        onBack = dropUnlessResumed {
            if (!state.blocksBack) {
                viewModel.dismiss()
                navigator.pop()
            }
        },
        onRetry = viewModel::retry,
        onAbort = viewModel::abort,
        onRollback = viewModel::rollback,
        onReboot = viewModel::requestReboot,
        onOpenRecovery = dropUnlessResumed { navigator.push(Route.Recovery(switchId)) },
        onSaveLog = dropUnlessResumed { navigator.push(Route.Diagnosis(switchId)) },
    )

    when (LocalUiMode.current) {
        UiMode.Miuix -> ModeSwitchScreenMiuix(state, actions)
        UiMode.Material -> ModeSwitchScreenMaterial(state, actions)
    }
    imageRequest?.let { request ->
        WorkModeImageDialog(
            request = request,
            busy = state.actionRunning,
            readError = imageError,
            onConfirm = viewModel::continueWithImages,
            onDismiss = viewModel::cancelImageSelection,
        )
    }
}
