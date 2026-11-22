package dev.maplesu.manager.workmode.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigationevent.NavigationEventInfo
import androidx.navigationevent.compose.NavigationBackHandler
import androidx.navigationevent.compose.rememberNavigationEventState
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.navigation3.LocalNavigator
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.migration.MigrationFacade

/** 迁移页动作（双皮肤共用）。 */
@Immutable
data class MigrationActions(
    val onBack: () -> Unit,
    val onRefresh: () -> Unit,
    val onSelectTarget: (WorkMode) -> Unit,
    val onRequestConfirm: () -> Unit,
    val onDismissConfirm: () -> Unit,
    val onStart: () -> Unit,
    val onAbort: () -> Unit,
    val onDismissResult: () -> Unit,
    val onExportDiagnostics: () -> Unit,
    val onOpenDiagnosis: () -> Unit,
    val onOpenRecovery: () -> Unit,
    val diagnosticsAvailable: Boolean = false,
    val recoveryAvailable: Boolean = false,
)

/**
 * 外部 Root 迁移页宿主。
 *
 * - 只通过 [MigrationFacade] 检测/开始/观察/中止；**不直连分区写入**；
 * - 默认 facade = [UnavailableMigrationFacade] → 诚实降级（不出现开始按钮）；
 * - `migrationId` 非空时接管已有迁移（进度/结果视图），空则先检测；
 * - 进行中禁止返回（对齐 `ModeSwitchScreen` 的 `NavigationBackHandler` 用法）。
 */
@Composable
fun MigrationScreen(
    migrationId: String = "",
    facade: MigrationFacade = MigrationViewModel.defaultFacade(),
    initialTarget: WorkMode? = null,
    confirmOnOpen: Boolean = false,
    onBack: (() -> Unit)? = null,
    onOpenDiagnostics: (() -> Unit)? = null,
    onOpenRecovery: (() -> Unit)? = null,
    onBackEnabledChange: (Boolean) -> Unit = {},
    deviceFingerprint: String? = null,
) {
    val navigator = LocalNavigator.current
    if (migrationId.isBlank()) {
        SideEffect { onBackEnabledChange(true) }
        com.maplesu.core.ui.screen.install.InstallScreen(
            initialTarget = dev.maplesu.manager.installer.InstallTargetMode.fromWorkMode(initialTarget),
            migrationEntry = true,
            onBack = onBack,
            deviceFingerprint = deviceFingerprint,
        )
        return
    }
    val viewModel = viewModel<MigrationViewModel>()
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(migrationId, facade, initialTarget, confirmOnOpen) {
        viewModel.attach(migrationId, facade, initialTarget, confirmOnOpen)
    }
    SideEffect { onBackEnabledChange(!state.blocksBack) }

    NavigationBackHandler(
        state = rememberNavigationEventState(NavigationEventInfo.None),
        // 返回拦截器：true = 吞掉返回。只有进行中才拦截（对照 FlashScreen）。
        isBackEnabled = state.blocksBack,
        onBackCompleted = {},
    )

    val actions = MigrationActions(
        onBack = { if (!state.blocksBack) { onBack?.invoke() ?: navigator.pop() } },
        onRefresh = viewModel::refresh,
        onSelectTarget = viewModel::selectTarget,
        onRequestConfirm = viewModel::requestConfirm,
        onDismissConfirm = viewModel::dismissConfirm,
        onStart = viewModel::start,
        onAbort = viewModel::abort,
        onDismissResult = { if (!state.blocksBack) { viewModel.dismissResult(); navigator.pop() } },
        onExportDiagnostics = { onOpenDiagnostics?.invoke() },
        onOpenDiagnosis = { onOpenDiagnostics?.invoke() },
        onOpenRecovery = { onOpenRecovery?.invoke() },
        diagnosticsAvailable = onOpenDiagnostics != null,
        recoveryAvailable = onOpenRecovery != null,
    )

    when (LocalUiMode.current) {
        UiMode.Miuix -> MigrationScreenMiuix(state, actions)
        UiMode.Material -> MigrationScreenMaterial(state, actions)
    }
}
