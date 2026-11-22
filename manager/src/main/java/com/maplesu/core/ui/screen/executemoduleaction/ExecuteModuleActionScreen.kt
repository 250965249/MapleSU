package com.maplesu.core.ui.screen.executemoduleaction

import android.widget.Toast
import androidx.activity.compose.LocalActivity
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigationevent.compose.NavigationBackHandler
import androidx.navigationevent.compose.rememberNavigationEventState
import androidx.navigationevent.NavigationEventInfo
import kotlinx.coroutines.launch
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.navigation3.LocalNavigator
@Composable
fun ExecuteModuleActionScreen(moduleId: String, fromShortcut: Boolean = false) {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val activity = LocalActivity.current
    val scope = rememberCoroutineScope()
    val model = viewModel<ExecuteModuleActionViewModel>()
    val state by model.state.collectAsStateWithLifecycle()
    val uiMode = LocalUiMode.current
    val snackbarHost = remember { SnackbarHostState() }
    val exitExecute = {
        if (fromShortcut && activity != null) {
            activity.finishAndRemoveTask()
        } else {
            navigator.pop()
        }
    }

    fun showMessage(message: String) {
        scope.launch {
            if (uiMode == UiMode.Material) {
                snackbarHost.showSnackbar(message)
            } else {
                Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
            }
        }
    }

    // The entry ViewModel survives skin changes and Activity recreation without replaying a command.
    val messages = ModuleActionMessages(
        stringResource(R.string.module_action_failed_message),
        stringResource(R.string.module_action_interrupted),
        stringResource(R.string.module_action_restored_complete),
    )
    LaunchedEffect(moduleId) { model.start(moduleId, messages) }

    val successMessage = stringResource(R.string.module_action_success)
    LaunchedEffect(state.isComplete) {
        if (state.isComplete) {
            if (fromShortcut) {
                val message = if (state.succeeded) successMessage
                    else state.text.lineSequence().lastOrNull { it.isNotBlank() } ?: messages.failed
                Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
                exitExecute()
            }
        }
    }

    val waitMessage = stringResource(R.string.module_action_wait)
    val requestBack: () -> Unit = {
        if (model.state.value.isComplete) exitExecute() else showMessage(waitMessage)
    }
    NavigationBackHandler(
        state = rememberNavigationEventState(NavigationEventInfo.None),
        isBackEnabled = true,
        onBackCompleted = requestBack,
    )
    val actions = ExecuteModuleActionScreenActions(
        onBack = requestBack,
        // 🟠（v2.19）失败文案在组合期取好（saveLog 不是 @Composable，只能传字符串进去）
        onSaveLog = saveLog(model::logSnapshot, scope, stringResource(R.string.log_save_failed),
            stringResource(R.string.module_action_log_saved)) { showMessage(it) },
        onClose = requestBack,
    )

    val displayState = if (state.text.isEmpty() && !state.isComplete) {
        state.copy(text = stringResource(R.string.module_operation_running))
    } else state
    when (uiMode) {
        UiMode.Miuix -> ExecuteModuleActionScreenMiuix(displayState, actions)
        UiMode.Material -> ExecuteModuleActionScreenMaterial(displayState, actions, snackbarHost)
    }
}
