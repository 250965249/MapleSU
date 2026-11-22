package com.maplesu.core.ui.screen.flash

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.screen.host.HiddenFlowButton
import com.maplesu.core.ui.screen.host.HiddenFlowText
import com.maplesu.core.ui.theme.materialDialogColor
import com.maplesu.core.ui.theme.miuixDialogColor
import kotlinx.coroutines.CompletableDeferred
import top.yukonga.miuix.kmp.preference.CheckboxPreference
import top.yukonga.miuix.kmp.window.WindowDialog

internal data class ModulePolicyNoticeRequest(
    val moduleName: String,
    // null = dismissed without confirming; it never persists the checkbox.
    val result: CompletableDeferred<Boolean?> = CompletableDeferred(),
)

@Composable
internal fun ModulePolicyNoticeDialog(request: ModulePolicyNoticeRequest) {
    var suppress by rememberSaveable(request.moduleName) { mutableStateOf(false) }
    val title = stringResource(R.string.ultra_module_policy_notice_title)
    val maxHeight = (LocalConfiguration.current.screenHeightDp * 0.55f).dp
    val body: @Composable () -> Unit = {
        Column(Modifier.heightIn(max = maxHeight).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            HiddenFlowText(stringResource(R.string.ultra_module_policy_notice, request.moduleName))
            if (LocalUiMode.current == UiMode.Miuix) {
                CheckboxPreference(title = stringResource(R.string.ultra_module_policy_notice_suppress),
                    checked = suppress, onCheckedChange = { suppress = it })
            } else {
                Row(Modifier.fillMaxWidth().toggleable(suppress, role = Role.Checkbox, onValueChange = { suppress = it }),
                    verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(suppress, onCheckedChange = null)
                    HiddenFlowText(stringResource(R.string.ultra_module_policy_notice_suppress),
                        Modifier.padding(start = 8.dp))
                }
            }
        }
    }
    val confirm: @Composable () -> Unit = {
        HiddenFlowButton(stringResource(R.string.confirm), { request.result.complete(suppress) },
            Modifier.fillMaxWidth(), primary = true)
    }
    when (LocalUiMode.current) {
        UiMode.Miuix -> WindowDialog(show = true, title = title, backgroundColor = miuixDialogColor(),
            onDismissRequest = { request.result.complete(null) }) {
            body()
            Column(Modifier.fillMaxWidth().padding(top = 20.dp)) { confirm() }
        }
        UiMode.Material -> AlertDialog(onDismissRequest = { request.result.complete(null) },
            containerColor = materialDialogColor(), title = { HiddenFlowText(title, title = true) },
            text = body, confirmButton = confirm)
    }
}
