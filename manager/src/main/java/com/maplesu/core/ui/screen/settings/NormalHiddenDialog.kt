package com.maplesu.core.ui.screen.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.background
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.maplesu.core.R
import com.maplesu.core.ui.screen.host.HiddenFlowButton
import com.maplesu.core.ui.screen.host.HiddenFlowDialog
import com.maplesu.core.ui.screen.host.HiddenFlowText
import com.maplesu.core.ui.screen.host.hiddenFlowColors

/** No controller calls: both native skins render the same explicit confirmation state. */
@Composable
internal fun NormalHiddenDialog(
    ui: NormalHiddenUi,
    onDismiss: () -> Unit,
    onPrepare: () -> Unit,
    onCopyLink: () -> Unit,
    onOpenLink: () -> Unit,
    onSaveLink: () -> Unit,
    onConfirm: () -> Unit,
    onPortChange: (String) -> Unit = {},
) {
    if (!ui.visible) return
    if (ui.completed) {
        HiddenFlowDialog(
            title = stringResource(R.string.normal_hidden_done_title),
            onDismiss = onDismiss,
            confirmLabel = stringResource(R.string.normal_hidden_done),
            onConfirm = onDismiss,
            dismissLabel = stringResource(R.string.lite_hidden_confirm_cancel),
        ) {
            HiddenFlowText(stringResource(R.string.normal_hidden_done_body), secondary = true)
        }
        return
    }
    if (ui.linkAvailable) {
        HiddenFlowDialog(
            title = stringResource(R.string.normal_hidden_link_title),
            onDismiss = onDismiss,
            confirmLabel = stringResource(if (ui.activating) R.string.normal_hidden_activating
                else R.string.normal_hidden_saved_confirm),
            onConfirm = { onSaveLink(); onConfirm() },
            dismissLabel = stringResource(R.string.lite_hidden_confirm_cancel),
            confirmEnabled = ui.canConfirm || ui.canSaveLink,
            dismissEnabled = !ui.activating,
        ) {
            HiddenFlowText(stringResource(R.string.normal_hidden_body), secondary = true)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                HiddenFlowButton(stringResource(R.string.normal_hidden_copy), onCopyLink, Modifier.weight(1f),
                    enabled = !ui.busy)
                HiddenFlowButton(stringResource(R.string.ui_polish_link_open), onOpenLink, Modifier.weight(1f),
                    enabled = !ui.busy)
            }
            NormalHiddenFailureText(ui.failure)
        }
        return
    }

    val colors = hiddenFlowColors()
    HiddenFlowDialog(
        title = stringResource(R.string.normal_hidden_setup_title),
        onDismiss = onDismiss,
        confirmLabel = stringResource(if (ui.failure != null) R.string.normal_hidden_retry
            else R.string.normal_hidden_prepare),
        onConfirm = onPrepare,
        dismissLabel = stringResource(R.string.lite_hidden_confirm_cancel),
        confirmEnabled = ui.canPrepare && ui.portValid,
    ) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            HiddenFlowText(stringResource(R.string.lite_hidden_webui_port), Modifier.weight(1f))
            BasicTextField(
                value = ui.portText, onValueChange = onPortChange, singleLine = true,
                enabled = ui.canPrepare,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                textStyle = TextStyle(color = colors.text, fontSize = 16.sp, textAlign = TextAlign.End),
                cursorBrush = SolidColor(colors.primary),
                modifier = Modifier.widthIn(min = 90.dp, max = 120.dp)
                    .background(colors.surface, RoundedCornerShape(12.dp))
                    .padding(12.dp).testTag("normalHiddenPort"),
            )
        }
        if (!ui.portValid) HiddenFlowText(stringResource(R.string.lite_hidden_port_invalid),
            secondary = true, color = colors.error)
        if (ui.preparing || ui.checkingWebUi) {
            HiddenFlowText(stringResource(R.string.normal_hidden_preparing), secondary = true)
        }
        NormalHiddenFailureText(ui.failure)
    }
}

@Composable
private fun NormalHiddenFailureText(failure: NormalHiddenFailure?) {
    if (failure == null) return
    HiddenFlowText(stringResource(when (failure) {
        NormalHiddenFailure.PREPARE -> R.string.normal_hidden_prepare_failed
        NormalHiddenFailure.ACTIVATE -> R.string.normal_hidden_activate_failed
        NormalHiddenFailure.COPY -> R.string.normal_hidden_copy_failed
        NormalHiddenFailure.OPEN -> R.string.normal_hidden_open_failed
    }), secondary = true, color = hiddenFlowColors().error)
}
