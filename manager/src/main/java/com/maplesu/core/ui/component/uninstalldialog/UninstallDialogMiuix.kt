package com.maplesu.core.ui.component.uninstalldialog

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** KSU 同款：居中标题、两行带图标和箭头、底部灰色取消。 */
@Composable
internal fun UninstallChooserMiuix(
    show: Boolean,
    title: String,
    choices: List<UninstallChoice>,
    onChoose: (UninstallChoice) -> Unit,
    onDismissRequest: () -> Unit,
) {
    OverlayDialog(
        show = show,
        onDismissRequest = onDismissRequest,
        insideMargin = DpSize(0.dp, 0.dp),
        content = {
            Text(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 24.dp, bottom = 12.dp),
                text = title,
                fontSize = MiuixTheme.textStyles.title4.fontSize,
                fontWeight = FontWeight.Medium,
                textAlign = TextAlign.Center,
                color = MiuixTheme.colorScheme.onSurface,
            )
            choices.forEach { choice ->
                ArrowPreference(
                    onClick = { onChoose(choice) },
                    title = choice.title,
                    summary = choice.disabledReason,
                    enabled = choice.disabledReason == null,
                    startAction = {
                        Icon(
                            imageVector = choice.icon,
                            contentDescription = null,
                            modifier = Modifier.padding(end = 16.dp),
                            tint = MiuixTheme.colorScheme.onSurface,
                        )
                    },
                    insideMargin = PaddingValues(horizontal = 24.dp, vertical = 12.dp),
                )
            }
            TextButton(
                text = stringResource(id = android.R.string.cancel),
                onClick = onDismissRequest,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 12.dp, bottom = 24.dp)
                    .padding(horizontal = 24.dp),
            )
        },
    )
}
