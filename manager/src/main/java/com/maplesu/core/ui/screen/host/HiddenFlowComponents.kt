package com.maplesu.core.ui.screen.host

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.theme.materialDialogColor
import com.maplesu.core.ui.theme.miuixDialogColor
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.window.WindowDialog

/** Shared flow semantics, rendered with native components from the selected skin. */
internal data class HiddenFlowColors(
    val background: Color,
    val surface: Color,
    val text: Color,
    val secondary: Color,
    val primary: Color,
    val error: Color,
    val outline: Color,
)

@Composable
internal fun hiddenFlowColors(): HiddenFlowColors = when (LocalUiMode.current) {
    UiMode.Miuix -> with(MiuixTheme.colorScheme) {
        HiddenFlowColors(background.copy(alpha = 1f), surface, onSurface, onSurfaceVariantSummary,
            primary, error, outline)
    }
    UiMode.Material -> with(MaterialTheme.colorScheme) {
        HiddenFlowColors(background.copy(alpha = 1f), surfaceContainer, onSurface, onSurfaceVariant,
            primary, error, outline)
    }
}

@Composable
internal fun HiddenFlowText(
    text: String,
    modifier: Modifier = Modifier,
    secondary: Boolean = false,
    color: Color = Color.Unspecified,
    title: Boolean = false,
    maxLines: Int = Int.MAX_VALUE,
) {
    val resolved = if (color != Color.Unspecified) color else {
        val colors = hiddenFlowColors()
        if (secondary) colors.secondary else colors.text
    }
    when (LocalUiMode.current) {
        UiMode.Miuix -> top.yukonga.miuix.kmp.basic.Text(
            text = text, modifier = modifier, color = resolved,
            fontSize = if (title) 20.sp else if (secondary) 13.sp else 16.sp,
            maxLines = maxLines, overflow = TextOverflow.Ellipsis,
        )
        UiMode.Material -> androidx.compose.material3.Text(
            text = text, modifier = modifier, color = resolved,
            style = if (title) MaterialTheme.typography.titleLarge else if (secondary)
                MaterialTheme.typography.bodySmall else MaterialTheme.typography.bodyLarge,
            maxLines = maxLines, overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
internal fun HiddenFlowButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    primary: Boolean = false,
) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> top.yukonga.miuix.kmp.basic.TextButton(
            text = text, onClick = onClick, modifier = modifier, enabled = enabled,
            colors = if (primary) ButtonDefaults.textButtonColorsPrimary() else ButtonDefaults.textButtonColors(),
        )
        UiMode.Material -> if (primary) {
            androidx.compose.material3.Button(onClick = onClick, modifier = modifier, enabled = enabled) {
                androidx.compose.material3.Text(text)
            }
        } else {
            androidx.compose.material3.TextButton(onClick = onClick, modifier = modifier, enabled = enabled) {
                androidx.compose.material3.Text(text)
            }
        }
    }
}

@Composable
internal fun HiddenFlowDialog(
    title: String,
    onDismiss: () -> Unit,
    confirmLabel: String,
    onConfirm: () -> Unit,
    dismissLabel: String,
    confirmEnabled: Boolean = true,
    dismissEnabled: Boolean = true,
    content: @Composable () -> Unit,
) {
    val maxBodyHeight = (LocalConfiguration.current.screenHeightDp * 0.55f).dp
    val body: @Composable () -> Unit = {
        Column(Modifier.heightIn(max = maxBodyHeight).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            content()
        }
    }
    when (LocalUiMode.current) {
        UiMode.Miuix -> WindowDialog(
            show = true, title = title, backgroundColor = miuixDialogColor(),
            onDismissRequest = { if (dismissEnabled) onDismiss() },
        ) {
            body()
            Row(Modifier.fillMaxWidth().padding(top = 20.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                HiddenFlowButton(dismissLabel, onDismiss, Modifier.weight(1f), enabled = dismissEnabled)
                HiddenFlowButton(confirmLabel, onConfirm, Modifier.weight(1f), enabled = confirmEnabled, primary = true)
            }
        }
        UiMode.Material -> AlertDialog(
            onDismissRequest = { if (dismissEnabled) onDismiss() },
            containerColor = materialDialogColor(),
            title = { HiddenFlowText(title, title = true) }, text = body,
            confirmButton = { HiddenFlowButton(confirmLabel, onConfirm, enabled = confirmEnabled, primary = true) },
            dismissButton = { HiddenFlowButton(dismissLabel, onDismiss, enabled = dismissEnabled) },
        )
    }
}
