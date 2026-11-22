package com.maplesu.core.ui.component.miuix

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.maplesu.core.ui.component.WarningLevel
import com.maplesu.core.ui.theme.isInDarkTheme
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.isDynamicColor
import top.yukonga.miuix.kmp.utils.PressFeedbackType

@Composable
fun WarningCard(
    message: String,
    modifier: Modifier = Modifier,
    level: WarningLevel = WarningLevel.Error,
    onClick: (() -> Unit)? = null,
    action: (@Composable () -> Unit)? = null,
) {
    Card(
        modifier = modifier,
        onClick = { onClick?.invoke() },
        colors = CardDefaults.defaultColors(
            color = level.containerColor(),
            contentColor = level.contentColor(),
        ),
        showIndication = onClick != null,
        pressFeedbackType = PressFeedbackType.Sink
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = message,
                fontSize = 14.sp
            )
            action?.invoke()
        }
    }
}

@Composable
private fun WarningLevel.containerColor(): Color = when (this) {
    WarningLevel.Warning -> if (isInDarkTheme()) Color(0xFF433500) else Color(0xFFFFF0C2)
    WarningLevel.Error -> when {
        isDynamicColor -> colorScheme.errorContainer
        isInDarkTheme() -> Color(0xFF310808)
        else -> Color(0xFFF8E2E2)
    }
    WarningLevel.Notice -> when {
        isDynamicColor -> colorScheme.tertiaryContainer
        isInDarkTheme() -> Color(0xFF3E2F1B)
        else -> Color(0xFFFFF0DB)
    }
}

@Composable
private fun WarningLevel.contentColor(): Color = when (this) {
    WarningLevel.Warning -> if (isInDarkTheme()) Color(0xFFFFDF88) else Color(0xFF5B4300)
    WarningLevel.Error -> if (isDynamicColor) colorScheme.onErrorContainer else Color(0xFFF72727)
    WarningLevel.Notice -> if (isDynamicColor) colorScheme.onTertiaryContainer else Color(0xFFF5A623)
}
