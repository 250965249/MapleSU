package com.maplesu.core.ui.screen.home

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigationevent.NavigationEventInfo
import androidx.navigationevent.compose.NavigationBackHandler
import androidx.navigationevent.compose.rememberNavigationEventState
import com.maplesu.core.ui.theme.isInDarkTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * 用户顾问计划卡片 · Miuix：字号对齐小窗正文的 14sp，圆角和按钮形状随 Miuix。
 *
 * Miuix 的 OverlayDialog 与页面同窗，详情打开时用 [NavigationBackHandler] 先于小窗接住返回键。
 */
@Composable
internal fun AdvisorWallMiuix(modifier: Modifier = Modifier, initiallyExpanded: Boolean = false) {
    val colors = MiuixTheme.colorScheme
    val base = MiuixTheme.textStyles.main
    val dark = isInDarkTheme()
    AdvisorWallCard(
        style = AdvisorWallStyle(
            dark = dark,
            shape = RoundedCornerShape(16.dp),
            title = base.copy(fontSize = 15.sp, lineHeight = 20.sp, fontWeight = FontWeight.Medium, color = colors.onSurface),
            body = base.copy(fontSize = 12.sp, lineHeight = 16.sp, color = colors.onSurfaceVariantSummary),
            name = base.copy(
                fontSize = 22.sp,
                lineHeight = 28.sp,
                fontWeight = FontWeight.SemiBold,
                color = colors.onSurface,
                textAlign = TextAlign.Center,
            ),
            role = base.copy(fontSize = 14.sp, lineHeight = 21.sp, color = colors.onSurface, textAlign = TextAlign.Center),
            note = base.copy(
                fontSize = 14.sp,
                lineHeight = 21.sp,
                color = colors.onSurfaceVariantSummary,
                textAlign = TextAlign.Center,
            ),
            label = base.copy(fontSize = 12.sp, lineHeight = 16.sp, fontWeight = FontWeight.Medium),
            button = base.copy(fontSize = 14.sp, lineHeight = 18.sp, fontWeight = FontWeight.Medium),
            content = colors.onSurface,
            secondary = colors.onSurfaceVariantSummary,
            chip = colors.secondaryContainer,
            hairline = colors.onSurface.copy(alpha = if (dark) 0.16f else 0.09f),
            buttonShape = RoundedCornerShape(12.dp),
            buttonHeight = 44.dp,
        ),
        backHandler = { enabled, onBack ->
            NavigationBackHandler(
                state = rememberNavigationEventState(NavigationEventInfo.None),
                isBackEnabled = enabled,
                onBackCompleted = onBack,
            )
        },
        modifier = modifier,
        initiallyExpanded = initiallyExpanded,
    )
}
