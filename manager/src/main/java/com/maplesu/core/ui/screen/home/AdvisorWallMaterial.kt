package com.maplesu.core.ui.screen.home

import androidx.activity.compose.BackHandler
import androidx.activity.compose.LocalOnBackPressedDispatcherOwner
import androidx.activity.findViewTreeOnBackPressedDispatcherOwner
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.navigationevent.compose.LocalNavigationEventDispatcherOwner
import androidx.navigationevent.findViewTreeNavigationEventDispatcherOwner
import com.maplesu.core.ui.theme.isInDarkTheme

/**
 * 用户顾问计划卡片 · Material：M3 字阶与色彩角色，按钮是胶囊形。
 */
@Composable
internal fun AdvisorWallMaterial(modifier: Modifier = Modifier, initiallyExpanded: Boolean = false) {
    val colors = MaterialTheme.colorScheme
    val type = MaterialTheme.typography
    AdvisorWallCard(
        style = AdvisorWallStyle(
            dark = isInDarkTheme(),
            shape = MaterialTheme.shapes.large,
            title = type.titleSmall.copy(color = colors.onSurface),
            body = type.bodySmall.copy(color = colors.onSurfaceVariant),
            name = type.titleLarge.copy(color = colors.onSurface, textAlign = TextAlign.Center),
            role = type.bodyMedium.copy(color = colors.onSurface, textAlign = TextAlign.Center),
            note = type.bodyMedium.copy(color = colors.onSurfaceVariant, textAlign = TextAlign.Center),
            label = type.labelMedium,
            button = type.labelLarge,
            content = colors.onSurface,
            secondary = colors.onSurfaceVariant,
            chip = colors.surfaceContainerHighest,
            hairline = colors.outlineVariant,
            buttonShape = CircleShape,
            buttonHeight = 44.dp,
        ),
        backHandler = { enabled, onBack -> DialogBackHandler(enabled, onBack) },
        modifier = modifier,
        initiallyExpanded = initiallyExpanded,
    )
}

/**
 * Material 的「关于」是独立的弹窗窗口，而组合里继承下来的返回分发器属于 Activity（NavDisplay 的条目），
 * 这里换成弹窗窗口自己的，返回键才会先关详情、再关小窗。做法同 WorkModeSheetMaterial。
 */
@Composable
private fun DialogBackHandler(enabled: Boolean, onBack: () -> Unit) {
    val view = LocalView.current
    val navigation = view.findViewTreeNavigationEventDispatcherOwner()
    val back = view.findViewTreeOnBackPressedDispatcherOwner()
    if (navigation != null && back != null) {
        CompositionLocalProvider(
            LocalNavigationEventDispatcherOwner provides navigation,
            LocalOnBackPressedDispatcherOwner provides back,
        ) {
            BackHandler(enabled = enabled, onBack = onBack)
        }
    } else {
        BackHandler(enabled = enabled, onBack = onBack)
    }
}
