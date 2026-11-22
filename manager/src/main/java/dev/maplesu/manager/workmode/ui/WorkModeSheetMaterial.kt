package dev.maplesu.manager.workmode.ui

import androidx.activity.compose.BackHandler
import androidx.activity.compose.LocalOnBackPressedDispatcherOwner
import androidx.activity.findViewTreeOnBackPressedDispatcherOwner
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.material.icons.filled.UnfoldMore
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.ModalBottomSheetProperties
import androidx.compose.material3.RadioButton
import androidx.compose.material3.SheetValue
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.navigationevent.compose.LocalNavigationEventDispatcherOwner
import androidx.navigationevent.findViewTreeNavigationEventDispatcherOwner
import com.maplesu.core.R
import com.maplesu.core.ui.component.maple.BrandDialogMaterial
import com.maplesu.core.ui.component.maple.brandBannerKind
import com.maplesu.core.ui.component.material.SegmentedColumn
import com.maplesu.core.ui.component.material.SegmentedListItem
import dev.maplesu.manager.workmode.WorkMode

/** 入口行 · Material：沿用分段列表项，加高到 76dp。 */
@Composable
internal fun WorkModeTargetRowMaterial(
    value: String,
    enabled: Boolean,
    onClick: () -> Unit,
    modifier: Modifier,
    title: String,
) {
    SegmentedColumn(
        modifier = modifier.fillMaxWidth(),
        content = listOf {
            SegmentedListItem(
                modifier = Modifier.heightIn(min = 76.dp),
                onClick = onClick,
                enabled = enabled,
                headlineContent = { Text(title) },
                leadingContent = { Icon(Icons.Filled.SwapHoriz, contentDescription = null) },
                trailingContent = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = value,
                            style = MaterialTheme.typography.bodyMedium,
                            maxLines = 1,
                        )
                        Spacer(Modifier.width(4.dp))
                        Icon(Icons.Filled.UnfoldMore, contentDescription = null, modifier = Modifier.size(20.dp))
                    }
                },
            )
        },
    )
}

/** 选择框 · Material：干净直接，短促过渡，无辉光。 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun WorkModeSheetMaterial(
    show: Boolean,
    ui: WorkModeSheetUi,
    onSelect: (WorkMode) -> Unit,
    onOpenIntro: (WorkMode) -> Unit,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    var rendered by remember { mutableStateOf(show) }
    if (show && !rendered) rendered = true
    if (!rendered) return

    val dismissible by rememberUpdatedState(ui.dismissible)
    val sheetState = rememberModalBottomSheetState(
        skipPartiallyExpanded = true,
        confirmValueChange = { value -> value != SheetValue.Hidden || dismissible },
    )
    // 由外部收起时也走完下滑动画，再把弹层移出组合。
    LaunchedEffect(show) {
        if (!show) {
            try {
                sheetState.hide()
            } finally {
                rendered = false
            }
        }
    }
    ModalBottomSheet(
        onDismissRequest = { if (dismissible) onDismiss() },
        sheetState = sheetState,
        containerColor = MaterialTheme.colorScheme.surfaceContainerLow.copy(alpha = 1f),
        properties = ModalBottomSheetProperties(shouldDismissOnBackPress = ui.dismissible),
    ) {
        // NavDisplay's entry dispatcher belongs to the Activity, not this dialog window.
        val sheetView = LocalView.current
        CompositionLocalProvider(
            LocalNavigationEventDispatcherOwner provides requireNotNull(
                sheetView.findViewTreeNavigationEventDispatcherOwner(),
            ),
            LocalOnBackPressedDispatcherOwner provides requireNotNull(
                sheetView.findViewTreeOnBackPressedDispatcherOwner(),
            ),
        ) {
            BackHandler(enabled = show) {
                if (dismissible) onDismiss()
            }
        }
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(horizontal = 24.dp)
                .padding(bottom = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = ui.title,
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.padding(bottom = 4.dp),
            )
            ui.options.forEach { option ->
                OptionRowMaterial(
                    option = option,
                    selected = ui.selected == option.mode,
                    isCurrent = ui.current == option.mode,
                    onSelect = { onSelect(option.mode) },
                    onOpenIntro = { onOpenIntro(option.mode) },
                )
            }
            ui.hint?.let { HintMaterial(it) }
            ui.note?.let { note ->
                Text(
                    text = note,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            ConfirmButtonMaterial(ui.confirmText, ui.confirmStyle, onConfirm)
        }
    }
}

@Composable
private fun OptionRowMaterial(
    option: WorkModeSheetOption,
    selected: Boolean,
    isCurrent: Boolean,
    onSelect: () -> Unit,
    onOpenIntro: () -> Unit,
) {
    val container by animateColorAsState(
        targetValue = if (selected) {
            MaterialTheme.colorScheme.secondaryContainer
        } else {
            MaterialTheme.colorScheme.surfaceContainerHigh
        },
        animationSpec = tween(SELECT_DURATION_MS),
        label = "workModeOptionContainer",
    )
    Surface(
        selected = selected,
        onClick = onSelect,
        enabled = option.enabled,
        shape = MaterialTheme.shapes.large,
        color = container,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 76.dp)
                .padding(start = 8.dp, end = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            RadioButton(selected = selected, onClick = null, enabled = option.enabled, modifier = Modifier.padding(8.dp))
            Spacer(Modifier.width(8.dp))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = stringResource(WorkModeStrings.modeNameRes(option.mode)),
                        modifier = Modifier.weight(1f, fill = false),
                        maxLines = 1,
                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                        style = MaterialTheme.typography.titleMedium,
                    )
                    if (isCurrent) {
                        Spacer(Modifier.width(8.dp))
                        TagMaterial(stringResource(R.string.work_mode_tag_current))
                    }
                    if (option.recommended) {
                        Spacer(Modifier.width(8.dp))
                        TagMaterial(stringResource(R.string.work_mode_tag_recommended))
                    }
                }
                Text(
                    text = stringResource(
                        if (option.enabled) WorkModeStrings.modeTaglineRes(option.mode) else R.string.migration_target_unavailable,
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            IconButton(onClick = onOpenIntro, modifier = Modifier.size(48.dp)) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                    contentDescription = stringResource(R.string.work_mode_intro_action),
                )
            }
        }
    }
}

@Composable
private fun TagMaterial(text: String) {
    Surface(
        shape = MaterialTheme.shapes.small,
        color = MaterialTheme.colorScheme.tertiaryContainer,
        contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 1.dp),
        )
    }
}

@Composable
private fun HintMaterial(hint: WorkModeSheetHint) {
    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(
            text = hint.text,
            style = MaterialTheme.typography.bodyMedium,
            color = if (hint.isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f),
        )
        val action = hint.onAction
        if (hint.actionText != null && action != null) {
            TextButton(onClick = action, contentPadding = PaddingValues(horizontal = 12.dp)) {
                Text(hint.actionText)
            }
        }
    }
}

@Composable
private fun ConfirmButtonMaterial(
    text: String,
    style: WorkModeSheetButtonStyle,
    onClick: () -> Unit,
) {
    Button(
        onClick = { if (style == WorkModeSheetButtonStyle.PRIMARY) onClick() },
        enabled = style != WorkModeSheetButtonStyle.DISABLED,
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 52.dp),
    ) {
        if (style == WorkModeSheetButtonStyle.LOADING) {
            CircularProgressIndicator(
                modifier = Modifier.size(18.dp),
                strokeWidth = 2.dp,
                color = LocalContentColor.current,
            )
            Spacer(Modifier.width(10.dp))
        }
        Text(text)
    }
}

/** 模式介绍小窗 · Material。 */
@Composable
internal fun WorkModeIntroDialogMaterial(mode: WorkMode?, onDismiss: () -> Unit) {
    if (mode == null) return
    BrandDialogMaterial(
        kind = brandBannerKind(mode),
        title = stringResource(
            R.string.work_mode_intro_title,
            stringResource(WorkModeStrings.modeNameRes(mode)),
            stringResource(WorkModeStrings.modeTaglineRes(mode)),
        ),
        lines = WorkModeStrings.modeIntroRes(mode),
        onDismiss = onDismiss,
    )
}

private const val SELECT_DURATION_MS = 200
