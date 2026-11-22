package dev.maplesu.manager.workmode.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.rounded.SwapHoriz
import androidx.compose.material.icons.rounded.UnfoldMore
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.node.Ref
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.maplesu.core.R
import com.maplesu.core.ui.component.maple.BrandDialogMiuix
import com.maplesu.core.ui.component.maple.brandBannerKind
import com.maplesu.core.ui.theme.miuixDialogColor
import dev.maplesu.manager.workmode.WorkMode
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.InfiniteProgressIndicator
import top.yukonga.miuix.kmp.basic.RadioButton
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.overlay.OverlayBottomSheet
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.PressFeedbackType

/** 入口行 · Miuix：整张卡片可按，按下有下沉反馈。 */
@Composable
internal fun WorkModeTargetRowMiuix(
    value: String,
    enabled: Boolean,
    onClick: () -> Unit,
    modifier: Modifier,
    title: String,
) {
    val contentAlpha = if (enabled) 1f else DISABLED_ALPHA
    Card(
        modifier = modifier.fillMaxWidth(),
        insideMargin = PaddingValues(horizontal = 16.dp, vertical = 0.dp),
        showIndication = enabled,
        pressFeedbackType = if (enabled) PressFeedbackType.Sink else PressFeedbackType.None,
        onClick = { if (enabled) onClick() },
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = TARGET_ROW_HEIGHT),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = Icons.Rounded.SwapHoriz,
                contentDescription = null,
                tint = colorScheme.primary.copy(alpha = contentAlpha),
                modifier = Modifier.size(26.dp),
            )
            Spacer(Modifier.width(14.dp))
            Text(
                text = title,
                fontSize = 17.sp,
                fontWeight = FontWeight.Medium,
                color = colorScheme.onSurface.copy(alpha = contentAlpha),
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.width(8.dp))
            Text(
                text = value,
                fontSize = 14.sp,
                color = colorScheme.onSurfaceVariantSummary.copy(alpha = contentAlpha),
                maxLines = 1,
            )
            Spacer(Modifier.width(4.dp))
            Icon(
                imageVector = Icons.Rounded.UnfoldMore,
                contentDescription = null,
                tint = colorScheme.onSurfaceVariantSummary.copy(alpha = contentAlpha),
                modifier = Modifier.size(20.dp),
            )
        }
    }
}

/** 选择框 · Miuix：圆角模糊、弹性进入，选中态用弹簧过渡。 */
@Composable
internal fun WorkModeSheetMiuix(
    show: Boolean,
    ui: WorkModeSheetUi,
    onSelect: (WorkMode) -> Unit,
    onOpenIntro: (WorkMode) -> Unit,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    OverlayBottomSheet(
        show = show,
        title = ui.title,
        backgroundColor = miuixDialogColor(),
        allowDismiss = ui.dismissible,
        onDismissRequest = { if (ui.dismissible) onDismiss() },
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            ui.options.forEach { option ->
                OptionRowMiuix(
                    option = option,
                    selected = ui.selected == option.mode,
                    isCurrent = ui.current == option.mode,
                    onSelect = { onSelect(option.mode) },
                    onOpenIntro = { onOpenIntro(option.mode) },
                )
            }
            ui.hint?.let { HintMiuix(it) }
            ui.note?.let { note ->
                Text(
                    text = note,
                    fontSize = 12.sp,
                    color = colorScheme.onSurfaceVariantSummary,
                    modifier = Modifier.padding(horizontal = 4.dp),
                )
            }
            ConfirmButtonMiuix(ui.confirmText, ui.confirmStyle, onConfirm)
        }
    }
}

@Composable
private fun OptionRowMiuix(
    option: WorkModeSheetOption,
    selected: Boolean,
    isCurrent: Boolean,
    onSelect: () -> Unit,
    onOpenIntro: () -> Unit,
) {
    val container by animateColorAsState(
        targetValue = if (selected) colorScheme.primary.copy(alpha = 0.14f) else colorScheme.surfaceContainer,
        animationSpec = spring(stiffness = Spring.StiffnessMediumLow),
        label = "workModeOptionContainer",
    )
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.defaultColors(color = container),
        insideMargin = PaddingValues(start = 16.dp, end = 4.dp),
        showIndication = option.enabled,
        pressFeedbackType = if (option.enabled) PressFeedbackType.Sink else PressFeedbackType.None,
        onClick = { if (option.enabled) onSelect() },
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 76.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            RadioButton(selected = selected, onClick = null, enabled = option.enabled)
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = stringResource(WorkModeStrings.modeNameRes(option.mode)),
                        modifier = Modifier.weight(1f, fill = false),
                        maxLines = 1,
                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Medium,
                        color = if (option.enabled) colorScheme.onSurface else colorScheme.onSurfaceVariantSummary,
                    )
                    if (isCurrent) {
                        Spacer(Modifier.width(8.dp))
                        TagMiuix(stringResource(R.string.work_mode_tag_current))
                    }
                    if (option.recommended) {
                        Spacer(Modifier.width(8.dp))
                        TagMiuix(stringResource(R.string.work_mode_tag_recommended))
                    }
                }
                Text(
                    text = stringResource(
                        if (option.enabled) WorkModeStrings.modeTaglineRes(option.mode) else R.string.migration_target_unavailable,
                    ),
                    fontSize = 13.sp,
                    color = colorScheme.onSurfaceVariantSummary,
                    modifier = Modifier.padding(top = 2.dp),
                )
            }
            IconButton(onClick = onOpenIntro, modifier = Modifier.size(INTRO_BUTTON_SIZE)) {
                Icon(
                    imageVector = Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                    contentDescription = stringResource(R.string.work_mode_intro_action),
                    tint = colorScheme.onSurfaceVariantSummary,
                )
            }
        }
    }
}

@Composable
private fun TagMiuix(text: String) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(colorScheme.primary.copy(alpha = 0.16f))
            .padding(horizontal = 6.dp, vertical = 1.dp),
    ) {
        Text(text = text, fontSize = 11.sp, color = colorScheme.primary)
    }
}

@Composable
private fun HintMiuix(hint: WorkModeSheetHint) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = hint.text,
            fontSize = 13.sp,
            color = if (hint.isError) colorScheme.error else colorScheme.onSurfaceVariantSummary,
            modifier = Modifier.weight(1f),
        )
        val action = hint.onAction
        if (hint.actionText != null && action != null) {
            Spacer(Modifier.width(8.dp))
            TextButton(
                text = hint.actionText,
                onClick = action,
                colors = ButtonDefaults.textButtonColorsPrimary(),
                minHeight = 36.dp,
                insideMargin = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
            )
        }
    }
}

@Composable
private fun ConfirmButtonMiuix(
    text: String,
    style: WorkModeSheetButtonStyle,
    onClick: () -> Unit,
) {
    val active = style != WorkModeSheetButtonStyle.DISABLED
    val spec = spring<Color>(stiffness = Spring.StiffnessMedium)
    val container by animateColorAsState(
        targetValue = if (active) colorScheme.primary else colorScheme.secondaryContainer,
        animationSpec = spec,
        label = "workModeConfirmContainer",
    )
    val content by animateColorAsState(
        targetValue = if (active) colorScheme.onPrimary else colorScheme.onSurfaceVariantSummary,
        animationSpec = spec,
        label = "workModeConfirmContent",
    )
    Button(
        onClick = { if (style == WorkModeSheetButtonStyle.PRIMARY) onClick() },
        enabled = active,
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 52.dp),
        colors = ButtonDefaults.buttonColors(color = container, disabledColor = container),
    ) {
        if (style == WorkModeSheetButtonStyle.LOADING) {
            InfiniteProgressIndicator(color = content, size = 18.dp)
            Spacer(Modifier.width(10.dp))
        }
        Text(text = text, fontSize = 16.sp, fontWeight = FontWeight.Medium, color = content)
    }
}

/** 模式介绍小窗 · Miuix。 */
@Composable
internal fun WorkModeIntroDialogMiuix(mode: WorkMode?, onDismiss: () -> Unit) {
    // 退场动画期间 mode 已是 null：留住上一个模式，内容才不会在小窗收起时塌掉。
    val held = remember { Ref<WorkMode>() }
    if (mode != null) held.value = mode
    val shown = held.value
    BrandDialogMiuix(
        show = mode != null,
        kind = shown?.let(::brandBannerKind),
        title = shown?.let {
            stringResource(
                R.string.work_mode_intro_title,
                stringResource(WorkModeStrings.modeNameRes(it)),
                stringResource(WorkModeStrings.modeTaglineRes(it)),
            )
        }.orEmpty(),
        lines = shown?.let { WorkModeStrings.modeIntroRes(it) }.orEmpty(),
        onDismiss = onDismiss,
    )
}

private const val DISABLED_ALPHA = 0.45f
private val TARGET_ROW_HEIGHT = 76.dp
private val INTRO_BUTTON_SIZE = 48.dp
