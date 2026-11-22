package com.maplesu.core.ui.component

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Constraints
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.DialogProperties
import androidx.navigationevent.NavigationEventInfo
import androidx.navigationevent.compose.NavigationBackHandler
import androidx.navigationevent.compose.rememberNavigationEventState
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.maple.BrandBanner
import com.maplesu.core.ui.component.maple.BrandBannerKind
import com.maplesu.core.ui.component.material.ExpressiveDialog
import com.maplesu.core.ui.theme.materialDialogColor
import com.maplesu.core.ui.theme.miuixDialogColor
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.window.WindowDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.basic.TextButton as MiuixTextButton

/** State-driven remote notice. The caller owns visibility and acknowledgement persistence. */
@Composable
fun T3NoticeDialog(
    title: String,
    content: String,
    publishedAt: String? = null,
    onDismiss: () -> Unit,
) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> WindowDialog(
            show = true,
            largeScreen = true,
            backgroundColor = miuixDialogColor(),
            onDismissRequest = onDismiss,
        ) {
            // Reserve the action first, as BrandDialogMiuix does, so long notices stay readable.
            Layout(content = {
                Column(verticalArrangement = Arrangement.spacedBy(20.dp)) {
                    T3DialogHeader(title, publishedAt)
                    T3DialogBody(
                        text = content,
                        modifier = Modifier.weight(1f, fill = false)
                            .verticalScroll(rememberScrollState()).testTag("t3NoticeContent"),
                    )
                }
                MiuixTextButton(
                    text = stringResource(android.R.string.ok),
                    onClick = onDismiss,
                    colors = ButtonDefaults.textButtonColorsPrimary(),
                    modifier = Modifier.fillMaxWidth().padding(top = 20.dp).testTag("t3NoticeConfirm"),
                )
            }) { measurables, constraints ->
                val action = measurables[1].measure(constraints.copy(minHeight = 0))
                val availableHeight = if (constraints.hasBoundedHeight) {
                    (constraints.maxHeight - action.height).coerceAtLeast(0)
                } else {
                    Constraints.Infinity
                }
                val body = measurables[0].measure(constraints.copy(minHeight = 0, maxHeight = availableHeight))
                layout(constraints.maxWidth, body.height + action.height) {
                    body.place(0, 0)
                    action.place(0, body.height)
                }
            }
        }
        UiMode.Material -> ExpressiveDialog(
            onDismissRequest = onDismiss,
            containerColor = materialDialogColor(),
            title = { T3DialogHeader(title, publishedAt) },
            text = {
                T3DialogBody(
                    text = content,
                    modifier = Modifier.verticalScroll(rememberScrollState()).testTag("t3NoticeContent"),
                )
            },
            confirmButton = {
                TextButton(onClick = onDismiss, modifier = Modifier.testTag("t3NoticeConfirm")) {
                    Text(stringResource(android.R.string.ok))
                }
            },
        )
    }
}

/** The caller supplies the countdown and performs the eventual exit; this UI never starts a timer. */
@Composable
fun T3DisabledDialog(secondsRemaining: Int) {
    val seconds = secondsRemaining.coerceAtLeast(0)
    val message = "当前版本已被禁用，将在 ${seconds}s 内退出"
    when (LocalUiMode.current) {
        UiMode.Miuix -> WindowDialog(
            show = true,
            largeScreen = true,
            backgroundColor = miuixDialogColor(),
            onDismissRequest = {},
        ) {
            // Consume predictive back before the overlay's own dismiss animation.
            NavigationBackHandler(
                state = rememberNavigationEventState(NavigationEventInfo.None),
                isBackEnabled = true,
                onBackCompleted = {},
            )
            Column(verticalArrangement = Arrangement.spacedBy(20.dp)) {
                T3DialogHeader(title = "版本已禁用", secondsRemaining = seconds)
                T3DialogBody(
                    text = message,
                    centered = true,
                    modifier = Modifier.testTag("t3DisabledMessage")
                        .semantics { liveRegion = LiveRegionMode.Polite },
                )
            }
        }
        UiMode.Material -> ExpressiveDialog(
            onDismissRequest = {},
            properties = DialogProperties(dismissOnBackPress = false, dismissOnClickOutside = false),
            containerColor = materialDialogColor(),
            title = { T3DialogHeader(title = "版本已禁用", secondsRemaining = seconds) },
            text = {
                T3DialogBody(
                    text = message,
                    centered = true,
                    modifier = Modifier.testTag("t3DisabledMessage")
                        .semantics { liveRegion = LiveRegionMode.Polite },
                )
            },
            confirmButton = {},
        )
    }
}

@Composable
private fun T3DialogHeader(title: String, publishedAt: String? = null, secondsRemaining: Int? = null) {
    val miuix = LocalUiMode.current == UiMode.Miuix
    val accent = if (miuix) MiuixTheme.colorScheme.primary else MaterialTheme.colorScheme.primary
    val foreground = if (miuix) MiuixTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurface
    val secondary = if (miuix) MiuixTheme.colorScheme.onSurfaceVariantSummary
        else MaterialTheme.colorScheme.onSurfaceVariant
    val titleStyle = if (miuix) MiuixTheme.textStyles.title4 else MaterialTheme.typography.headlineSmall
    val captionStyle = if (miuix) MiuixTheme.textStyles.body2 else MaterialTheme.typography.labelMedium
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (secondsRemaining == null) {
            // Share About MapleSU's artwork, theme treatment and compact-window sizing.
            BrandBanner(
                kind = BrandBannerKind.MAPLE,
                accent = accent,
                soft = miuix,
                modifier = Modifier.testTag("t3NoticeBanner"),
            )
        } else {
            Box(
                modifier = Modifier.size(64.dp).background(accent.copy(alpha = 0.1f), CircleShape)
                    .clearAndSetSemantics {},
                contentAlignment = Alignment.Center,
            ) {
                Canvas(Modifier.size(64.dp).padding(2.dp)) {
                    drawArc(
                        color = accent,
                        startAngle = -90f,
                        sweepAngle = 360f * secondsRemaining.coerceIn(0, 3) / 3f,
                        useCenter = false,
                        style = Stroke(width = 3.dp.toPx(), cap = StrokeCap.Round),
                    )
                }
                BasicText(
                    text = secondsRemaining.toString(),
                    style = titleStyle.copy(color = accent, fontSize = 28.sp, fontWeight = FontWeight.SemiBold),
                )
            }
        }
        BasicText(
            text = title,
            style = titleStyle.copy(color = foreground, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center),
            modifier = Modifier.fillMaxWidth().semantics { heading() },
        )
        if (!publishedAt.isNullOrBlank()) {
            BasicText(
                text = publishedAt,
                style = captionStyle.copy(color = secondary, fontSize = 12.sp, textAlign = TextAlign.Center),
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun T3DialogBody(text: String, modifier: Modifier = Modifier, centered: Boolean = false) {
    val miuix = LocalUiMode.current == UiMode.Miuix
    val color = if (miuix) MiuixTheme.colorScheme.onSurfaceVariantSummary
        else MaterialTheme.colorScheme.onSurfaceVariant
    val style = if (miuix) MiuixTheme.textStyles.body1 else MaterialTheme.typography.bodyLarge
    BasicText(
        text = text,
        style = style.copy(color = color, fontSize = 15.sp, lineHeight = 24.sp,
            textAlign = if (centered) TextAlign.Center else TextAlign.Start),
        modifier = modifier.fillMaxWidth(),
    )
}
