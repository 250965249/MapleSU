package com.maplesu.core.ui.component.maple

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.Constraints
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.maplesu.core.R
import com.maplesu.core.ui.theme.miuixDialogColor
import dev.maplesu.manager.workmode.ui.splitIntroLine
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.layout.DialogDefaults
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme

/** 「标签：内容」一行：标签加重，内容次要。 */
@Composable
internal fun BrandIntroLineMiuix(@StringRes res: Int) {
    val (label, body) = splitIntroLine(stringResource(res))
    Text(
        text = buildAnnotatedString {
            withStyle(SpanStyle(fontWeight = FontWeight.Medium, color = colorScheme.onSurface)) { append(label) }
            append(body)
        },
        fontSize = 14.sp,
        color = colorScheme.onSurfaceVariantSummary,
    )
}

/**
 * 带品牌 Banner 的只读小窗 · Miuix。
 *
 * miuix 的标题固定在内容之上，Banner 又要压在最上面，所以这里不传 `title`、自己画同款标题
 * （样式对齐 miuix 0.9.4 `DialogContentLayout`：title4 / Medium / 居中）。
 *
 * 布局沿用 [com.maplesu.core.ui.component.dialog.InfoDialogMiuix] 的做法：正文和按钮分开测量，
 * 正文超长时自己滚动，不会把按钮挤出屏幕。
 *
 * @param kind 为 null 时不画 Banner（小窗退场、内容已清空时）
 * @param lines 「标签：内容」形式的字符串资源
 * @param footer 接在 [lines] 之后的内容
 */
@Composable
internal fun BrandDialogMiuix(
    show: Boolean,
    kind: BrandBannerKind?,
    title: String,
    lines: List<Int>,
    onDismiss: () -> Unit,
    footer: @Composable ColumnScope.() -> Unit = {},
) {
    OverlayDialog(
        show = show,
        backgroundColor = miuixDialogColor(),
        onDismissRequest = onDismiss,
    ) {
        Layout(
            content = {
                Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                    if (kind != null) {
                        BrandBanner(
                            kind = kind,
                            accent = colorScheme.primary,
                            soft = true,
                            modifier = Modifier.padding(bottom = 6.dp),
                        )
                    }
                    Text(
                        text = title,
                        fontSize = MiuixTheme.textStyles.title4.fontSize,
                        fontWeight = FontWeight.Medium,
                        textAlign = TextAlign.Center,
                        color = DialogDefaults.titleColor(),
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 14.dp),
                    )
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        lines.forEach { BrandIntroLineMiuix(it) }
                        footer()
                    }
                }
                TextButton(
                    text = stringResource(R.string.work_mode_intro_ok),
                    onClick = onDismiss,
                    colors = ButtonDefaults.textButtonColorsPrimary(),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 18.dp),
                )
            },
        ) { measurables, constraints ->
            val button = measurables[1].measure(constraints.copy(minHeight = 0))
            val bodyMax = if (constraints.hasBoundedHeight) {
                (constraints.maxHeight - button.height).coerceAtLeast(0)
            } else {
                Constraints.Infinity
            }
            val body = measurables[0].measure(constraints.copy(minHeight = 0, maxHeight = bodyMax))
            layout(constraints.maxWidth, body.height + button.height) {
                body.place(0, 0)
                button.place(0, body.height)
            }
        }
    }
}
