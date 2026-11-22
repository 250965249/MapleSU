package com.maplesu.core.ui.component.maple

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import com.maplesu.core.R
import com.maplesu.core.ui.component.material.ExpressiveDialog
import com.maplesu.core.ui.theme.materialDialogColor
import dev.maplesu.manager.workmode.ui.splitIntroLine

/** 「标签：内容」一行：标签加重，内容次要。 */
@Composable
internal fun BrandIntroLineMaterial(@StringRes res: Int) {
    val (label, body) = splitIntroLine(stringResource(res))
    Text(
        text = buildAnnotatedString {
            withStyle(SpanStyle(fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurface)) {
                append(label)
            }
            append(body)
        },
        style = MaterialTheme.typography.bodyMedium,
    )
}

/**
 * 带品牌 Banner 的只读小窗 · Material。
 *
 * Banner 放在 M3 的 `icon` 槽：它本来就在标题之上，有 `icon` 时 M3 会把标题居中，
 * 正好和 Miuix 的居中标题一致，不需要改库或量内边距。
 *
 * @param lines 「标签：内容」形式的字符串资源
 * @param footer 接在 [lines] 之后的内容
 */
@Composable
internal fun BrandDialogMaterial(
    kind: BrandBannerKind,
    title: String,
    lines: List<Int>,
    onDismiss: () -> Unit,
    footer: @Composable ColumnScope.() -> Unit = {},
) {
    ExpressiveDialog(
        onDismissRequest = onDismiss,
        containerColor = materialDialogColor(),
        icon = { BrandBanner(kind = kind, accent = MaterialTheme.colorScheme.primary, soft = false) },
        title = { Text(title) },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                lines.forEach { BrandIntroLineMaterial(it) }
                footer()
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.work_mode_intro_ok)) }
        },
    )
}
