package dev.maplesu.manager.workmode.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material3.Icon as MaterialIcon
import androidx.compose.material3.Text
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.material.SegmentedListItem
import top.yukonga.miuix.kmp.basic.Icon as MiuixIcon
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme

/**
 * 设置页的「隐藏」**单项入口**（不是内嵌卡片）。
 *
 * 仅在 LITE 且未隐藏时可见；点进入独立隐藏设置页（[LiteHiddenScreen]）。
 * 隐藏开启后该行与隐藏页整体消失（与 `Stealth.looksStealthy()` 的 root 入口隐藏同一套判定）。
 */
@Immutable
data class LiteHiddenCardUi(
    val visible: Boolean = false,
    val hidden: Boolean = false,
    /** 三态事实（状态行文案来源）：UNKNOWN 不得渲染成"已开启"。 */
    val status: LiteHiddenStatus = LiteHiddenStatus.OFF,
) {
    /** 是否显示入口行：调用方用它决定把行放进哪张卡片，避免留下空卡片。 */
    val showsRow: Boolean get() = visible && !hidden

    companion object {
        val HIDDEN = LiteHiddenCardUi(visible = false)
    }
}

/** 隐藏入口行（只有行本身，容器由设置页决定，和工作模式放在同一张卡片里）。 */
@Composable
fun LiteHiddenEntry(
    ui: LiteHiddenCardUi,
    onClick: () -> Unit,
) {
    if (!ui.showsRow) return
    // 状态行只陈述事实：ON→已开启；OFF→未开启；UNKNOWN→状态未知（读取失败）。
    val statusText = stringResource(LiteHiddenStatusPolicy.statusRes(ui.status))
    val title = stringResource(R.string.lite_hidden_title)
    when (LocalUiMode.current) {
        UiMode.Miuix -> ArrowPreference(
            title = title,
            summary = statusText,
            startAction = {
                MiuixIcon(
                    Icons.Rounded.VisibilityOff,
                    contentDescription = title,
                    modifier = Modifier.padding(end = 6.dp),
                    tint = colorScheme.onBackground,
                )
            },
            onClick = onClick,
        )

        UiMode.Material -> SegmentedListItem(
            onClick = onClick,
            headlineContent = { Text(title) },
            supportingContent = { Text(statusText) },
            leadingContent = { MaterialIcon(Icons.Rounded.VisibilityOff, contentDescription = title) },
            trailingContent = {
                MaterialIcon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null)
            },
        )
    }
}

/**
 * 「WebUI 自检」入口行（A/B 都显示，隐藏生效后整体消失）。
 *
 * 目前它是开启隐藏前取得可用 WebUI 链接的唯一途径（`preparePreviewUrl` + 启动 daemon），
 * 所以副标题写这一点，而不是重复标题。
 */
@Composable
fun WebUiSelfCheckEntry(onClick: () -> Unit) {
    val title = stringResource(R.string.webui_selfcheck_title)
    val summary = stringResource(R.string.ui_d_selfcheck_entry_summary)
    when (LocalUiMode.current) {
        UiMode.Miuix -> ArrowPreference(
            title = title,
            summary = summary,
            startAction = {
                MiuixIcon(
                    Icons.Rounded.Language,
                    contentDescription = title,
                    modifier = Modifier.padding(end = 6.dp),
                    tint = colorScheme.onBackground,
                )
            },
            onClick = onClick,
        )

        UiMode.Material -> SegmentedListItem(
            onClick = onClick,
            headlineContent = { Text(title) },
            supportingContent = { Text(summary) },
            leadingContent = { MaterialIcon(Icons.Rounded.Language, contentDescription = title) },
            trailingContent = {
                MaterialIcon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null)
            },
        )
    }
}
