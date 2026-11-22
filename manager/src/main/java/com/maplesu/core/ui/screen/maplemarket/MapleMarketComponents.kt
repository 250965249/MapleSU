package com.maplesu.core.ui.screen.maplemarket

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.material.ExpressiveDialog
import com.maplesu.core.ui.component.material.ExpressiveScaffold
import com.maplesu.core.ui.theme.materialDialogColor
import com.maplesu.core.ui.theme.miuixDialogColor
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
internal fun MarketPage(
    title: String,
    onBack: () -> Unit,
    onRefresh: (() -> Unit)?,
    onSource: () -> Unit,
    content: @Composable (PaddingValues) -> Unit,
) {
    val back = @Composable { MarketIconButton(Icons.AutoMirrored.Rounded.ArrowBack, stringResource(R.string.work_mode_back), onBack) }
    val actions: @Composable RowScope.() -> Unit = {
        if (onRefresh != null) MarketIconButton(Icons.Outlined.Refresh, stringResource(R.string.maple_market_refresh), onRefresh)
        MarketIconButton(Icons.Outlined.Settings, stringResource(R.string.maple_market_source), onSource)
    }
    when (LocalUiMode.current) {
        UiMode.Miuix -> top.yukonga.miuix.kmp.basic.Scaffold(
            topBar = {
                top.yukonga.miuix.kmp.basic.SmallTopAppBar(
                    title = title,
                    color = MiuixTheme.colorScheme.surface,
                    navigationIcon = back,
                    actions = actions,
                )
            },
            popupHost = {},
            contentWindowInsets = WindowInsets.systemBars.only(WindowInsetsSides.Horizontal + WindowInsetsSides.Bottom),
            content = content,
        )
        UiMode.Material -> ExpressiveScaffold(
            topBar = {
                androidx.compose.material3.TopAppBar(
                    title = { androidx.compose.material3.Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    navigationIcon = back,
                    actions = actions,
                )
            },
            contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal + WindowInsetsSides.Bottom),
            content = content,
        )
    }
}

@Composable
internal fun MarketIconButton(icon: ImageVector, description: String, onClick: () -> Unit) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> top.yukonga.miuix.kmp.basic.IconButton(onClick = onClick) {
            top.yukonga.miuix.kmp.basic.Icon(icon, description, tint = MiuixTheme.colorScheme.onSurface)
        }
        UiMode.Material -> androidx.compose.material3.IconButton(onClick = onClick) {
            androidx.compose.material3.Icon(icon, description)
        }
    }
}

@Composable
internal fun MarketCard(
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> top.yukonga.miuix.kmp.basic.Card(
            modifier = modifier.fillMaxWidth(),
            insideMargin = PaddingValues(18.dp),
            showIndication = onClick != null,
            onClick = onClick ?: {},
        ) { Column(verticalArrangement = Arrangement.spacedBy(8.dp), content = content) }
        UiMode.Material -> androidx.compose.material3.Card(
            modifier = modifier.fillMaxWidth().then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier),
            shape = MaterialTheme.shapes.large,
        ) { Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(8.dp), content = content) }
    }
}

@Composable
internal fun MarketText(
    text: String,
    modifier: Modifier = Modifier,
    secondary: Boolean = false,
    size: TextUnit = 14.sp,
    weight: FontWeight? = null,
    maxLines: Int = Int.MAX_VALUE,
) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> top.yukonga.miuix.kmp.basic.Text(
            text = text, modifier = modifier, fontSize = size, fontWeight = weight,
            color = if (secondary) MiuixTheme.colorScheme.onSurfaceVariantSummary else MiuixTheme.colorScheme.onSurface,
            maxLines = maxLines, overflow = TextOverflow.Ellipsis,
        )
        UiMode.Material -> androidx.compose.material3.Text(
            text = text, modifier = modifier, fontSize = size, fontWeight = weight,
            color = if (secondary) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurface,
            maxLines = maxLines, overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
internal fun MarketButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true, primary: Boolean = false) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> top.yukonga.miuix.kmp.basic.TextButton(
            text = text, onClick = onClick, enabled = enabled, modifier = modifier,
            colors = if (primary) top.yukonga.miuix.kmp.basic.ButtonDefaults.textButtonColorsPrimary()
                else top.yukonga.miuix.kmp.basic.ButtonDefaults.textButtonColors(),
        )
        UiMode.Material -> if (primary) androidx.compose.material3.Button(onClick, modifier, enabled) {
            androidx.compose.material3.Text(text)
        } else androidx.compose.material3.TextButton(onClick, modifier, enabled) { androidx.compose.material3.Text(text) }
    }
}

@Composable
internal fun MarketField(value: String, onValueChange: (String) -> Unit, label: String, singleLine: Boolean = false) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> top.yukonga.miuix.kmp.basic.TextField(
            value = value, onValueChange = onValueChange, label = label,
            modifier = Modifier.fillMaxWidth(), singleLine = singleLine,
        )
        UiMode.Material -> androidx.compose.material3.OutlinedTextField(
            value = value, onValueChange = onValueChange, label = { androidx.compose.material3.Text(label) },
            modifier = Modifier.fillMaxWidth(), singleLine = singleLine, maxLines = if (singleLine) 1 else 5,
        )
    }
}

@Composable
internal fun MarketLoading(progress: Float? = null) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> if (progress == null) top.yukonga.miuix.kmp.basic.InfiniteProgressIndicator(size = 24.dp)
            else top.yukonga.miuix.kmp.basic.CircularProgressIndicator(progress = progress, size = 24.dp, strokeWidth = 2.dp)
        UiMode.Material -> if (progress == null) androidx.compose.material3.CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
            else androidx.compose.material3.CircularProgressIndicator(progress = { progress }, modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
    }
}

@Composable
internal fun MarketDialog(title: String, onDismiss: () -> Unit, content: @Composable ColumnScope.() -> Unit) {
    val bodyHeight = (LocalConfiguration.current.screenHeightDp * 0.65f).dp
    val body: @Composable () -> Unit = {
        Column(Modifier.fillMaxWidth().heightIn(max = bodyHeight).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp), content = content)
    }
    when (LocalUiMode.current) {
        UiMode.Miuix -> top.yukonga.miuix.kmp.window.WindowDialog(
            show = true, title = title, backgroundColor = miuixDialogColor(), onDismissRequest = onDismiss,
            content = body,
        )
        UiMode.Material -> ExpressiveDialog(
            onDismissRequest = onDismiss, containerColor = materialDialogColor(),
            title = { androidx.compose.material3.Text(title) },
            text = body,
            confirmButton = {},
        )
    }
}
