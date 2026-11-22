package com.maplesu.core.ui.screen.settings

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.selection.selectable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.ChevronRight
import androidx.compose.material.icons.rounded.FileOpen
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.res.stringResource
import com.maplesu.core.R
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.unit.dp
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.material.ExpressiveScaffold
import com.maplesu.core.ui.component.material.SegmentedListItem
import com.maplesu.core.ui.component.material.SegmentedSwitchItem
import com.maplesu.core.ui.component.material.expressiveTopAppBarColors
import com.maplesu.core.ui.theme.materialDialogColor
import com.maplesu.core.ui.theme.miuixDialogColor

/** Theme-only native presentation helpers; state and actions live outside the skin branches. */
internal val LocalThemeBusy = staticCompositionLocalOf { false }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun ThemePage(title: String, onBack: () -> Unit, actions: @Composable RowScope.() -> Unit = {},
    floatingActionButton: @Composable () -> Unit = {}, content: @Composable (PaddingValues) -> Unit) {
    val pageContent = com.maplesu.core.ui.theme.rememberSkinContentWithParameter(content)
    when (LocalUiMode.current) {
        UiMode.Miuix -> top.yukonga.miuix.kmp.basic.Scaffold(topBar = {
            top.yukonga.miuix.kmp.basic.TopAppBar(title = title, navigationIcon = {
                top.yukonga.miuix.kmp.basic.IconButton(onClick = onBack) {
                    top.yukonga.miuix.kmp.basic.Icon(Icons.AutoMirrored.Rounded.ArrowBack, stringResource(R.string.theme_back))
                }
            }, actions = actions, color = com.maplesu.core.ui.util.miuixBarColor(blurActive = false))
        }, floatingActionButton = floatingActionButton, popupHost = {}, contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal), content = pageContent)
        UiMode.Material -> ExpressiveScaffold(topBar = {
            androidx.compose.material3.LargeFlexibleTopAppBar(title = { androidx.compose.material3.Text(title) },
                navigationIcon = { androidx.compose.material3.IconButton(onClick = onBack) { androidx.compose.material3.Icon(Icons.AutoMirrored.Rounded.ArrowBack, stringResource(R.string.theme_back)) } },
                actions = actions, colors = expressiveTopAppBarColors())
        }, floatingActionButton = floatingActionButton, contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal), content = pageContent)
    }
}

@Composable
internal fun ThemeImportFab(onClick: () -> Unit) {
    val label = stringResource(R.string.theme_import_file)
    val enabled = !LocalThemeBusy.current
    when (LocalUiMode.current) {
        UiMode.Miuix -> top.yukonga.miuix.kmp.basic.FloatingActionButton(
            onClick = { if (enabled) onClick() }, shadowElevation = 0.dp,
            modifier = Modifier.padding(end=20.dp,bottom=20.dp).navigationBarsPadding()) {
            top.yukonga.miuix.kmp.basic.Icon(Icons.Rounded.FileOpen,label,
                tint=top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme.onPrimary)
        }
        UiMode.Material -> androidx.compose.material3.ExtendedFloatingActionButton(
            onClick = { if (enabled) onClick() }, modifier=Modifier.navigationBarsPadding(),
            icon={ androidx.compose.material3.Icon(Icons.Rounded.FileOpen,label) },
            text={ androidx.compose.material3.Text(label) })
    }
}

@Composable
internal fun ThemeText(text: String, modifier: Modifier = Modifier, secondary: Boolean = false) {
    val photoContent = com.maplesu.core.theme.LocalThemePhotoContent.current?.let { if (secondary) it.copy(alpha=.8f) else it }
    when (LocalUiMode.current) {
        UiMode.Miuix -> top.yukonga.miuix.kmp.basic.Text(text, modifier, color = photoContent ?: if (secondary)
            top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme.onSurfaceVariantSummary else top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme.onSurface)
        UiMode.Material -> androidx.compose.material3.Text(text, modifier, color = photoContent ?: if (secondary)
            androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant else androidx.compose.material3.MaterialTheme.colorScheme.onSurface)
    }
}

@Composable
internal fun ThemeButton(text: String, enabled: Boolean = true, onClick: () -> Unit) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> top.yukonga.miuix.kmp.basic.TextButton(text = text, enabled = enabled && !LocalThemeBusy.current, onClick = onClick)
        UiMode.Material -> androidx.compose.material3.TextButton(enabled = enabled && !LocalThemeBusy.current, onClick = onClick) { androidx.compose.material3.Text(text) }
    }
}

@Composable
internal fun ThemeChoice(label: String, selected: Boolean, onClick: () -> Unit) {
    val enabled = !LocalThemeBusy.current
    when (LocalUiMode.current) {
        UiMode.Miuix -> Row(Modifier.fillMaxWidth().selectable(selected,enabled=enabled,
            role=Role.RadioButton,onClick=onClick).padding(horizontal=16.dp,vertical=12.dp),
            verticalAlignment=androidx.compose.ui.Alignment.CenterVertically,
            horizontalArrangement=Arrangement.spacedBy(14.dp)) {
            top.yukonga.miuix.kmp.basic.RadioButton(selected=selected,onClick=null,enabled=enabled)
            top.yukonga.miuix.kmp.basic.Text(label)
        }
        UiMode.Material -> com.maplesu.core.ui.component.material.SegmentedRadioItem(
            title=label,selected=selected,enabled=enabled,onClick=onClick)
    }
}

@Composable
internal fun ThemeCard(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    val style = com.maplesu.core.theme.LocalThemeWallpaperStyle.current
    when (LocalUiMode.current) {
        UiMode.Miuix -> top.yukonga.miuix.kmp.basic.Card(modifier, content = content)
        UiMode.Material -> androidx.compose.material3.Card(modifier, colors=androidx.compose.material3.CardDefaults.cardColors(
            containerColor=style?.let { androidx.compose.material3.MaterialTheme.colorScheme.surface.copy(alpha=it.group) }
                ?: androidx.compose.material3.MaterialTheme.colorScheme.surfaceContainerLow),content = content)
    }
}

@Composable
internal fun ThemeProgress(progress: Float? = null) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> if (progress == null) top.yukonga.miuix.kmp.basic.InfiniteProgressIndicator(size = 24.dp)
            else top.yukonga.miuix.kmp.basic.CircularProgressIndicator(progress = progress.coerceIn(0f,1f), size = 24.dp, strokeWidth = 2.dp)
        UiMode.Material -> if (progress == null) androidx.compose.material3.CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
            else androidx.compose.material3.CircularProgressIndicator(progress = { progress.coerceIn(0f,1f) }, modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
    }
}

@Composable
internal fun ThemeRow(title: String, summary: String = "", icon: ImageVector? = null, enabled: Boolean = true, onClick: () -> Unit) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> top.yukonga.miuix.kmp.preference.ArrowPreference(title = title, summary = summary.ifBlank { null }, enabled = enabled && !LocalThemeBusy.current,
            startAction = { icon?.let { top.yukonga.miuix.kmp.basic.Icon(it, null, Modifier.padding(end = 6.dp)) } }, onClick = onClick)
        UiMode.Material -> SegmentedListItem(onClick = onClick, enabled = enabled && !LocalThemeBusy.current,
            colors=themeSettingRowColors(),
            headlineContent = { androidx.compose.material3.Text(title) }, supportingContent = summary.takeIf { it.isNotBlank() }?.let { { androidx.compose.material3.Text(it) } },
            leadingContent = icon?.let { { androidx.compose.material3.Icon(it, null) } },
            trailingContent = { androidx.compose.material3.Icon(Icons.Rounded.ChevronRight, null) })
    }
}

@Composable
internal fun ThemeSwitch(title: String, checked: Boolean, enabled: Boolean = true, summary: String? = null, onChange: (Boolean) -> Unit) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> top.yukonga.miuix.kmp.preference.SwitchPreference(title = title, summary = summary, checked = checked, enabled = enabled && !LocalThemeBusy.current, onCheckedChange = onChange)
        UiMode.Material -> SegmentedSwitchItem(title = title, summary = summary, colors=themeSettingRowColors(),checked = checked, enabled = enabled && !LocalThemeBusy.current, onCheckedChange = onChange)
    }
}

@Composable
internal fun ThemeDropdown(title: String, items: List<String>, selected: Int, onChange: (Int) -> Unit) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> top.yukonga.miuix.kmp.preference.OverlayDropdownPreference(title=title,items=items,
            selectedIndex=selected,enabled=!LocalThemeBusy.current,onSelectedIndexChange=onChange)
        UiMode.Material -> com.maplesu.core.ui.component.material.SegmentedDropdownItem(title=title,items=items,
            selectedIndex=selected,enabled=!LocalThemeBusy.current,onItemSelected=onChange)
    }
}

@Composable
private fun themeSettingRowColors(): androidx.compose.material3.ListItemColors {
    val colors = androidx.compose.material3.MaterialTheme.colorScheme
    val alpha = if (com.maplesu.core.theme.LocalThemeWallpaperStyle.current != null) 0f else colors.surfaceBright.alpha
    return androidx.compose.material3.ListItemDefaults.segmentedColors(
        containerColor=colors.surfaceBright.copy(alpha=alpha),disabledContainerColor=colors.surfaceBright.copy(alpha=alpha),
        supportingContentColor=colors.onSurfaceVariant)
}

@Composable
internal fun ThemeInput(label: String, value: String, onChange: (String) -> Unit) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> top.yukonga.miuix.kmp.basic.TextField(value = value, onValueChange = onChange, enabled = !LocalThemeBusy.current, label = label, modifier = Modifier.fillMaxWidth())
        UiMode.Material -> androidx.compose.material3.OutlinedTextField(value = value, onValueChange = onChange,
            enabled = !LocalThemeBusy.current,label = { androidx.compose.material3.Text(label) }, modifier = Modifier.fillMaxWidth())
    }
}

@Composable
internal fun ThemeSlider(title: String, value: Float, range: ClosedFloatingPointRange<Float> = 0f..1f, enabled: Boolean = true, onChange: (Float) -> Unit) {
    var current by remember(value, range) { mutableFloatStateOf(value.coerceIn(range.start, range.endInclusive)) }
    Column(Modifier.padding(16.dp)) {
        ThemeText("$title · ${"%.2f".format(current)}")
        when (LocalUiMode.current) {
            UiMode.Miuix -> top.yukonga.miuix.kmp.basic.Slider(value = current, onValueChange = { current = it }, enabled = enabled && !LocalThemeBusy.current, valueRange = range, onValueChangeFinished = { onChange(current) })
            UiMode.Material -> androidx.compose.material3.Slider(value = current, onValueChange = { current = it }, enabled = enabled && !LocalThemeBusy.current, valueRange = range, onValueChangeFinished = { onChange(current) })
        }
    }
}

@Composable
internal fun ThemeDialog(title: String, onDismiss: () -> Unit, confirm: String = stringResource(R.string.theme_confirm), enabled: Boolean = true,
    onConfirm: () -> Unit, content: @Composable ColumnScope.() -> Unit) {
    val bodyHeight = (LocalConfiguration.current.screenHeightDp * .6f).dp.coerceAtMost(480.dp)
    val body: @Composable (Modifier) -> Unit = { modifier ->
        CompositionLocalProvider(com.maplesu.core.theme.LocalThemePhotoContent provides null) {
            Column(modifier.fillMaxWidth().heightIn(max = bodyHeight).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp), content = content)
        }
    }
    when (LocalUiMode.current) {
        UiMode.Miuix -> top.yukonga.miuix.kmp.window.WindowDialog(show = true, title = title,
            backgroundColor = miuixDialogColor(), onDismissRequest = onDismiss, content = {
                Column { body(Modifier.weight(1f,fill=false)); Row(Modifier.fillMaxWidth().padding(top=12.dp), horizontalArrangement = Arrangement.spacedBy(20.dp)) {
                    top.yukonga.miuix.kmp.basic.TextButton(text=stringResource(R.string.theme_cancel),
                        enabled=!LocalThemeBusy.current,modifier=Modifier.weight(1f),onClick=onDismiss)
                    top.yukonga.miuix.kmp.basic.TextButton(text=confirm,enabled=enabled && !LocalThemeBusy.current,
                        modifier=Modifier.weight(1f),colors=top.yukonga.miuix.kmp.basic.ButtonDefaults.textButtonColorsPrimary(),onClick=onConfirm)
                } }
            })
        UiMode.Material -> androidx.compose.material3.AlertDialog(onDismissRequest = onDismiss,
            containerColor = materialDialogColor(), title = { androidx.compose.material3.Text(title) }, text = { body(Modifier) },
            confirmButton = { ThemeButton(confirm, enabled, onConfirm) }, dismissButton = { ThemeButton(stringResource(R.string.theme_cancel), onClick = onDismiss) })
    }
}
