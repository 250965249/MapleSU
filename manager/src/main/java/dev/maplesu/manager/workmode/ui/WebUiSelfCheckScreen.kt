package dev.maplesu.manager.workmode.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.Text
import top.yukonga.miuix.kmp.basic.TopAppBar as MiuixTopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import com.maplesu.core.ui.screen.host.HiddenFlowText
import com.maplesu.core.ui.screen.host.HiddenFlowButton
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.material.ExpressiveScaffold
import com.maplesu.core.ui.component.material.SegmentedColumn
import com.maplesu.core.ui.component.material.TopBarBackButton
import com.maplesu.core.ui.component.material.expressiveTopAppBarColors
import com.maplesu.core.ui.theme.LocalEnableBlur
import com.maplesu.core.ui.util.BlurredBar
import com.maplesu.core.ui.util.rememberBlurBackdrop
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

/**
 * WebUI 自检页（内部验证；A/B 都显示，风格同隐藏页/主题设置）。
 * 所有检查项就地显示 ok/fail+原因，不假装成功；隐藏后入口与页面整体消失。
 */
@Composable
fun WebUiSelfCheckScreen(onBack: () -> Unit) {
    val viewModel = viewModel<WebUiSelfCheckViewModel>()
    val ui by viewModel.uiState.collectAsStateWithLifecycle()
    when (LocalUiMode.current) {
        UiMode.Miuix -> SelfCheckMiuix(ui, viewModel, onBack)
        UiMode.Material -> SelfCheckMaterial(ui, viewModel, onBack)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SelfCheckMaterial(
    ui: WebUiSelfCheckUi,
    viewModel: WebUiSelfCheckViewModel,
    onBack: () -> Unit,
) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())
    ExpressiveScaffold(
        topBar = {
            LargeFlexibleTopAppBar(
                navigationIcon = { TopBarBackButton(onClick = onBack) },
                title = { Text(stringResource(R.string.webui_selfcheck_title)) },
                colors = expressiveTopAppBarColors(),
                windowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
                scrollBehavior = scrollBehavior,
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing,
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .nestedScroll(scrollBehavior.nestedScrollConnection),
            verticalArrangement = Arrangement.spacedBy(13.dp),
        ) {
            item {
                SegmentedColumn(
                    modifier = Modifier.padding(horizontal = 16.dp),
                    content = listOf { SelfCheckBody(ui, viewModel) },
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SelfCheckMiuix(
    ui: WebUiSelfCheckUi,
    viewModel: WebUiSelfCheckViewModel,
    onBack: () -> Unit,
) {
    val scrollBehavior = MiuixScrollBehavior()
    val backdrop = rememberBlurBackdrop(LocalEnableBlur.current)
    Scaffold(
        topBar = {
            BlurredBar(backdrop) {
                MiuixTopAppBar(
                    color = if (backdrop != null) androidx.compose.ui.graphics.Color.Transparent else colorScheme.surface,
                    title = stringResource(R.string.webui_selfcheck_title),
                    navigationIcon = {
                        IconButton(onClick = onBack) {
                            Icon(MiuixIcons.Back, contentDescription = stringResource(R.string.ui_d_back), tint = colorScheme.onSurface)
                        }
                    },
                    scrollBehavior = scrollBehavior,
                )
            }
        },
        popupHost = { },
        contentWindowInsets = WindowInsets.systemBars.only(WindowInsetsSides.Horizontal),
    ) { innerPadding ->
        Box(modifier = if (backdrop != null) Modifier.layerBackdrop(backdrop) else Modifier) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxHeight()
                    .scrollEndHaptic()
                    .overScrollVertical()
                    .nestedScroll(scrollBehavior.nestedScrollConnection)
                    .padding(horizontal = 12.dp),
                contentPadding = innerPadding,
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                item {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(12.dp)) { SelfCheckBody(ui, viewModel) }
                    }
                }
            }
        }
    }
}

@Composable
private fun SelfCheckBody(ui: WebUiSelfCheckUi, viewModel: WebUiSelfCheckViewModel) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        InfoLine(stringResource(R.string.webui_selfcheck_mode), ui.modeLabel)
        HiddenFlowButton(stringResource(if (ui.busy) R.string.ui_polish_link_preparing else R.string.webui_selfcheck_start),
            viewModel::startWebUi, Modifier.fillMaxWidth(), enabled = !ui.busy, primary = true)
        if (ui.startResult.isNotBlank()) {
            HiddenFlowText(stringResource(if (ui.startResult.startsWith("ok")) R.string.ui_polish_link_ready else R.string.ui_polish_link_failed), secondary = true)
        }
        Column(Modifier.fillMaxWidth().clickable(onClick = viewModel::copyLink).padding(vertical = 8.dp)) {
            HiddenFlowText(stringResource(R.string.webui_selfcheck_link))
            HiddenFlowText(ui.webUiLink.ifBlank { "—" }, secondary = true, maxLines = 2)
        }
        HiddenFlowButton(stringResource(if (expanded) R.string.ui_polish_diagnostics_hide else R.string.ui_polish_diagnostics_show),
            { expanded = !expanded }, Modifier.fillMaxWidth())
        if (expanded) {
            InfoLine(stringResource(R.string.webui_selfcheck_root_backend), ui.rootBackendLabel)
            if (ui.startResult.isNotBlank()) HiddenFlowText(ui.startResult, secondary = true)
            HiddenFlowButton(stringResource(R.string.webui_selfcheck_check_status), viewModel::checkStatus, Modifier.fillMaxWidth())
            LinesBlock(ui.statusLines)
            HiddenFlowButton(stringResource(R.string.webui_selfcheck_boot), viewModel::loadBootEvidence, Modifier.fillMaxWidth())
            LinesBlock(ui.bootEvidenceLines)
            HiddenFlowButton(stringResource(R.string.webui_selfcheck_dry_run), viewModel::dryRunRestore, Modifier.fillMaxWidth())
            LinesBlock(ui.dryRunLines)
            HiddenFlowButton(stringResource(R.string.webui_selfcheck_backup), viewModel::prepareBackup, Modifier.fillMaxWidth())
            LinesBlock(ui.backupLines)
        }
    }
}

@Composable
private fun InfoLine(label: String, value: String) {
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        HiddenFlowText(label, secondary = true)
        HiddenFlowText(value.ifBlank { "—" }, maxLines = 2)
    }
}

@Composable
private fun LinesBlock(lines: List<String>) {
    if (lines.isEmpty()) return
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        lines.forEach { HiddenFlowText(it, secondary = true) }
    }
}
