package com.maplesu.core.ui.screen.maplemarket

import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.viewmodel.compose.viewModel
import com.maplesu.core.R
import com.maplesu.core.ui.component.dialog.rememberConfirmDialog
import com.maplesu.core.ui.navigation3.LocalNavigator
import com.maplesu.core.ui.navigation3.Route
import com.maplesu.core.ui.screen.flash.FlashIt
import com.maplesu.core.ui.screen.modulerepo.formatFileSize
import dev.maplesu.manager.market.MarketModule
import dev.maplesu.manager.modules.compat.UltraModuleAction

internal const val MARKET_ISSUES_URL = "https://github.com/FengQiuFQ/maplesu-module-market/issues/new?template=rights.yml"

@Composable
fun MapleMarketScreen() {
    val navigator = LocalNavigator.current
    val uriHandler = LocalUriHandler.current
    val viewModel = viewModel<MapleMarketViewModel>()
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    var query by rememberSaveable { mutableStateOf("") }
    var sourceOpen by rememberSaveable { mutableStateOf(false) }
    val listState = rememberLazyListState()
    var pendingDownload by remember { mutableStateOf<MarketModule?>(null) }
    val downloadNotice = rememberConfirmDialog(
        onConfirm = { pendingDownload?.let(viewModel::download); pendingDownload = null },
        onDismiss = { pendingDownload = null },
    )
    val noticeTitle = stringResource(R.string.maple_market_download_notice)
    val downloadLabel = stringResource(R.string.maple_market_download)

    LaunchedEffect(Unit) { if (state.modules.isEmpty()) viewModel.refresh() }
    LifecycleResumeEffect(Unit) {
        viewModel.refreshInstalled()
        onPauseOrDispose {}
    }
    LaunchedEffect(state.downloaded) {
        state.downloaded?.let { uri ->
            viewModel.consumeDownload()
            navigator.push(Route.Flash(FlashIt.FlashModules(listOf(uri), UltraModuleAction.MARKET_QUICK_ACTION)))
        }
    }
    BackHandler(enabled = state.selected != null && !sourceOpen) { viewModel.closeDetail() }
    fun back() {
        if (state.selected != null) viewModel.closeDetail() else navigator.pop()
    }

    MarketPage(
        title = state.selected?.name ?: stringResource(R.string.maple_market_title),
        onBack = ::back,
        onRefresh = if (state.selected == null) viewModel::refresh else null,
        onSource = { sourceOpen = true },
    ) { padding ->
        AnimatedContent(
            targetState = state.selected,
            contentKey = { it?.id },
            transitionSpec = { fadeIn() togetherWith fadeOut() },
            modifier = Modifier.fillMaxSize().padding(padding).consumeWindowInsets(padding),
            label = "market-detail",
        ) { selected ->
            if (selected == null) {
                MarketModuleList(state, query, { query = it }, viewModel::refresh, viewModel::select, viewModel::cancelDownload, listState)
            } else {
                MarketDetail(
                    module = selected,
                    changelog = state.changelog,
                    installedVersion = state.installedVersions[selected.installedModuleId],
                    downloadingId = state.downloadingId,
                    progress = state.progress,
                    error = state.error,
                    onDownload = {
                        if (selected.downloadAlert.isBlank()) viewModel.download(selected)
                        else {
                            pendingDownload = selected
                            downloadNotice.showConfirm(title = noticeTitle, content = selected.downloadAlert, confirm = downloadLabel)
                        }
                    },
                    onCancel = viewModel::cancelDownload,
                    onOpenSource = { if (isMarketWebUrl(selected.sourceUrl)) uriHandler.openUri(selected.sourceUrl) },
                )
            }
        }
    }
    if (sourceOpen) {
        var url by rememberSaveable { mutableStateOf(state.sourceUrl) }
        var key by rememberSaveable { mutableStateOf(state.sourceKey) }
        MarketDialog(stringResource(R.string.maple_market_source), onDismiss = { sourceOpen = false }) {
            MarketText(stringResource(if (state.sourceIsOfficial) R.string.maple_market_official else R.string.maple_market_custom), weight = FontWeight.Medium)
            MarketText(stringResource(R.string.maple_market_source_hint), secondary = true)
            MarketField(url, { url = it }, stringResource(R.string.maple_market_manifest_url), singleLine = true)
            MarketField(key, { key = it }, stringResource(R.string.maple_market_trusted_key))
            if (isMarketWebUrl(state.sourceUrl)) MarketButton(stringResource(R.string.maple_market_open_manifest), {
                uriHandler.openUri(state.sourceUrl)
            }, Modifier.fillMaxWidth())
            state.error?.takeIf { it.isNotBlank() }?.let { MarketText(it, secondary = true, size = 12.sp) }
            MarketButton(stringResource(R.string.maple_market_restore_official), {
                viewModel.resetSource()
                sourceOpen = false
            }, Modifier.fillMaxWidth())
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                MarketButton(stringResource(android.R.string.cancel), { sourceOpen = false }, Modifier.weight(1f))
                MarketButton(stringResource(R.string.maple_market_save_source), {
                    if (viewModel.saveSource(url.trim(), key.trim())) sourceOpen = false
                }, Modifier.weight(1f), enabled = url.isNotBlank() && key.isNotBlank(), primary = true)
            }
        }
    }
}

@Composable
internal fun MarketModuleList(
    state: MapleMarketUiState,
    query: String,
    onQuery: (String) -> Unit,
    onRefresh: () -> Unit,
    onSelect: (MarketModule) -> Unit,
    onCancel: () -> Unit,
    listState: LazyListState = rememberLazyListState(),
) {
    val filtered = remember(state.modules, query) { filterMarketModules(state.modules, query) }
    val uriHandler = LocalUriHandler.current
    LazyColumn(state = listState, contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item(key = "search") {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                MarketText(stringResource(R.string.maple_market_intro), secondary = true)
                MarketText(
                    stringResource(R.string.maple_market_contribution_notice),
                    modifier = Modifier.clickable(role = Role.Button) { uriHandler.openUri(MARKET_ISSUES_URL) },
                    secondary = true,
                    size = 12.sp,
                )
                MarketField(query, onQuery, stringResource(R.string.maple_market_search), singleLine = true)
            }
        }
        if (state.loading || state.refreshing) item(key = "loading") {
            Box(Modifier.fillMaxWidth().padding(12.dp), contentAlignment = Alignment.Center) { MarketLoading() }
        }
        if (state.stale) item(key = "cached") {
            MarketText(stringResource(R.string.maple_market_cached), secondary = true, size = 12.sp)
        }
        if (state.downloadingId != null) item(key = "download") {
            MarketCard {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    MarketLoading(state.progress?.coerceIn(0f, 1f))
                    MarketText(stringResource(R.string.maple_market_downloading), Modifier.weight(1f))
                    MarketButton(stringResource(android.R.string.cancel), onCancel)
                }
            }
        }
        state.error?.takeIf(String::isNotBlank)?.let { error -> item(key = "error") { MarketError(error, onRefresh) } }
        if (filtered.isEmpty() && !state.loading) item(key = "empty") {
            Box(Modifier.fillMaxWidth().padding(vertical = 48.dp), contentAlignment = Alignment.Center) {
                MarketText(stringResource(if (query.isBlank()) R.string.maple_market_empty else R.string.maple_market_no_results), secondary = true)
            }
        }
        items(filtered, key = { it.id }, contentType = { "market-module" }) { module ->
            MarketModuleCard(module, state.installedVersions[module.installedModuleId], onClick = { onSelect(module) })
        }
    }
}

internal fun filterMarketModules(modules: List<MarketModule>, query: String): List<MarketModule> {
    val words = query.trim().split(Regex("\\s+")).filter(String::isNotBlank)
    if (words.isEmpty()) return modules
    return modules.filter { module ->
        val text = listOf(module.name, module.englishName, module.id, module.author, module.description).joinToString(" ")
        words.all { text.contains(it, ignoreCase = true) }
    }
}

internal fun isMarketWebUrl(value: String): Boolean = runCatching {
    val uri = Uri.parse(value)
    uri.scheme.equals("https", ignoreCase = true) && !uri.host.isNullOrBlank() && uri.userInfo == null
}.getOrDefault(false)

@Composable
private fun MarketModuleCard(module: MarketModule, installedVersion: String?, onClick: () -> Unit) {
    MarketCard(onClick = onClick) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            MarketText(module.name, Modifier.weight(1f), size = 18.sp, weight = FontWeight.SemiBold, maxLines = 2)
            MarketText(module.version, secondary = true, size = 12.sp, maxLines = 1)
        }
        if (module.author.isNotBlank()) MarketText(module.author, secondary = true, size = 12.sp, maxLines = 1)
        MarketText(module.description, secondary = true, maxLines = 3)
        if (module.installable) MarketText(stringResource(if (module.type == "KERNEL_SU")
            R.string.maple_market_ksu_compatible else R.string.maple_market_ultra_native), secondary = true, size = 12.sp)
        if (installedVersion != null) MarketText(stringResource(R.string.module_repo_installed) + " · " + installedVersion, secondary = true, size = 12.sp)
        if (installedVersion != null && module.isNewerThan(installedVersion)) MarketText(stringResource(R.string.maple_market_update_available), size = 12.sp, weight = FontWeight.Medium)
        if (!module.installable) MarketText(stringResource(R.string.maple_market_incompatible), secondary = true, size = 12.sp)
    }
}

@Composable
internal fun MarketDetail(
    module: MarketModule,
    changelog: String?,
    installedVersion: String?,
    downloadingId: String?,
    progress: Float?,
    error: String?,
    onDownload: () -> Unit,
    onCancel: () -> Unit,
    onOpenSource: () -> Unit,
) {
    var showChangelog by rememberSaveable(module.id) { mutableStateOf(false) }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        MarketCard {
            MarketText(module.name, size = 24.sp, weight = FontWeight.SemiBold)
            MarketText(listOf(module.version, module.author, formatFileSize(module.size)).filter(String::isNotBlank).joinToString(" · "), secondary = true)
            if (installedVersion != null) MarketText(stringResource(R.string.module_repo_installed) + " · " + installedVersion, secondary = true, size = 12.sp)
            if (module.updatedAt.isNotBlank()) MarketText(module.updatedAt, secondary = true, size = 12.sp)
            if (module.installable) MarketText(stringResource(if (module.type == "KERNEL_SU")
                R.string.maple_market_ksu_compatible else R.string.maple_market_ultra_native), secondary = true, size = 12.sp)
            if (isMarketWebUrl(module.sourceUrl)) MarketButton(stringResource(R.string.maple_market_open_project), onOpenSource)
        }
        MarketCard {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                MarketButton(stringResource(R.string.maple_market_details), { showChangelog = false }, Modifier.weight(1f), primary = !showChangelog)
                MarketButton(stringResource(R.string.maple_market_changelog), { showChangelog = true }, Modifier.weight(1f), primary = showChangelog)
            }
            SelectionContainer {
                MarketText(if (showChangelog) changelog?.takeIf(String::isNotBlank) ?: stringResource(R.string.maple_market_no_changelog) else module.description)
            }
        }
        MarketCard {
            if (!module.installable) MarketText(stringResource(R.string.maple_market_incompatible), secondary = true)
            error?.takeIf(String::isNotBlank)?.let { MarketText(it, secondary = true) }
            when {
                downloadingId == module.id -> {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        MarketLoading(progress?.coerceIn(0f, 1f))
                        MarketText(stringResource(R.string.maple_market_downloading) + (progress?.let { " ${(it.coerceIn(0f, 1f) * 100).toInt()}%" } ?: ""))
                    }
                    MarketButton(stringResource(android.R.string.cancel), onCancel, Modifier.fillMaxWidth())
                }
                else -> {
                    if (downloadingId != null) MarketText(stringResource(R.string.maple_market_download_busy), secondary = true)
                    val label = when {
                        installedVersion == module.version -> R.string.maple_market_reinstall
                        installedVersion != null && module.isNewerThan(installedVersion) -> R.string.maple_market_update
                        else -> R.string.maple_market_download
                    }
                    MarketButton(stringResource(label), onDownload, Modifier.fillMaxWidth(), enabled = module.installable && downloadingId == null, primary = true)
                }
            }
        }
    }
}

@Composable
private fun MarketError(error: String, onRetry: () -> Unit) {
    MarketCard {
        MarketText(error, secondary = true)
        MarketButton(stringResource(R.string.maple_market_retry), onRetry)
    }
}
