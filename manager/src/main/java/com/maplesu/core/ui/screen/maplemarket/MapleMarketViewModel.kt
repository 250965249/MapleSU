package com.maplesu.core.ui.screen.maplemarket

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.maplesu.core.R
import com.maplesu.core.data.repository.ModuleRepositoryImpl
import com.maplesu.core.ksuApp
import dev.maplesu.manager.market.MapleMarketRepository
import dev.maplesu.manager.market.MarketErrorCode
import dev.maplesu.manager.market.MarketException
import dev.maplesu.manager.market.MarketModule
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class MapleMarketUiState(
    val modules: List<MarketModule> = emptyList(),
    val loading: Boolean = false,
    val refreshing: Boolean = false,
    val stale: Boolean = false,
    val error: String? = null,
    val selected: MarketModule? = null,
    val changelog: String? = null,
    val downloadingId: String? = null,
    val progress: Float? = null,
    val downloaded: Uri? = null,
    val sourceUrl: String = "",
    val sourceKey: String = "",
    val sourceIsOfficial: Boolean = true,
    val installedVersions: Map<String, String> = emptyMap(),
)

class MapleMarketViewModel(
    private val repository: MapleMarketRepository = MapleMarketRepository(ksuApp),
) : ViewModel() {
    private val initialSource = repository.source()
    private val state = MutableStateFlow(MapleMarketUiState(
        sourceUrl = initialSource.url,
        sourceKey = initialSource.key,
        sourceIsOfficial = initialSource.isOfficial,
    ))
    val uiState = state.asStateFlow()
    private var refreshJob: Job? = null
    private var changelogJob: Job? = null
    private var downloadJob: Job? = null
    private var installedJob: Job? = null
    private var generation = 0L
    private var downloadSerial = 0L

    init { refresh() }

    fun refresh() {
        if (refreshJob?.isActive == true) return
        val currentGeneration = generation
        state.update { it.copy(loading = it.modules.isEmpty(), refreshing = true, error = null) }
        refreshJob = viewModelScope.launch {
            try {
                val catalog = repository.loadCatalog()
                if (currentGeneration == generation) state.update { current ->
                    val selected = current.selected?.let { previous ->
                        catalog.modules.firstOrNull { it.id == previous.id && it.sha256 == previous.sha256 }
                    }
                    current.copy(modules = catalog.modules, stale = catalog.stale, selected = selected,
                        error = catalog.error?.let(::message))
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                if (currentGeneration == generation) state.update { it.copy(error = message(error)) }
            } finally {
                if (currentGeneration == generation) state.update { it.copy(loading = false, refreshing = false) }
            }
        }
        refreshInstalled()
    }

    fun refreshInstalled() {
        if (installedJob?.isActive == true || ModeRuntime.active != WorkMode.LITE) return
        installedJob = viewModelScope.launch {
            try {
                ModuleRepositoryImpl().getModules().onSuccess { modules ->
                    state.update { it.copy(installedVersions = modules
                        .filter { module -> !module.remove }
                        .associate { module -> module.id.removePrefix("maplesu:") to module.version }) }
                }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { /* The catalog remains usable when the installed list is not ready. */ }
        }
    }

    fun select(module: MarketModule) {
        val current = state.value.modules.firstOrNull { it.id == module.id && it.sha256 == module.sha256 } ?: return
        changelogJob?.cancel()
        state.update { it.copy(selected = current, changelog = null, error = null) }
        val currentGeneration = generation
        changelogJob = viewModelScope.launch {
            val text = try { repository.changelog(current) }
            catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { ksuApp.getString(R.string.maple_market_runtime_changelog_failed) }
            if (currentGeneration == generation && state.value.selected == current) {
                state.update { it.copy(changelog = text) }
            }
        }
    }

    fun closeDetail() {
        changelogJob?.cancel()
        state.update { it.copy(selected = null, changelog = null) }
    }

    fun download(module: MarketModule) {
        if (downloadJob?.isActive == true) return
        val current = state.value.modules.firstOrNull { it.id == module.id && it.sha256 == module.sha256 } ?: return
        if (!current.installable || ModeRuntime.active != WorkMode.LITE) {
            state.update { it.copy(error = ksuApp.getString(R.string.maple_market_runtime_mode_required)) }
            return
        }
        val currentGeneration = generation
        val serial = ++downloadSerial
        state.update { it.copy(downloadingId = current.id, progress = 0f, downloaded = null, error = null) }
        downloadJob = viewModelScope.launch {
            try {
                val file = repository.download(current) { progress ->
                    if (currentGeneration == generation && serial == downloadSerial) state.update { it.copy(progress = progress.coerceIn(0f, 1f)) }
                }
                if (currentGeneration == generation && serial == downloadSerial) state.update {
                    if (ModeRuntime.active == WorkMode.LITE) it.copy(downloaded = Uri.fromFile(file))
                    else it.copy(error = ksuApp.getString(R.string.maple_market_runtime_mode_required))
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                if (currentGeneration == generation && serial == downloadSerial) state.update { it.copy(error = message(error)) }
            } finally {
                if (currentGeneration == generation && serial == downloadSerial) state.update { it.copy(downloadingId = null, progress = null) }
            }
        }
    }

    fun cancelDownload() {
        downloadSerial++
        downloadJob?.cancel()
        downloadJob = null
        state.update { it.copy(downloadingId = null, progress = null) }
    }

    fun consumeDownload() { state.update { it.copy(downloaded = null) } }

    fun saveSource(url: String, key: String): Boolean {
        try { repository.saveSource(url.trim(), key.trim()) }
        catch (_: Exception) {
            state.update { it.copy(error = ksuApp.getString(R.string.maple_market_runtime_invalid_source)) }
            return false
        }
        sourceChanged()
        return true
    }

    fun resetSource() {
        repository.resetSource()
        sourceChanged()
    }

    private fun sourceChanged() {
        generation++
        refreshJob?.cancel()
        refreshJob = null
        changelogJob?.cancel()
        cancelDownload()
        val source = repository.source()
        state.update { MapleMarketUiState(sourceUrl = source.url, sourceKey = source.key,
            sourceIsOfficial = source.isOfficial, installedVersions = it.installedVersions) }
        refresh()
    }

    private fun message(error: Throwable): String {
        val resource = when ((error as? MarketException)?.code) {
            MarketErrorCode.SIGNATURE_INVALID -> R.string.maple_market_runtime_signature_failed
            MarketErrorCode.DOWNLOAD_INTEGRITY -> R.string.maple_market_runtime_package_failed
            MarketErrorCode.INVALID_SOURCE -> R.string.maple_market_runtime_invalid_source
            MarketErrorCode.MODULE_UNAVAILABLE -> R.string.maple_market_runtime_mode_required
            else -> R.string.maple_market_runtime_load_failed
        }
        return ksuApp.getString(resource)
    }
}
