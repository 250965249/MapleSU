package com.maplesu.core.ui.viewmodel

import android.content.Context
import android.content.SharedPreferences
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.maplesu.core.Natives
import com.maplesu.core.data.repository.SettingsRepository
import com.maplesu.core.data.repository.SettingsRepositoryImpl
import com.maplesu.core.ksuApp
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.theme.ThemeController
import dev.maplesu.manager.workmode.ModeRuntime
import com.maplesu.core.ui.util.AppearancePreferences

class MainActivityViewModel(
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    // 外观共享；业务与权限相关设置仍由 SettingsRepository 的模式路由隔离。
    private val prefs = AppearancePreferences.prefs(ksuApp)
    private val settingRepo: SettingsRepository = SettingsRepositoryImpl()
    private val mainPageState = MainPageState(savedStateHandle)
    private val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == null || key in observedKeys || key.startsWith("theme_")) {
            _uiState.value = readUiState()
        }
    }

    private val _uiState = MutableStateFlow(readUiState())
    val uiState: StateFlow<MainActivityUiState> = _uiState.asStateFlow()
    val selectedMainPage: StateFlow<Int> = mainPageState.selectedPage

    /**
     * `Natives.isFullFeatured()` 的快照：门控预加载与导航角标。
     *
     * 它以前在 MainScreen 组合期读取，有两个问题：每次重组都跑一遍（内部可能读文件/JNI），
     * 而且不是状态——模式激活后不会触发重组，预加载要等用户第一次切页才开始，
     * 正好撞上切页动画，列表数据又在随后某个时刻突然到达。
     */
    private val _isFullFeatured = MutableStateFlow(false)
    val isFullFeatured: StateFlow<Boolean> = _isFullFeatured.asStateFlow()

    init {
        prefs.registerOnSharedPreferenceChangeListener(listener)
        viewModelScope.launch {
            publishFullFeatured()
            if (ModeRuntime.active == null) {
                ModeRuntime.awaitActivated(MODE_ACTIVATION_WAIT_MS)
                publishFullFeatured()
            }
            // Lite 下它取决于 Ultra 探针缓存，探针可能比模式激活晚落地。
            var attempt = 0
            while (!_isFullFeatured.value && attempt < FULL_FEATURED_RETRIES) {
                attempt += 1
                delay(FULL_FEATURED_RETRY_STEP_MS * attempt)
                publishFullFeatured()
            }
        }
    }

    /** 回前台/切页时重读一次（可能在别的页面完成了安装或环境激活）。 */
    fun refreshFullFeatured() {
        viewModelScope.launch { publishFullFeatured() }
    }

    private suspend fun publishFullFeatured() {
        _isFullFeatured.value = withContext(Dispatchers.IO) {
            runCatching { Natives.isFullFeatured() }.getOrDefault(false)
        }
    }

    override fun onCleared() {
        prefs.unregisterOnSharedPreferenceChangeListener(listener)
    }

    fun selectUiMode(mode: UiMode) {
        settingRepo.uiMode = mode.value
    }

    fun finishAppearanceIntro() {
        settingRepo.applyComicPreset(UiMode.fromValue(settingRepo.uiMode) == UiMode.Miuix &&
            prefs.getBoolean(AppearancePreferences.INTRO_COMIC, true))
        prefs.edit().putBoolean(AppearancePreferences.INTRO_COMPLETE, true).apply()
    }

    fun setIntroComic(enabled: Boolean) {
        prefs.edit().putBoolean(AppearancePreferences.INTRO_COMIC, enabled).apply()
    }

    fun setSelectedMainPage(page: Int) {
        mainPageState.updateSelectedPage(page)
    }

    private fun readUiState(): MainActivityUiState {
        return MainActivityUiState(
            appSettings = ThemeController.getAppSettings(),
            appearanceIntroComplete = prefs.getBoolean(AppearancePreferences.INTRO_COMPLETE, false),
            introComic = prefs.getBoolean(AppearancePreferences.INTRO_COMIC, true),
            pageScale = settingRepo.pageScale,
            enableBlur = settingRepo.enableBlur,
            enableFloatingBottomBar = settingRepo.enableFloatingBottomBar,
            enableFloatingBottomBarBlur = settingRepo.enableFloatingBottomBarBlur,
            enableNavigationBadge = settingRepo.enableNavigationBadge,
            snowEnabled = settingRepo.snowEnabled,
            snowSize = settingRepo.snowSize,
            snowSpeed = settingRepo.snowSpeed,
            trollRainEnabled = settingRepo.trollRainEnabled,
            trollRainSize = settingRepo.trollRainSize,
            trollRainSpeed = settingRepo.trollRainSpeed,
            gravityEnabled = settingRepo.gravityEnabled,
            gravityMode = settingRepo.gravityMode,
            enablePredictiveBack = settingRepo.enablePredictiveBack,
            enableSwipeDismiss = settingRepo.enableSwipeDismiss,
            pagerInterceptionMode = settingRepo.pagerInterceptionMode,
            moduleDescriptionMaxLines = settingRepo.moduleDescriptionMaxLines,
            uiMode = UiMode.fromValue(settingRepo.uiMode),
        )
    }

    private companion object {
        const val MODE_ACTIVATION_WAIT_MS = 15_000L
        const val FULL_FEATURED_RETRIES = 3
        const val FULL_FEATURED_RETRY_STEP_MS = 1_000L

        val observedKeys = setOf(
            AppearancePreferences.INTRO_COMPLETE,
            AppearancePreferences.INTRO_COMIC,
            "color_mode",
            "key_color",
            "color_style",
            "color_spec",
            "page_scale",
            "module_description_max_lines",
            "enable_blur",
            "enable_floating_bottom_bar",
            "enable_floating_bottom_bar_blur",
            "enable_navigation_badge",
            "snow_enabled",
            "snow_size",
            "snow_speed",
            "troll_rain_enabled",
            "troll_rain_size",
            "troll_rain_speed",
            "gravity_enabled",
            "gravity_mode",
            "enable_swipe_dismiss",
            "enable_predictive_back",
            "pager_interception_mode",
            "ui_mode",
            "miuix_monet",
            // 个性化壁纸(改了要立刻重新组合,壁纸才会即时生效)
            "wallpaper_path",
            "wallpaper_kind",
            "wallpaper_dim",
            "wallpaper_blur",
            "ui_translucent",
            "ui_translucent_alpha",
            "wallpaper_seed",
            "wallpaper_seed_color",
        )
    }
}

private const val SELECTED_MAIN_PAGE_KEY = "selected_main_page"

private class MainPageState(
    private val savedStateHandle: SavedStateHandle,
) {
    val selectedPage: StateFlow<Int> = savedStateHandle.getStateFlow(SELECTED_MAIN_PAGE_KEY, 0)

    fun updateSelectedPage(page: Int) {
        savedStateHandle[SELECTED_MAIN_PAGE_KEY] = MainPagerConfig.coercePage(page)
    }
}

object MainPagerConfig {
    const val PAGE_COUNT = 4
    const val LAST_PAGE_INDEX = PAGE_COUNT - 1

    fun coercePage(page: Int): Int = page.coerceIn(0, LAST_PAGE_INDEX)
}
