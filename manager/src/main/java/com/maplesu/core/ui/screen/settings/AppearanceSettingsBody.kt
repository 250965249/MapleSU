package com.maplesu.core.ui.screen.settings

import android.os.Build
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringArrayResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.maplesu.core.R
import com.maplesu.core.data.repository.SettingsRepositoryImpl
import com.maplesu.core.theme.ThemeHomeLayout
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.material.SegmentedColumn
import com.maplesu.core.ui.navigation3.LocalNavigator
import com.maplesu.core.ui.navigation3.Route
import com.maplesu.core.ui.screen.home.rememberThemeHomeLayout
import com.maplesu.core.ui.util.WallpaperPrefs

/** One set of entries and preference ownership, presented by each skin's native controls. */
@Composable
internal fun AppearanceSettingsBody(uiState: SettingsUiState, actions: SettingsScreenActions) {
    val navigator = LocalNavigator.current
    val operations = LocalThemeOperations.current
    val revision = WallpaperPrefs.observe()
    val repo = remember { SettingsRepositoryImpl() }
    val layout = rememberThemeHomeLayout()
    val layoutLabel = stringResource(when (layout) {
        ThemeHomeLayout.Large -> R.string.theme_home_large
        ThemeHomeLayout.Small -> R.string.theme_home_small
        ThemeHomeLayout.Three -> R.string.theme_home_three
    })
    // Refresh controls after a theme/reset or an edit on another appearance page.
    key(revision) {
        Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            AppearanceGroup(stringResource(R.string.theme_section_theme), listOf {
                ThemeRow(stringResource(R.string.theme_store),stringResource(R.string.theme_appearance_store_summary),
                    Icons.Rounded.Storefront,onClick=actions.onOpenThemeStore)
            })
            AppearanceGroup(stringResource(R.string.theme_section_design), listOf(
                { ThemeDropdown(stringResource(R.string.settings_ui_mode),UiMode.entries.map { it.name },
                    if (uiState.uiMode == UiMode.Material.value) 1 else 0,actions.onSetUiModeIndex) },
                { ThemeRow(stringResource(R.string.settings_theme),stringResource(R.string.settings_theme_summary),
                    Icons.Rounded.Palette,onClick=actions.onOpenTheme) },
                { ThemeRow(stringResource(R.string.theme_font),stringResource(R.string.theme_appearance_font_summary),
                    Icons.Rounded.FontDownload,onClick=actions.onOpenFont) },
                { ThemeSlider(stringResource(R.string.settings_page_scale),repo.pageScale,.8f..1.1f) { repo.pageScale=it } },
            ))
            AppearanceGroup(stringResource(R.string.theme_section_home), listOf(
                { ThemeRow(stringResource(R.string.theme_layout_title),
                    stringResource(R.string.theme_home_current,layoutLabel),Icons.Rounded.Dashboard,onClick=actions.onOpenLayout) },
                { ThemeSwitch(stringResource(R.string.settings_navigation_badge),repo.enableNavigationBadge,
                    summary=stringResource(R.string.settings_navigation_badge_summary)) { repo.enableNavigationBadge=it } },
                { ThemeDropdown(stringResource(R.string.settings_module_description_max_lines),
                    (1..5).map { "$it ${stringResource(R.string.unit_lines)}" },repo.moduleDescriptionMaxLines.coerceIn(1,5)-1) {
                    repo.moduleDescriptionMaxLines=it+1
                } },
            ))
            AppearanceGroup(stringResource(R.string.theme_section_images), listOf(
                { ThemeRow(stringResource(R.string.theme_wallpaper),stringResource(R.string.theme_appearance_wallpaper_summary),
                    Icons.Rounded.Wallpaper,onClick=actions.onOpenWallpaper) },
                { ThemeRow(stringResource(R.string.ui_d_custom_images),stringResource(R.string.theme_images_summary),
                    Icons.Rounded.Image,onClick=actions.onOpenImages) },
                { ThemeRow(stringResource(R.string.theme_media_title),icon=Icons.Rounded.Movie) { navigator.push(Route.ThemeMedia) } },
            ))
            AppearanceGroup(stringResource(R.string.theme_section_navigation), buildList {
                if (LocalUiMode.current == UiMode.Miuix) {
                    if (Build.VERSION.SDK_INT >= 33) add {
                        ThemeSwitch(stringResource(R.string.settings_enable_blur),repo.enableBlur,
                            summary=stringResource(R.string.settings_enable_blur_summary)) { repo.enableBlur=it }
                    }
                    add { ThemeSwitch(stringResource(R.string.settings_floating_bottom_bar),repo.enableFloatingBottomBar,
                        summary=stringResource(R.string.settings_floating_bottom_bar_summary)) { repo.enableFloatingBottomBar=it } }
                    if (repo.enableFloatingBottomBar && Build.VERSION.SDK_INT >= 33) add {
                        ThemeSwitch(stringResource(R.string.settings_enable_glass),repo.enableFloatingBottomBarBlur,
                            summary=stringResource(R.string.settings_enable_glass_summary)) { repo.enableFloatingBottomBarBlur=it }
                    }
                }
                if (Build.VERSION.SDK_INT >= 34) add {
                    ThemeSwitch(stringResource(R.string.settings_enable_predictive_back),repo.enablePredictiveBack,
                        summary=stringResource(R.string.settings_enable_predictive_back_summary)) { repo.enablePredictiveBack=it }
                }
                add { ThemeSwitch(stringResource(R.string.settings_enable_swipe_dismiss),repo.enableSwipeDismiss,
                    summary=stringResource(R.string.settings_enable_swipe_dismiss_summary)) { repo.enableSwipeDismiss=it } }
                add { ThemeDropdown(stringResource(R.string.settings_pager_gesture_mode),listOf(
                    stringResource(R.string.settings_pager_gesture_native),stringResource(R.string.settings_pager_gesture_cross_axis),
                    stringResource(R.string.settings_pager_gesture_ios_like)),repo.pagerInterceptionMode.coerceIn(0,2)) { repo.pagerInterceptionMode=it } }
            })
            AppearanceGroup(stringResource(R.string.theme_section_effects), buildList {
                add { ThemeSwitch(stringResource(R.string.ui_d_fall_title),repo.snowEnabled,
                    summary=stringResource(R.string.ui_d_fall_summary)) { repo.snowEnabled=it } }
                if (repo.snowEnabled) {
                    add { ThemeSlider(stringResource(R.string.ui_d_fall_size),repo.snowSize,.4f..3f) { repo.snowSize=it } }
                    add { ThemeSlider(stringResource(R.string.ui_d_fall_speed),repo.snowSpeed,.4f..3f) { repo.snowSpeed=it } }
                }
                add { ThemeSwitch(stringResource(R.string.ui_d_troll_title),repo.trollRainEnabled,
                    summary=stringResource(R.string.ui_d_troll_summary)) { repo.trollRainEnabled=it } }
                if (repo.trollRainEnabled) {
                    add { ThemeSlider(stringResource(R.string.ui_d_troll_size),repo.trollRainSize,.4f..3f) { repo.trollRainSize=it } }
                    add { ThemeSlider(stringResource(R.string.ui_d_troll_speed),repo.trollRainSpeed,.4f..3f) { repo.trollRainSpeed=it } }
                }
                add { ThemeSwitch(stringResource(R.string.ui_d_gravity_title),repo.gravityEnabled,
                    summary=stringResource(R.string.ui_d_gravity_summary)) { repo.gravityEnabled=it } }
                if (repo.gravityEnabled) add {
                    ThemeDropdown(stringResource(R.string.ui_d_gravity_calibrate),stringArrayResource(R.array.ui_d_gravity_modes).toList(),
                        repo.gravityMode.coerceIn(0,3)) { repo.gravityMode=it }
                }
            })
            AppearanceGroup("",listOf { ThemeResetPreference(operations::reset) })
        }
    }
}

@Composable
private fun AppearanceGroup(title: String, rows: List<@Composable () -> Unit>) {
    Column(verticalArrangement=Arrangement.spacedBy(8.dp)) {
        if (title.isNotEmpty()) ThemeText(title,Modifier.padding(start=8.dp,top=8.dp),secondary=true)
        when (LocalUiMode.current) {
            UiMode.Miuix -> top.yukonga.miuix.kmp.basic.Card(Modifier.fillMaxWidth()) { rows.forEach { it() } }
            UiMode.Material -> SegmentedColumn(Modifier.fillMaxWidth(),content=rows)
        }
    }
}

