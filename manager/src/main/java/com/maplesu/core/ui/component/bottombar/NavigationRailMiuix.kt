package com.maplesu.core.ui.component.bottombar

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.foundation.layout.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.maplesu.core.R
import com.maplesu.core.data.repository.SettingsRepositoryImpl
import com.maplesu.core.ui.LocalMainPagerState
import top.yukonga.miuix.kmp.basic.NavigationRail
import top.yukonga.miuix.kmp.basic.NavigationRailItem
import top.yukonga.miuix.kmp.basic.NavigationRailValue
import top.yukonga.miuix.kmp.basic.rememberNavigationRailState
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
fun NavigationRailMiuix(
    navigationBadge: NavigationBadgeState,
    modifier: Modifier = Modifier,
) {
    val mainState = LocalMainPagerState.current

    val items = BottomBarDestination.entries.map { destination ->
        Pair(stringResource(destination.label), destination.icon)
    }
    val settingsRepo = remember { SettingsRepositoryImpl() }
    val state = rememberNavigationRailState(
        initialValue = if (settingsRepo.navigationRailExpanded) {
            NavigationRailValue.Expanded
        } else {
            NavigationRailValue.Collapsed
        },
    )
    LaunchedEffect(state.currentValue) {
        settingsRepo.navigationRailExpanded = state.isExpanded
    }

    NavigationRail(
        modifier = modifier,
        state = state,
        color = MiuixTheme.colorScheme.surface,
        expandContentDescription = stringResource(R.string.nav_rail_expand),
        collapseContentDescription = stringResource(R.string.nav_rail_collapse),
    ) {
        items.forEachIndexed { index, (label, icon) ->
            val revision = com.maplesu.core.ui.util.WallpaperPrefs.observe()
            val context = LocalContext.current
            if (com.maplesu.core.ui.util.NavIcons.hasAny(context)) {
                val selected = mainState.selectedPage == index
                top.yukonga.miuix.kmp.basic.Card(
                    modifier = Modifier.padding(horizontal=8.dp,vertical=4.dp).fillMaxWidth(),
                    onClick = { mainState.animateToPage(index) },
                    colors = top.yukonga.miuix.kmp.basic.CardDefaults.defaultColors(
                        color = if (selected) com.maplesu.core.theme.LocalThemeWallpaperStyle.current?.let {
                            MiuixTheme.colorScheme.secondaryContainer.copy(alpha=it.selection)
                        } ?: MiuixTheme.colorScheme.primaryContainer else androidx.compose.ui.graphics.Color.Transparent),
                ) {
                    Row(Modifier.padding(16.dp),verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(12.dp)) {
                        val badge = navigationBadgeFor(index,navigationBadge)
                        if (badge != null) top.yukonga.miuix.kmp.basic.BadgedBox(badge={ badge() }) { NavIcon(index,icon,label) }
                        else NavIcon(index,icon,label)
                        if (state.isExpanded) top.yukonga.miuix.kmp.basic.Text(label)
                    }
                }
            } else {
            NavigationRailItem(
                selected = mainState.selectedPage == index,
                onClick = {
                    mainState.animateToPage(index)
                },
                icon = icon,
                label = label,
                badge = navigationBadgeFor(index, navigationBadge),
            )
            }
        }
    }
}
