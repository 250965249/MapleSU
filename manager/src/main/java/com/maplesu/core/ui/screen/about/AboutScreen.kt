package com.maplesu.core.ui.screen.about

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.dropUnlessResumed
import com.maplesu.core.BuildConfig
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.maple.BrandBannerKind
import com.maplesu.core.ui.component.maple.BrandDialogMaterial
import com.maplesu.core.ui.component.maple.BrandDialogMiuix
import com.maplesu.core.ui.navigation3.LocalNavigator
import com.maplesu.core.ui.screen.home.ABOUT_TELEGRAM_URL
import com.maplesu.core.ui.screen.home.AdvisorWallMaterial
import com.maplesu.core.ui.screen.home.AdvisorWallMiuix

@Composable
fun AboutScreen() {
    val navigator = LocalNavigator.current
    val uriHandler = LocalUriHandler.current
    var showAdvisors by rememberSaveable { mutableStateOf(false) }
    val htmlString = stringResource(R.string.maplesu_upstream_sources)
    val state = AboutUiState(
        title = stringResource(R.string.about),
        appName = stringResource(R.string.app_name),
        versionName = BuildConfig.VERSION_NAME,
        links = extractLinks(htmlString) + LinkInfo(stringResource(R.string.about_join_telegram), ABOUT_TELEGRAM_URL),
    )
    val actions = AboutScreenActions(
        onBack = dropUnlessResumed { navigator.pop() },
        onOpenLink = uriHandler::openUri,
        onOpenAdvisors = dropUnlessResumed { showAdvisors = true },
    )

    when (LocalUiMode.current) {
        UiMode.Miuix -> {
            AboutScreenMiuix(state, actions)
            BrandDialogMiuix(
                show = showAdvisors,
                kind = BrandBannerKind.MAPLE,
                title = stringResource(R.string.advisors_title),
                lines = emptyList(),
                onDismiss = { showAdvisors = false },
            ) {
                AdvisorWallMiuix(initiallyExpanded = showAdvisors)
            }
        }
        UiMode.Material -> {
            AboutScreenMaterial(state, actions)
            if (showAdvisors) {
                BrandDialogMaterial(
                    kind = BrandBannerKind.MAPLE,
                    title = stringResource(R.string.advisors_title),
                    lines = emptyList(),
                    onDismiss = { showAdvisors = false },
                ) {
                    AdvisorWallMaterial(initiallyExpanded = true)
                }
            }
        }
    }
}
