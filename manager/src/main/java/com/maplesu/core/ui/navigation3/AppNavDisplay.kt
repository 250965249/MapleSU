package com.maplesu.core.ui.navigation3

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.CompositingStrategy
import androidx.compose.ui.graphics.graphicsLayer
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import top.yukonga.miuix.kmp.nav.core.NavBackStack
import top.yukonga.miuix.kmp.nav.core.NavDisplay
import top.yukonga.miuix.kmp.nav.core.NavDisplayEffects
import top.yukonga.miuix.kmp.nav.core.NavEntryBuilder
import top.yukonga.miuix.kmp.nav.transition.NavTransition
import top.yukonga.miuix.kmp.nav.transition.NavTransitionScope
import top.yukonga.miuix.kmp.nav.transition.NavTransitions
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** Keep transparent destinations from blending with the retained page underneath them. */
@Composable
fun AppNavDisplay(
    backStack: NavBackStack,
    effects: NavDisplayEffects = NavDisplayEffects(),
    onBack: () -> Unit,
    content: NavEntryBuilder.() -> Unit,
) {
    val translucent = when (LocalUiMode.current) {
        UiMode.Material -> MaterialTheme.colorScheme.background.alpha < 1f
        UiMode.Miuix -> MiuixTheme.colorScheme.background.alpha < 1f
    }
    NavDisplay(
        backStack = backStack,
        // Src replaces covered pages, including transparent pixels. Isolate the navigation
        // surface so those pixels reveal the single wallpaper host instead of erasing it.
        modifier = Modifier.graphicsLayer {
            compositingStrategy = if (translucent) CompositingStrategy.Offscreen else CompositingStrategy.Auto
        },
        transition = if (translucent) TranslucentPageTransition else NavTransitions.MiuixDefault,
        effects = effects,
        onBack = onBack,
        content = content,
    )
}

private object TranslucentPageTransition : NavTransition by NavTransitions.MiuixDefault {
    override fun Modifier.transformEntry(scope: NavTransitionScope): Modifier =
        with(NavTransitions.MiuixDefault) { transformEntry(scope) }.graphicsLayer {
            compositingStrategy = CompositingStrategy.Offscreen
            blendMode = BlendMode.Src
        }
}
