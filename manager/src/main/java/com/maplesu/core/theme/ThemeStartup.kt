package com.maplesu.core.theme

import androidx.compose.runtime.*
import kotlinx.coroutines.flow.collectLatest

private class ThemeStartupState {
    val resources = mutableStateMapOf<Any, Boolean>()
    var released = false
}

private val LocalThemeStartup = staticCompositionLocalOf<ThemeStartupState?> { null }

/** Keep the system splash until the selected appearance, including terminal fallbacks, commits. */
@Composable
internal fun ThemeStartupHost(onReady: () -> Unit, content: @Composable () -> Unit) {
    val startup = remember { ThemeStartupState() }
    val ready by rememberUpdatedState(onReady)
    LaunchedEffect(startup) {
        snapshotFlow { startup.resources.toMap() }.collectLatest { resources ->
            if (!startup.released && resources.values.all { it }) {
                // Let subcomposed content register and the decoded state reach composition.
                repeat(2) { withFrameNanos { } }
                if (startup.resources.values.all { it }) {
                    startup.released = true
                    startup.resources.clear()
                    ready()
                }
            }
        }
    }
    CompositionLocalProvider(LocalThemeStartup provides startup, content = content)
}

/** A failed decode is ready too; cancellation/disposal must never leave a launch blocker. */
@Composable
internal fun ThemeStartupResource(loaded: Boolean) {
    val startup = LocalThemeStartup.current ?: return
    if (startup.released) return
    val token = remember(startup) { Any() }
    DisposableEffect(startup, token) {
        startup.resources[token] = loaded
        onDispose { startup.resources.remove(token) }
    }
    SideEffect { if (!startup.released) startup.resources[token] = loaded }
}
