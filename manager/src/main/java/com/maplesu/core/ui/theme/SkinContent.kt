package com.maplesu.core.ui.theme

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.movableContentOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState

/** Native skin providers move this composition instead of recreating its navigation state. */
@Composable
internal fun rememberSkinContent(content: @Composable () -> Unit): @Composable () -> Unit {
    val currentContent by rememberUpdatedState(content)
    return remember { movableContentOf { currentContent() } }
}

/** The pager also moves between scaffolds whose current bottom insets are different. */
@Composable
internal fun <T> rememberSkinContentWithParameter(content: @Composable (T) -> Unit): @Composable (T) -> Unit {
    val currentContent by rememberUpdatedState(content)
    return remember { movableContentOf<T> { parameter -> currentContent(parameter) } }
}
