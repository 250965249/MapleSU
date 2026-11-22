package com.maplesu.core.ui

import androidx.compose.runtime.AbstractApplier
import androidx.compose.runtime.BroadcastFrameClock
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Composition
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.Recomposer
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.snapshots.Snapshot
import androidx.compose.runtime.staticCompositionLocalOf
import com.maplesu.core.ui.theme.rememberSkinContent
import com.maplesu.core.ui.theme.rememberSkinContentWithParameter
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test

/** Exercises real Compose movement without creating an Activity or touching a backend. */
class SkinContentIdentityTest {
    @Test fun nativeThemeAndScaffoldChangesRetainEntryIdentityAndUseLatestLocals() = runBlocking {
        val clock = BroadcastFrameClock()
        val recomposer = Recomposer(coroutineContext + clock)
        val runner = launch(clock) { recomposer.runRecomposeAndApplyChanges() }
        val composition = Composition(EmptyApplier(), recomposer)
        val mode = mutableIntStateOf(0)
        val callbackVersion = mutableIntStateOf(0)
        val homeVisible = mutableStateOf(false)
        var created = 0
        var disposed = 0
        var observedLocal = -1
        var observedCallback = -1
        var observedToken: Any? = null
        var frame = 0L
        suspend fun advance() {
            Snapshot.sendApplyNotifications()
            repeat(5) {
                yield()
                if (clock.hasAwaiters) clock.sendFrame(++frame * 16_666_667L)
                yield()
            }
        }
        try {
            composition.setContent {
                val currentMode = mode.intValue
                val currentCallback = callbackVersion.intValue
                val currentScene = homeVisible.value
                val scene = rememberSkinContent {
                    if (currentScene) {
                        val pager = rememberSkinContentWithParameter { inset: Int ->
                            val token = remember { created += 1; Any() }
                            val skin = LocalTestSkin.current
                            DisposableEffect(Unit) { onDispose { disposed += 1 } }
                            SideEffect {
                                observedToken = token
                                observedLocal = skin
                                observedCallback = inset
                            }
                        }
                        val navigation = rememberSkinContent {
                            when (currentMode) {
                                0 -> NativeScaffoldA { pager(currentCallback) }
                                else -> NativeScaffoldB { pager(currentCallback) }
                            }
                        }
                        when (currentMode) {
                            0 -> NativeScaffoldA { navigation() }
                            else -> NativeScaffoldB { navigation() }
                        }
                    }
                }
                when (currentMode) {
                    0 -> NativeThemeA { scene() }
                    else -> NativeThemeB { scene() }
                }
            }
            advance()
            assertEquals(0, created) // First-run preview does not start navigation.
            mode.intValue = 1
            advance()
            assertEquals(0, created)
            homeVisible.value = true
            advance()
            assertEquals(1, created)
            val token = observedToken
            assertEquals(1, observedLocal)
            repeat(4) { index ->
                mode.intValue = index % 2
                callbackVersion.intValue = index + 1
                advance()
                assertSame(token, observedToken)
                assertEquals(1, created)
                assertEquals(0, disposed)
                assertEquals(index % 2, observedLocal)
                assertEquals(index + 1, observedCallback)
            }
        } finally {
            composition.dispose()
            recomposer.cancel()
            runner.cancelAndJoin()
        }
        assertEquals(1, disposed)
    }
}

private val LocalTestSkin = staticCompositionLocalOf { -1 }
@Composable private fun NativeThemeA(content: @Composable () -> Unit) = CompositionLocalProvider(LocalTestSkin provides 0, content = content)
@Composable private fun NativeThemeB(content: @Composable () -> Unit) = CompositionLocalProvider(LocalTestSkin provides 1, content = content)
@Composable private fun NativeScaffoldA(content: @Composable () -> Unit) = content()
@Composable private fun NativeScaffoldB(content: @Composable () -> Unit) = content()

private class EmptyApplier : AbstractApplier<Unit>(Unit) {
    override fun insertTopDown(index: Int, instance: Unit) = Unit
    override fun insertBottomUp(index: Int, instance: Unit) = Unit
    override fun remove(index: Int, count: Int) = Unit
    override fun move(from: Int, to: Int, count: Int) = Unit
    override fun onClear() = Unit
}
