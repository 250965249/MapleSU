package com.maplesu.core.ui.component

import android.content.res.Configuration
import android.graphics.Bitmap
import android.os.SystemClock
import android.view.MotionEvent
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.swipeUp
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.theme.AppSettings
import com.maplesu.core.ui.theme.ColorMode
import com.maplesu.core.ui.theme.KernelSUTheme
import com.maplesu.core.ui.theme.LocalColorMode
import com.maplesu.core.ui.theme.LocalEnableBlur
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

@RunWith(Parameterized::class)
class T3DialogRenderTest(private val mode: UiMode, private val dark: Boolean) {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test
    fun longNoticeScrollsWhileConfirmationStaysVisible() {
        val visible = mutableStateOf(true)
        var dismisses = 0
        render {
            if (visible.value) {
                T3NoticeDialog(
                    title = "MapleSU 公告",
                    content = (1..80).joinToString("\n") { "第 $it 行：这是用于验证长公告滚动的正文。" },
                    publishedAt = "2026-11-14 12:30",
                    onDismiss = { dismisses++; visible.value = false },
                )
            }
        }
        compose.onNodeWithText("MapleSU 公告").assertIsDisplayed()
        compose.onNodeWithText("2026-11-14 12:30").assertIsDisplayed()
        compose.onNodeWithTag("t3NoticeConfirm").assertIsDisplayed()
        val banner = compose.onNodeWithTag("t3NoticeBanner")
        val bannerBounds = if (compose.activity.resources.configuration.screenHeightDp >= 520) {
            banner.assertIsDisplayed().fetchSemanticsNode().boundsInWindow.also { bounds ->
                val titleBounds = compose.onNodeWithText("MapleSU 公告").fetchSemanticsNode().boundsInWindow
                assertTrue("Banner precedes the notice title", bounds.bottom <= titleBounds.top)
                assertEquals("Banner and title share the center", titleBounds.center.x, bounds.center.x, 1f)
            }
        } else {
            banner.assertDoesNotExist()
            null
        }
        saveScreenshot("notice")
        val body = compose.onNodeWithTag("t3NoticeContent")
        val scroll = body.fetchSemanticsNode().config[SemanticsProperties.VerticalScrollAxisRange]
        assertTrue("Long notice has a scrollable viewport", scroll.maxValue() > 0f)
        body.performTouchInput { swipeUp() }
        compose.runOnIdle { assertTrue("Notice body moved", scroll.value() > 0f) }
        if (bannerBounds != null) {
            assertEquals("Banner stays above the scrolling body", bannerBounds,
                banner.assertIsDisplayed().fetchSemanticsNode().boundsInWindow)
        }
        compose.onNodeWithTag("t3NoticeConfirm").assertIsDisplayed().performClick()
        compose.onNodeWithText("MapleSU 公告").assertDoesNotExist()
        compose.runOnIdle { assertEquals(1, dismisses) }
    }

    @Test
    fun compactWindowOmitsBannerAndKeepsNoticeActions() {
        render {
            val compact = Configuration(LocalConfiguration.current).apply { screenHeightDp = 480 }
            CompositionLocalProvider(LocalConfiguration provides compact) {
                T3NoticeDialog(title = "MapleSU 公告", content = "公告正文", onDismiss = {})
            }
        }
        compose.onNodeWithTag("t3NoticeBanner").assertDoesNotExist()
        compose.onNodeWithText("MapleSU 公告").assertIsDisplayed()
        compose.onNodeWithText("公告正文").assertIsDisplayed()
        compose.onNodeWithTag("t3NoticeConfirm").assertIsDisplayed()
    }

    @Test
    fun disabledDialogSurvivesOutsideTapAndBackAndReflectsCountdown() {
        val seconds = mutableIntStateOf(3)
        render { T3DisabledDialog(seconds.intValue) }
        compose.onNodeWithText("当前版本已被禁用，将在 3s 内退出").assertIsDisplayed()
        compose.onNodeWithTag("t3NoticeBanner").assertDoesNotExist()
        compose.onNodeWithTag("t3NoticeConfirm").assertDoesNotExist()

        // Send a real screen event so Material's separate dialog window receives the outside tap.
        val bounds = compose.onNodeWithTag("t3Fixture").fetchSemanticsNode().boundsInWindow
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val now = SystemClock.uptimeMillis()
        listOf(MotionEvent.ACTION_DOWN, MotionEvent.ACTION_UP).forEach { action ->
            val event = MotionEvent.obtain(now, SystemClock.uptimeMillis(), action,
                bounds.left + 4f, bounds.center.y, 0)
            try {
                instrumentation.sendPointerSync(event)
            } finally {
                event.recycle()
            }
        }
        compose.waitForIdle()
        compose.onNodeWithTag("t3DisabledMessage").assertIsDisplayed()
        compose.runOnIdle { compose.activity.onBackPressedDispatcher.onBackPressed() }
        compose.onNodeWithTag("t3DisabledMessage").assertIsDisplayed()
        compose.runOnIdle { seconds.intValue = 2 }
        compose.onNodeWithText("当前版本已被禁用，将在 2s 内退出").assertIsDisplayed()
        saveScreenshot("disabled")
        compose.runOnIdle { seconds.intValue = 0 }
        compose.onNodeWithText("当前版本已被禁用，将在 0s 内退出").assertIsDisplayed()
    }

    private fun saveScreenshot(kind: String) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val bitmap = instrumentation.uiAutomation.takeScreenshot() ?: return
        try {
            val output = File(instrumentation.targetContext.getExternalFilesDir(null),
                "t3-$kind-${mode.name}-${if (dark) "dark" else "light"}.png")
            output.outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
        } finally {
            bitmap.recycle()
        }
    }

    private fun render(content: @Composable () -> Unit) {
        compose.setContent {
            CompositionLocalProvider(
                LocalUiMode provides mode,
                LocalColorMode provides if (dark) ColorMode.DARK.value else ColorMode.LIGHT.value,
                LocalEnableBlur provides false,
            ) {
                KernelSUTheme(
                    AppSettings(if (dark) ColorMode.DARK else ColorMode.LIGHT,
                        0xff6750a4.toInt(), PaletteStyle.TonalSpot, ColorSpec.SpecVersion.SPEC_2025),
                    mode,
                ) {
                    // MainActivity's startup/disabled dialogs sit outside its navigation Scaffold.
                    Box(Modifier.fillMaxSize().testTag("t3Fixture")) { content() }
                }
            }
        }
    }

    companion object {
        @JvmStatic @Parameterized.Parameters(name = "{0}-dark{1}")
        fun parameters(): List<Array<Any>> = UiMode.entries.flatMap { mode ->
            listOf(false, true).map { dark -> arrayOf<Any>(mode, dark) }
        }
    }
}
