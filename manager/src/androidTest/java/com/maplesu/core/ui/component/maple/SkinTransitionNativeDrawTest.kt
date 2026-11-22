package com.maplesu.core.ui.component.maple

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.MotionDurationScale
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.graphics.rememberGraphicsLayer
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.theme.AppSettings
import com.maplesu.core.ui.theme.ColorMode
import com.maplesu.core.ui.theme.KernelSUTheme
import com.maplesu.core.ui.theme.LocalColorMode
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/** Native Canvas/RenderNode regression: an empty composition never exercises density recursion. */
@OptIn(ExperimentalTestApi::class)
@RunWith(Parameterized::class)
class SkinTransitionNativeDrawTest(private val initialMode: UiMode) {
    @get:Rule val compose = createComposeRule()

    private val settings = AppSettings(
        ColorMode.LIGHT,
        0xff6750a4.toInt(),
        PaletteStyle.TonalSpot,
        ColorSpec.SpecVersion.SPEC_2025,
    )
    private val revision = mutableIntStateOf(0)
    private val requestedAppearance = mutableStateOf(SkinRequest(initialMode, settings, false))
    private val completedDraws = AtomicInteger()
    private val lastDraw = AtomicReference<DrawResult?>()
    private lateinit var skin: SkinTransitionState
    private lateinit var scope: CoroutineScope
    private var transition: Job? = null
    private val motionScale = object : MotionDurationScale { override val scaleFactor = 1f }
    private val otherMode get() = if (initialMode == UiMode.Miuix) UiMode.Material else UiMode.Miuix

    @Test fun firstFrameAndRepeatedInvalidationsCompleteDensityDependentDrawing() {
        render()
        assertDrawn(initialMode, scene = false)
        repeat(6) { index ->
            val before = completedDraws.get()
            compose.runOnIdle { revision.intValue = index + 1 }
            compose.mainClock.advanceTimeByFrame()
            assertDrawn(initialMode, scene = false)
            assertTrue("invalidated child must finish another native draw", completedDraws.get() > before)
        }
    }

    @Test fun skinAndSceneChangesCaptureRevealAndReleaseTheNativeSnapshot() {
        render()
        assertDrawn(initialMode, scene = false)
        for ((mode, scene) in listOf(otherMode to false, otherMode to true, initialMode to true, initialMode to false)) {
            val job = beginTransition(mode, scene)
            compose.mainClock.advanceTimeBy(80)
            assertDrawn(mode, scene, checkPixels = false)
            finishTransition(job)
            assertDrawn(mode, scene)
        }
    }

    @Test fun rapidSkinAndSceneRequestsKeepDrawingAndFinishWithTheLatestContent() {
        render()
        assertDrawn(initialMode, scene = false)
        val jobs = mutableListOf<Job>()
        for ((mode, scene) in listOf(otherMode to true, initialMode to false, otherMode to false, initialMode to true)) {
            jobs += beginTransition(mode, scene)
            compose.mainClock.advanceTimeBy(80)
            assertDrawn(mode, scene, checkPixels = false)
        }
        finishTransition(jobs.last())
        assertTrue("superseded reveal jobs must be cancelled", jobs.dropLast(1).all { it.isCancelled })
        assertDrawn(initialMode, scene = true)
        compose.runOnIdle { revision.intValue += 1 }
        compose.mainClock.advanceTimeByFrame()
        assertDrawn(initialMode, scene = true)
    }

    @Test fun lightDarkAndSystemAppearanceChangesFinishDrawingWithResolvedColors() {
        render()
        for (request in listOf(
            SkinRequest(initialMode, settings.copy(colorMode = ColorMode.DARK), false),
            SkinRequest(initialMode, settings, false),
            SkinRequest(initialMode, settings.copy(colorMode = ColorMode.SYSTEM), false, systemDark = true),
            SkinRequest(initialMode, settings.copy(colorMode = ColorMode.SYSTEM), false, systemDark = false),
            SkinRequest(initialMode, settings.copy(colorMode = ColorMode.MONET_SYSTEM), false, systemDark = true),
            SkinRequest(initialMode, settings.copy(colorMode = ColorMode.MONET_SYSTEM), false, systemDark = false),
        )) {
            val resolved = resolvedColorMode(request)
            val job = beginTransition(request.mode, request.scene, request.settings, request.systemDark)
            compose.mainClock.advanceTimeBy(80)
            assertDrawn(request.mode, request.scene, checkPixels = false, colorMode = resolved)
            finishTransition(job)
            assertDrawn(request.mode, request.scene, colorMode = resolved)
        }
    }

    @Test fun rapidDarkSkinAndSceneChangesDrawTheLatestResolvedAppearance() {
        render()
        val requests = listOf(
            SkinRequest(initialMode, settings.copy(colorMode = ColorMode.DARK), false),
            SkinRequest(otherMode, settings, true),
            SkinRequest(initialMode, settings.copy(colorMode = ColorMode.MONET_SYSTEM), false, systemDark = true),
            SkinRequest(otherMode, settings.copy(colorMode = ColorMode.SYSTEM), true, systemDark = false),
            SkinRequest(initialMode, settings.copy(colorMode = ColorMode.DARK), true),
        )
        val jobs = requests.map { request ->
            val job = beginTransition(request.mode, request.scene, request.settings, request.systemDark)
            compose.mainClock.advanceTimeBy(80)
            assertDrawn(request.mode, request.scene, checkPixels = false, colorMode = resolvedColorMode(request))
            job
        }
        finishTransition(jobs.last())
        assertTrue("superseded color reveals must be cancelled", jobs.dropLast(1).all { it.isCancelled })
        assertDrawn(initialMode, scene = true, colorMode = ColorMode.DARK)
    }

    @Test fun rememberedRequestCollectorResolvesRapidLightDarkAndSceneChanges() {
        render(rememberRequests = true)
        assertDrawn(initialMode, scene = false)
        for (request in listOf(
            SkinRequest(initialMode, settings.copy(colorMode = ColorMode.DARK), false),
            SkinRequest(otherMode, settings, true),
            SkinRequest(initialMode, settings.copy(colorMode = ColorMode.DARK), true),
            SkinRequest(initialMode, settings, false),
        )) {
            compose.runOnIdle { requestedAppearance.value = request }
            compose.mainClock.advanceTimeByFrame()
            compose.waitUntil(timeoutMillis = 5_000) {
                skin.appliedMode == request.mode && skin.appliedScene == request.scene &&
                    skin.appliedSettings.colorMode == request.settings.colorMode
            }
            compose.mainClock.advanceTimeBy(80)
            assertDrawn(request.mode, request.scene, checkPixels = false, colorMode = request.settings.colorMode)
        }
        compose.mainClock.advanceTimeBy(1_000)
        compose.waitUntil(timeoutMillis = 5_000) { !skin.isRunning }
        compose.runOnIdle { assertNull("collector must release the last snapshot", skin.snapshot) }
        assertDrawn(initialMode, scene = false)
    }

    private fun render(rememberRequests: Boolean = false) {
        compose.mainClock.autoAdvance = false
        compose.setContent {
            val host = if (rememberRequests) {
                val request = requestedAppearance.value
                rememberSkinTransitionState(request.mode, request.settings, request.scene)
            } else {
                val layer = rememberGraphicsLayer()
                remember { SkinTransitionState(SkinRequest(initialMode, settings, false), layer) }
            }
            val coroutineScope = rememberCoroutineScope()
            SideEffect { skin = host; scope = coroutineScope }
            SkinTransitionHost(host, Modifier.testTag(HOST_TAG)) {
                val mode = host.appliedMode
                val scene = host.appliedScene
                val colorMode = host.appliedSettings.colorMode
                CompositionLocalProvider(
                    LocalUiMode provides mode,
                    LocalSkinTransition provides host,
                    LocalColorMode provides host.appliedSettings.colorMode.value,
                ) {
                    KernelSUTheme(host.appliedSettings, mode) {
                        Column(
                            Modifier.fillMaxSize().background(if (colorMode.isDark) Color.Black else Color.White)
                                .drawWithContent {
                                    drawContent()
                                    // Read density AFTER drawing descendants, inside the recorded layer.
                                    val dpPixels = 24.dp.toPx()
                                    val spPixels = 18.sp.toPx()
                                    val frame = revision.intValue
                                    drawRect(marker(mode, scene, colorMode.isDark), size = Size(dpPixels, dpPixels))
                                    lastDraw.set(DrawResult(mode, scene, colorMode, frame, dpPixels, spPixels))
                                    completedDraws.incrementAndGet()
                                }
                                .padding(32.dp),
                        ) {
                            BasicText(
                                "${mode.value} / ${colorMode.name} / ${if (scene) "home" else "preview"} / ${revision.intValue}",
                                style = TextStyle(color = if (colorMode.isDark) Color.White else Color.Black, fontSize = 18.sp),
                            )
                        }
                    }
                }
            }
        }
        compose.mainClock.advanceTimeByFrame()
        compose.waitForIdle()
    }

    private fun beginTransition(
        mode: UiMode,
        scene: Boolean,
        requestedSettings: AppSettings = settings,
        systemDark: Boolean = false,
    ): Job {
        lateinit var job: Job
        compose.runOnIdle {
            val previous = transition
            job = scope.launch(motionScale) {
                previous?.cancelAndJoin()
                // Exercise the actual bitmap path even when device animations are disabled.
                skin.apply(SkinRequest(mode, requestedSettings, scene, systemDark), motionEnabled = true)
            }
            transition = job
        }
        compose.waitUntil(timeoutMillis = 5_000) {
            skin.appliedMode == mode && skin.appliedScene == scene &&
                skin.appliedSettings.colorMode == resolvedColorMode(SkinRequest(mode, requestedSettings, scene, systemDark)) &&
                skin.isRunning && skin.snapshot != null
        }
        compose.runOnIdle {
            assertNotNull("transition must capture a real native layer", skin.snapshot)
            assertTrue("reveal must still be running before advancing its clock", job.isActive)
        }
        return job
    }

    private fun finishTransition(job: Job) {
        compose.mainClock.advanceTimeBy(1_000)
        compose.waitUntil(timeoutMillis = 5_000) { job.isCompleted && !skin.isRunning }
        compose.runOnIdle {
            assertFalse("latest reveal must complete, not be cancelled", job.isCancelled)
            assertNull("completed reveal must release its bitmap", skin.snapshot)
        }
    }

    private fun assertDrawn(mode: UiMode, scene: Boolean, checkPixels: Boolean = true, colorMode: ColorMode = ColorMode.LIGHT) {
        val host = compose.onNodeWithTag(HOST_TAG).assertIsDisplayed()
        val bitmap = host.captureToImage().asAndroidBitmap()
        val result = lastDraw.get()
        assertNotNull("density-dependent draw must return normally", result)
        assertEquals(mode, result!!.mode)
        assertEquals(scene, result.scene)
        assertEquals(colorMode, result.colorMode)
        assertEquals(revision.intValue, result.revision)
        assertTrue("dp conversion must remain finite and positive", result.dpPixels.isFinite() && result.dpPixels > 0)
        assertTrue("sp conversion must remain finite and positive", result.spPixels.isFinite() && result.spPixels > 0)
        assertTrue("native layer capture must contain pixels", bitmap.width > 8 && bitmap.height > 8)
        if (checkPixels) assertEquals("latest content must reach the native canvas", marker(mode, scene, colorMode.isDark).toArgb(), bitmap.getPixel(4, 4))
    }

    private fun marker(mode: UiMode, scene: Boolean, dark: Boolean): Color = when (mode) {
        UiMode.Miuix -> if (dark) {
            if (scene) Color(0xffffab40) else Color(0xff69f0ae)
        } else if (scene) Color(0xffe65100) else Color(0xff1b5e20)
        UiMode.Material -> if (dark) {
            if (scene) Color(0xffea80fc) else Color(0xff82b1ff)
        } else if (scene) Color(0xff6a1b9a) else Color(0xff0d47a1)
    }

    private fun resolvedColorMode(request: SkinRequest): ColorMode = when (request.settings.colorMode) {
        ColorMode.SYSTEM -> if (request.systemDark) ColorMode.DARK else ColorMode.LIGHT
        ColorMode.MONET_SYSTEM -> if (request.systemDark) ColorMode.MONET_DARK else ColorMode.MONET_LIGHT
        else -> request.settings.colorMode
    }

    private data class DrawResult(val mode: UiMode, val scene: Boolean, val colorMode: ColorMode, val revision: Int, val dpPixels: Float, val spPixels: Float)

    companion object {
        private const val HOST_TAG = "skin-transition-native-host"

        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        fun skins(): Collection<Array<Any>> = UiMode.entries.map { arrayOf<Any>(it) }
    }
}
