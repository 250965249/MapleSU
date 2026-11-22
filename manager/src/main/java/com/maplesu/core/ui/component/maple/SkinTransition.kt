package com.maplesu.core.ui.component.maple

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.isSpecified
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.Paint
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.draw
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.layer.GraphicsLayer
import androidx.compose.ui.graphics.layer.drawLayer
import androidx.compose.ui.graphics.rememberGraphicsLayer
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.PointerEventType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.toIntSize
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.theme.AppSettings
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.collectLatest
import kotlin.math.hypot
import kotlin.math.max
import kotlin.math.roundToInt

/** 过渡参数集中于此，装机目视后只改这里。 */
private object SkinTransitionTokens {
    /** 规范：主题切换 420ms。 */
    const val DURATION_MS = 420

    /** 新皮肤组合完成后再多等的帧数：首帧往往还在补布局，这段时间它被静止画面盖着。 */
    const val SETTLE_FRAMES = 3

    /** 揭开圆的羽化宽度。 */
    val FEATHER = 96.dp

    /** 进度过了这个比例，剩余的位图开始整体淡出，收尾更轻。 */
    const val FADE_FROM = 0.78f

    val Easing = CubicBezierEasing(0.3f, 0f, 0.1f, 1f)
}

/**
 * 外部请求的目标外观。[scene] 是额外的页面级开关（首次风格页是否已完成），
 * 它和皮肤走同一条过渡，`开始使用` 才能用同一个揭开进入首页。
 */
internal data class SkinRequest(
    val mode: UiMode,
    val settings: AppSettings,
    val scene: Boolean,
    val systemDark: Boolean = false,
)

/** 是否需要走位图过渡（纯函数）：皮肤、明暗、页面变化才需要，配色之类的小改动直接生效。 */
internal fun skinChangeNeedsTransition(
    applied: SkinRequest,
    requested: SkinRequest,
): Boolean {
    if (applied.mode != requested.mode || applied.scene != requested.scene) return true
    fun darkOf(request: SkinRequest): Boolean = request.settings.colorMode.let {
        it.isDark || (it.isSystem && request.systemDark)
    }
    return darkOf(applied) != darkOf(requested)
}

/**
 * 全局皮肤过渡层的状态。
 *
 * 界面读 [appliedMode] / [appliedSettings] / [appliedScene]，而不是 ViewModel 的最新值：
 * 请求到来时旧界面还在，先把它抓成位图盖住，再放行新值让界面重建。
 * 快照在新皮肤准备时保持视觉连续；真实帧耗时仍需装机采样。
 */
@Stable
class SkinTransitionState internal constructor(
    initial: SkinRequest,
    internal val layer: GraphicsLayer,
) {
    private var applied by mutableStateOf(initial)

    val appliedMode: UiMode get() = applied.mode
    val appliedSettings: AppSettings get() = applied.settings.let { settings ->
        val color = settings.colorMode
        if (!color.isSystem) settings else settings.copy(colorMode = when {
            color.isMonet && applied.systemDark -> com.maplesu.core.ui.theme.ColorMode.MONET_DARK
            color.isMonet -> com.maplesu.core.ui.theme.ColorMode.MONET_LIGHT
            applied.systemDark -> com.maplesu.core.ui.theme.ColorMode.DARK
            else -> com.maplesu.core.ui.theme.ColorMode.LIGHT
        })
    }
    val appliedScene: Boolean get() = applied.scene

    /** 位图还在屏幕上。开场动画、公告等要等它结束。 */
    var isRunning: Boolean by mutableStateOf(false)
        private set

    internal var snapshot: ImageBitmap? by mutableStateOf(null)
        private set
    internal val progress = Animatable(0f)

    /** 宿主内最近一次按下的位置，作为揭开圆心。 */
    internal var lastPress: Offset = Offset.Unspecified
    internal var origin: Offset = Offset.Unspecified
        private set

    internal suspend fun apply(request: SkinRequest, motionEnabled: Boolean) {
        if (request == applied) { clearSnapshot(); return }
        if (!skinChangeNeedsTransition(applied, request)) {
            clearSnapshot()
            applied = request
            return
        }
        val bitmap = if (motionEnabled) capture() else null
        if (bitmap == null) {
            clearSnapshot()
            applied = request
            return
        }

        isRunning = true
        origin = lastPress
        progress.snapTo(0f)
        // 位图和新值同一快照生效：盖上去的那一帧，底下才开始重建。
        snapshot = bitmap
        applied = request

        repeat(SkinTransitionTokens.SETTLE_FRAMES) { withFrameNanos { } }
        progress.animateTo(1f, tween(SkinTransitionTokens.DURATION_MS, easing = SkinTransitionTokens.Easing))
        clearSnapshot()
    }

    private fun clearSnapshot() {
        snapshot = null
        isRunning = false
    }

    /** 抓图失败（设备不支持、尺寸为零）只是少一段过渡，不影响切换本身。 */
    private suspend fun capture(): ImageBitmap? {
        if (layer.size.width <= 0 || layer.size.height <= 0) return null
        return try {
            layer.toImageBitmap()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Throwable) {
            android.util.Log.w("MapleSkinTransition", "capture failed, switching without transition", failure)
            null
        }
    }
}

val LocalSkinTransition = staticCompositionLocalOf<SkinTransitionState?> { null }

@Composable
fun rememberSkinTransitionState(
    mode: UiMode,
    settings: AppSettings,
    scene: Boolean,
): SkinTransitionState {
    val layer = rememberGraphicsLayer()
    val systemDark = isSystemInDarkTheme()
    val initial = remember { SkinRequest(mode, settings, scene, systemDark) }
    val state = remember(layer) { SkinTransitionState(initial, layer) }
    val motionEnabled = rememberMotionEnabled()

    val latestRequest by rememberUpdatedState(SkinRequest(mode, settings, scene, systemDark))
    val latestMotion by rememberUpdatedState(motionEnabled)
    LaunchedEffect(state) {
        // collectLatest：过渡中又点了另一个皮肤时立刻取消，下一次抓图连同未揭开的位图一起抓，
        // 画面不会跳。
        snapshotFlow { latestRequest to latestMotion }.collectLatest { (request, motion) ->
            state.apply(request, motion)
        }
    }
    return state
}

/**
 * 包住整棵界面的宿主：平时只多一个 RenderNode，过渡期间把位图画在内容之上。
 *
 * 必须放在 `KernelSUTheme` 之外，否则切皮肤时宿主自己也会被销毁。
 */
@Composable
fun SkinTransitionHost(
    state: SkinTransitionState,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Box(
        modifier = modifier
            .fillMaxSize()
            .pointerInput(state) {
                awaitPointerEventScope {
                    while (true) {
                        val event = awaitPointerEvent(PointerEventPass.Initial)
                        if (event.type == PointerEventType.Press) {
                            state.lastPress = event.changes.firstOrNull()?.position ?: state.lastPress
                        }
                    }
                }
            }
            .drawWithContent {
                val outer = this
                // DrawScope.record delegates Density back to this mutable draw scope. While
                // redirecting its canvas that becomes a self-reference on Compose 1.13.
                val recordingDensity = Density(density, fontScale)
                val recordingDirection = layoutDirection
                val recordingSize = size
                state.layer.record(recordingDensity, recordingDirection, recordingSize.toIntSize()) {
                    outer.draw(recordingDensity, recordingDirection, drawContext.canvas, recordingSize,
                        graphicsLayer = state.layer) {
                        outer.drawContent()
                        state.snapshot?.let { image ->
                            drawRevealingSnapshot(image, state.progress.value, state.origin)
                        }
                    }
                }
                drawLayer(state.layer)
            },
    ) {
        content()
    }
}

private fun DrawScope.drawRevealingSnapshot(image: ImageBitmap, progress: Float, origin: Offset) {
    val width = size.width
    val height = size.height
    val center = if (origin.isSpecified && origin.x in 0f..width && origin.y in 0f..height) {
        origin
    } else {
        Offset(width / 2f, height / 2f)
    }
    val feather = SkinTransitionTokens.FEATHER.toPx()
    val reach = hypot(max(center.x, width - center.x), max(center.y, height - center.y)) + feather
    val radius = (reach * progress).coerceAtLeast(1f)
    val fade = ((progress - SkinTransitionTokens.FADE_FROM) / (1f - SkinTransitionTokens.FADE_FROM)).coerceIn(0f, 1f)

    drawIntoCanvas { canvas ->
        canvas.saveLayer(Rect(Offset.Zero, size), Paint())
        drawImage(
            image = image,
            srcOffset = IntOffset.Zero,
            srcSize = IntSize(image.width, image.height),
            dstSize = IntSize(width.roundToInt(), height.roundToInt()),
            alpha = 1f - fade,
        )
        val solidUntil = ((radius - feather) / radius).coerceIn(0f, 0.999f)
        drawCircle(
            brush = Brush.radialGradient(
                colorStops = arrayOf(0f to Color.Black, solidUntil to Color.Black, 1f to Color.Transparent),
                center = center,
                radius = radius,
            ),
            radius = radius,
            center = center,
            blendMode = BlendMode.DstOut,
        )
        canvas.restore()
    }
}
