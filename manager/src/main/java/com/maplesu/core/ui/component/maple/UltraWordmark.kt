package com.maplesu.core.ui.component.maple

import android.graphics.Paint
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.tween
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Canvas
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.graphics.drawscope.CanvasDrawScope
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.clipRect
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.text.drawText
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.LayoutDirection
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.currentStateAsState
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlin.math.PI
import kotlin.math.pow
import kotlin.math.roundToInt
import kotlin.math.sin

/** 组合内的字样全部用这串文字；`Ultra` 单独成段，才能分开上色与展开。 */
internal const val ULTRA_WORD = "Ultra"

/**
 * 字样的运行状态：[visible] 决定是否出现，动画进度只在绘制阶段读取。
 *
 * [reveal] 由 0 到 1 走完开场；[time] 是持续流动用的累计秒数，页面不可见时停在原值，
 * 回来后接着流动，不会跳变。
 */
@Stable
class UltraWordmarkState internal constructor(revealed: Boolean) {
    var visible: Boolean by mutableStateOf(false)
        internal set

    internal val reveal = Animatable(if (revealed) 1f else 0f)
    internal val time = mutableFloatStateOf(0f)
}

/**
 * @param visible [shouldShowUltraBrand] 的结果；变为 false 时字样立刻消失，不做退场
 * @param foreground 首页是否正是当前页面
 */
@Composable
fun rememberUltraWordmarkState(visible: Boolean, foreground: Boolean): UltraWordmarkState {
    val session = LocalBrandSession.current
    val transition = LocalSkinTransition.current
    val motionEnabled = rememberMotionEnabled()
    val state = remember { UltraWordmarkState(revealed = session.introPlayed) }
    SideEffect { state.visible = visible }

    val lifecycleState by LocalLifecycleOwner.current.lifecycle.currentStateAsState()
    val ticking = visible && foreground && motionEnabled && lifecycleState.isAtLeast(Lifecycle.State.RESUMED)
    LaunchedEffect(visible, motionEnabled, ticking) {
        if (!visible) return@LaunchedEffect
        if (session.introPlayed || !motionEnabled) {
            state.reveal.snapTo(1f)
            session.introPlayed = true
            return@LaunchedEffect
        }
        if (!ticking) return@LaunchedEffect
        // 切页或离开 RESUMED 时此 effect 会取消；Animatable 保留当前进度，回来接着播。
        snapshotFlow { transition?.isRunning != true }.first { it }
        if (state.reveal.value == 0f) delay(UltraBrandTokens.INTRO_HOLD_MS)
        val remainingMs = (UltraBrandTokens.INTRO_DURATION_MS * (1f - state.reveal.value))
            .roundToInt().coerceAtLeast(1)
        state.reveal.animateTo(
            targetValue = 1f,
            animationSpec = tween(remainingMs, easing = LinearEasing),
        )
        session.introPlayed = true
    }

    LaunchedEffect(ticking) {
        if (ticking) runBrandClock(state.time)
    }
    return state
}

/** 开场时间线：线性进度映射到像素波位置，波头的速度曲线集中在这里。 */
internal object UltraIntroTimeline {
    private val SweepEasing = CubicBezierEasing(0.32f, 0f, 0.24f, 1f)

    fun front(progress: Float, start: Float, end: Float): Float =
        start + (end - start) * SweepEasing.transform(progress.coerceIn(0f, 1f))

    /** 辉光在 `Ultra` 展开后段轻微过冲，再回落到常驻亮度。 */
    fun bloomBump(progress: Float): Float {
        val t = ((progress - 0.45f) / 0.55f).coerceIn(0f, 1f)
        return sin(PI.toFloat() * t)
    }
}

/**
 * 一处字样的绘制器。大标题和折叠标题各持一份，网格缓存互不打扰。
 *
 * 绘制顺序：氛围光 → 点阵 → 辉光贴图 → 字（含字母内亮斑）。
 * Material 皮肤传 [bloom] = false：没有氛围光和辉光，点阵不做柔边。
 */
internal class UltraWordmarkRenderer(
    private val palette: UltraBrandPalette,
    private val bloom: Boolean,
) {
    private val field = UltraPixelField(
        cells = palette.cells,
        gain = palette.cellGain,
        ceiling = palette.cellCeiling,
        antiAlias = bloom,
        softRows = bloom,
    )
    private val sparks = UltraLetterSparks(palette.spark)
    private val layerPaint = Paint()

    private var glow: ImageBitmap? = null
    private var glowSource: TextLayoutResult? = null
    private var glowMargin = 0f

    private var wordBrush: Brush? = null
    private var wordBrushWidth = -1f

    private var ambient: Brush? = null
    private var ambientRadius = -1f

    /**
     * 所有坐标都是当前 DrawScope 的像素。
     *
     * @param reveal 开场进度
     * @param time 累计秒数
     * @param alpha 随滚动变化的整体不透明度
     * @param intensity 点阵亮度倍率
     */
    fun DrawScope.drawWordmark(
        word: TextLayoutResult,
        wordLeft: Float,
        wordTop: Float,
        fieldLeft: Float,
        fieldTop: Float,
        fieldWidth: Float,
        pitchPx: Int,
        cellPx: Int,
        rows: Int,
        fadeEnd: Boolean,
        reveal: Float,
        time: Float,
        alpha: Float,
        intensity: Float,
    ) {
        if (reveal <= 0f || alpha <= 0f) return
        val pxPerDp = density
        val wordWidth = word.size.width.toFloat()
        val wordHeight = word.size.height.toFloat()
        val settled = reveal >= 1f

        val fieldRight = fieldLeft + fieldWidth
        val front = if (settled) {
            NO_SWEEP_FRONT
        } else {
            val tail = (UltraBrandTokens.SWEEP_CREST + UltraBrandTokens.SWEEP_SETTLE).toPx()
            UltraIntroTimeline.front(reveal, fieldLeft - UltraBrandTokens.SWEEP_CREST.toPx(), fieldRight + tail)
        }
        val wordProgress = if (settled) {
            1f
        } else {
            ((front - wordLeft) / wordWidth).coerceIn(0f, 1f)
        }
        val canvas = drawContext.canvas.nativeCanvas

        if (bloom) drawAmbient(fieldRight, fieldTop, rows * pitchPx.toFloat(), reveal, time, alpha)

        if (fieldWidth >= UltraBrandTokens.FIELD_MIN_WIDTH.toPx()) {
            with(field) {
                draw(
                    canvas = canvas,
                    left = fieldLeft,
                    top = fieldTop,
                    width = fieldWidth,
                    pitchPx = pitchPx,
                    cellPx = cellPx,
                    rowCount = rows,
                    pxPerDp = pxPerDp,
                    time = time,
                    frontPx = front,
                    holeStart = wordLeft - pitchPx,
                    holeEnd = wordLeft + wordWidth + pitchPx,
                    intensity = intensity,
                    alpha = alpha,
                    fadeEnd = fadeEnd,
                )
            }
        }
        if (wordProgress <= 0f) return

        val eased = 1f - (1f - wordProgress).pow(3)
        val slide = -UltraBrandTokens.WORD_SLIDE.toPx() * (1f - eased)
        val clipRight = wordLeft + wordWidth * wordProgress
        val strength = eased * (1f + UltraBrandTokens.BLOOM_OVERSHOOT * UltraIntroTimeline.bloomBump(reveal))

        if (bloom) {
            val image = glowFor(word, this)
            val margin = glowMargin
            clipRect(
                left = wordLeft - margin,
                top = wordTop - margin,
                right = if (settled) wordLeft + wordWidth + margin else clipRight + margin * 0.4f,
                bottom = wordTop + wordHeight + margin,
            ) {
                drawImage(
                    image = image,
                    topLeft = Offset(wordLeft - margin + slide, wordTop - margin),
                    alpha = (palette.bloomAlpha * strength * alpha).coerceIn(0f, 1f),
                )
            }
        }

        layerPaint.alpha = (alpha * 255f).roundToInt().coerceIn(0, 255)
        val checkpoint = canvas.saveLayer(
            wordLeft - pitchPx,
            wordTop,
            wordLeft + wordWidth + pitchPx,
            wordTop + wordHeight,
            layerPaint,
        )
        clipRect(left = wordLeft - pitchPx, right = if (settled) wordLeft + wordWidth + pitchPx else clipRight) {
            drawText(
                textLayoutResult = word,
                brush = brushFor(wordWidth),
                topLeft = Offset(wordLeft + slide, wordTop),
            )
            sparks.draw(
                canvas = canvas,
                left = wordLeft,
                top = wordTop,
                width = wordWidth,
                height = wordHeight,
                pitchPx = (UltraBrandTokens.LETTER_PITCH.toPx()).roundToInt().coerceAtLeast(2),
                cellPx = (UltraBrandTokens.LETTER_CELL.toPx()).roundToInt().coerceAtLeast(1),
                pxPerDp = pxPerDp,
                time = time,
                strength = UltraBrandTokens.LETTER_SPARK_GAIN,
            )
        }
        canvas.restoreToCount(checkpoint)
    }

    private fun brushFor(width: Float): Brush {
        val cached = wordBrush
        if (cached != null && wordBrushWidth == width) return cached
        return Brush.linearGradient(
            colors = listOf(palette.wordStart, palette.wordEnd),
            start = Offset.Zero,
            end = Offset(width, 0f),
        ).also {
            wordBrush = it
            wordBrushWidth = width
        }
    }

    private fun DrawScope.drawAmbient(
        fieldRight: Float,
        fieldTop: Float,
        fieldHeight: Float,
        reveal: Float,
        time: Float,
        alpha: Float,
    ) {
        val presence = ((reveal - 0.5f) / 0.5f).coerceIn(0f, 1f)
        if (presence <= 0f) return
        val radius = fieldHeight * 0.95f
        val brush = ambient?.takeIf { ambientRadius == radius } ?: Brush.radialGradient(
            colors = listOf(palette.bloom, Color.Transparent),
            center = Offset.Zero,
            radius = radius,
        ).also {
            ambient = it
            ambientRadius = radius
        }
        val breath = 0.76f + 0.24f * sin(2f * PI.toFloat() * time / UltraBrandTokens.AMBIENT_BREATH_SECONDS)
        translate(left = fieldRight - radius, top = fieldTop + fieldHeight / 2f) {
            scale(scaleX = 3f, scaleY = 1f, pivot = Offset.Zero) {
                drawCircle(
                    brush = brush,
                    radius = radius,
                    center = Offset.Zero,
                    alpha = palette.ambientAlpha * breath * presence * alpha,
                )
            }
        }
    }

    /** 辉光贴图只在第一次需要时烘一次：软件画布模糊一回，之后每帧只是贴图。 */
    private fun glowFor(word: TextLayoutResult, density: Density): ImageBitmap {
        val cached = glow
        if (cached != null && glowSource === word) return cached
        val wide = with(density) { UltraBrandTokens.BLOOM_WIDE.toPx() }
        val near = with(density) { UltraBrandTokens.BLOOM_NEAR.toPx() }
        val margin = wide * 2.4f
        val width = (word.size.width + margin * 2f).roundToInt().coerceAtLeast(1)
        val height = (word.size.height + margin * 2f).roundToInt().coerceAtLeast(1)
        val image = ImageBitmap(width, height)
        CanvasDrawScope().draw(
            density = density,
            layoutDirection = LayoutDirection.Ltr,
            canvas = Canvas(image),
            size = Size(width.toFloat(), height.toFloat()),
        ) {
            val origin = Offset(margin, margin)
            drawText(word, color = palette.bloom, topLeft = origin, shadow = Shadow(palette.bloom, Offset.Zero, wide))
            drawText(word, color = palette.bloom, topLeft = origin, shadow = Shadow(palette.bloom, Offset.Zero, near))
        }
        glow = image
        glowSource = word
        glowMargin = margin
        return image
    }
}
