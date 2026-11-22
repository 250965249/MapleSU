package com.maplesu.core.ui.component.maple

import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.PorterDuff
import android.graphics.PorterDuffXfermode
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.floor
import kotlin.math.pow
import kotlin.math.sin
import kotlin.random.Random

private const val LUT_SIZE = 1024
private const val LUT_MASK = LUT_SIZE - 1

/** 0..1 的正弦表：一条顶栏上千个格子每帧都要算，查表没有分配也没有 double 运算。 */
private val WaveLut = FloatArray(LUT_SIZE) { i ->
    (0.5 + 0.5 * sin(2.0 * PI * i / LUT_SIZE)).toFloat()
}

/** [cycles] 以周期为单位；负值靠补码按位与自然回绕。 */
internal fun wave(cycles: Float): Float = WaveLut[(cycles * LUT_SIZE).toInt() and LUT_MASK]

/** 波头尚未出现（开场已结束）时传入 [UltraPixelField.draw] 的取值。 */
internal const val NO_SWEEP_FRONT = Float.POSITIVE_INFINITY

/**
 * 字样背后的方格点阵：左侧几乎不可见，向右渐亮，亮斑持续右移。
 *
 * 每帧把格子按亮度分进若干色阶，同一色阶用一次 [Canvas.drawPoints] 画完，
 * 所以上千个格子也只有个位数绘制调用。所有数组按网格尺寸缓存，绘制路径没有对象分配。
 */
internal class UltraPixelField(
    cells: List<Color>,
    private val gain: Float,
    private val ceiling: Float,
    /** 边缘是否抗锯齿：Miuix 柔和，Material 利落。 */
    antiAlias: Boolean,
    /** 上下边缘是否渐隐：Miuix 柔和，Material 整齐。 */
    private val softRows: Boolean,
) {
    private val levels = cells.size
    private val levelColors = IntArray(levels) { cells[it].toArgb() }
    private val paints = Array(levels) {
        Paint().apply {
            isAntiAlias = antiAlias
            style = Paint.Style.STROKE
            strokeCap = Paint.Cap.SQUARE
        }
    }
    private val points = Array(levels) { FloatArray(0) }
    private val counts = IntArray(levels)

    private var cols = 0
    private var rows = 0
    private var preparedPitchDp = Float.NaN
    private var preparedFadeEnd = false
    private var noise = FloatArray(0)
    private var ramp = FloatArray(0)
    private var rampSoft = FloatArray(0)
    private var lift = FloatArray(0)
    private var swellPhase = FloatArray(0)
    private var spotPhase = FloatArray(0)
    private var twinklePhase = FloatArray(0)
    private var rowEnvelope = FloatArray(0)

    private fun prepare(newCols: Int, newRows: Int, pitchDp: Float, fadeEnd: Boolean) {
        if (newCols == cols && newRows == rows && pitchDp == preparedPitchDp && fadeEnd == preparedFadeEnd) return
        cols = newCols
        rows = newRows
        preparedPitchDp = pitchDp
        preparedFadeEnd = fadeEnd
        val total = cols * rows
        val random = Random(0x4D61706C)
        noise = FloatArray(total) { random.nextFloat() }
        for (i in 0 until levels) points[i] = FloatArray(total * 2)

        val last = (cols - 1).coerceAtLeast(1).toFloat()
        ramp = FloatArray(cols)
        rampSoft = FloatArray(cols)
        lift = FloatArray(cols)
        swellPhase = FloatArray(cols)
        spotPhase = FloatArray(cols)
        twinklePhase = FloatArray(cols)
        for (c in 0 until cols) {
            val u = c / last
            val rising = ((u - UltraBrandTokens.RAMP_START) / (1f - UltraBrandTokens.RAMP_START))
                .coerceIn(0f, 1f)
            // 大屏上点阵不到屏幕边，尾部收一下，不留一道硬截断。
            val tail = if (fadeEnd) ((1f - u) / 0.14f).coerceIn(0f, 1f) else 1f
            val r = rising.pow(UltraBrandTokens.RAMP_POWER)
            ramp[c] = r * tail
            rampSoft[c] = r.pow(0.7f) * tail
            lift[c] = 0.86f + 0.36f * r
            val xDp = c * pitchDp
            swellPhase[c] = xDp / UltraBrandTokens.SWELL_WAVELENGTH.value
            spotPhase[c] = xDp / UltraBrandTokens.SPOT_WAVELENGTH.value
            twinklePhase[c] = xDp / UltraBrandTokens.TWINKLE_WAVELENGTH.value
        }
        val edge = if (softRows) 0.78f else 0.14f
        val rowLast = (rows - 1).coerceAtLeast(1).toFloat()
        rowEnvelope = FloatArray(rows) { r ->
            val v = abs(2f * r / rowLast - 1f)
            1f - v * v * edge
        }
    }

    /**
     * @param frontPx 开场像素波的波头 x；[NO_SWEEP_FRONT] 表示已进入常驻流动
     * @param holeStart 字样左缘，字样范围内的格子压暗
     * @param intensity 整体亮度（折叠态更低）
     * @param alpha 整体不透明度（随滚动淡出）
     */
    fun draw(
        canvas: Canvas,
        left: Float,
        top: Float,
        width: Float,
        pitchPx: Int,
        cellPx: Int,
        rowCount: Int,
        pxPerDp: Float,
        time: Float,
        frontPx: Float,
        holeStart: Float,
        holeEnd: Float,
        intensity: Float,
        alpha: Float,
        fadeEnd: Boolean,
    ) {
        val columnCount = (width / pitchPx).toInt()
        if (columnCount < 2 || rowCount < 1 || alpha <= 0f) return
        prepare(columnCount, rowCount, pitchPx / pxPerDp, fadeEnd)
        counts.fill(0)

        val swellShift = time * UltraBrandTokens.SWELL_SPEED.value / UltraBrandTokens.SWELL_WAVELENGTH.value
        val spotShift = time * UltraBrandTokens.SPOT_SPEED.value / UltraBrandTokens.SPOT_WAVELENGTH.value
        val twinkleShift = time * UltraBrandTokens.TWINKLE_SPEED.value / UltraBrandTokens.TWINKLE_WAVELENGTH.value
        val hasFront = frontPx != NO_SWEEP_FRONT
        val crest = UltraBrandTokens.SWEEP_CREST.value * pxPerDp
        val settle = UltraBrandTokens.SWEEP_SETTLE.value * pxPerDp
        val dither = UltraBrandTokens.SWEEP_DITHER.value * pxPerDp
        val half = cellPx / 2f

        for (r in 0 until rows) {
            val y = top + r * pitchPx + half
            val envelope = rowEnvelope[r]
            val rowShift = r / 9f
            val rowOffset = r * cols
            for (c in 0 until cols) {
                val n = noise[rowOffset + c]
                val swell = wave(swellPhase[c] - swellShift)
                val spot = wave(spotPhase[c] - spotShift + rowShift + n * 0.1f)
                val tw = wave(twinklePhase[c] - twinkleShift + n)
                val tw2 = tw * tw
                val twinkle = tw2 * tw2 * tw

                val base = ramp[c] * (0.34f + 0.26f * swell + 0.28f * spot) + rampSoft[c] * twinkle * 0.46f
                var v = base * lift[c] * envelope * (0.72f + 0.28f * n)
                val x = left + c * pitchPx + half

                if (hasFront) {
                    val ahead = x - frontPx
                    if (ahead > dither * n) continue
                    val behind = -ahead
                    val settled = (behind / settle).coerceIn(0f, 1f)
                    val glow = (1f - behind / crest).coerceIn(0f, 1f) * (0.55f + 0.45f * n)
                    v = v * settled + glow * 0.9f * envelope
                }
                if (x in holeStart..holeEnd) v *= UltraBrandTokens.UNDER_WORD_DIM
                v *= intensity
                if (v < 0.035f) continue

                val level = (v * levels).toInt().coerceAtMost(levels - 1)
                val index = counts[level]
                val slot = points[level]
                slot[index] = x
                slot[index + 1] = y
                counts[level] = index + 2
            }
        }

        val stroke = cellPx.toFloat()
        for (level in 0 until levels) {
            val count = counts[level]
            if (count == 0) continue
            val opacity = (((level + 0.5f) / levels) * gain + 0.15f).coerceAtMost(ceiling) * alpha
            val paint = paints[level]
            paint.strokeWidth = stroke
            paint.color = withAlpha(levelColors[level], opacity)
            canvas.drawPoints(points[level], 0, count, paint)
        }
    }
}

/**
 * 字母笔画里的亮斑：用 SrcAtop 叠在已经画好的字形上，所以只会出现在字母内部。
 *
 * 调用方负责在同一个 saveLayer 内先画字，再调这里。
 */
internal class UltraLetterSparks(spark: Color) {
    private val sparkColor = spark.toArgb()
    private val paints = Array(SPARK_LEVELS) {
        Paint().apply {
            isAntiAlias = false
            style = Paint.Style.STROKE
            strokeCap = Paint.Cap.SQUARE
            xfermode = PorterDuffXfermode(PorterDuff.Mode.SRC_ATOP)
        }
    }
    private val points = Array(SPARK_LEVELS) { FloatArray(0) }
    private val counts = IntArray(SPARK_LEVELS)
    private var noise = FloatArray(0)
    private var cols = 0
    private var rows = 0

    fun draw(
        canvas: Canvas,
        left: Float,
        top: Float,
        width: Float,
        height: Float,
        pitchPx: Int,
        cellPx: Int,
        pxPerDp: Float,
        time: Float,
        strength: Float,
    ) {
        val columnCount = (width / pitchPx).toInt() + 1
        val rowCount = (height / pitchPx).toInt() + 1
        if (columnCount != cols || rowCount != rows) {
            cols = columnCount
            rows = rowCount
            val random = Random(0x55)
            noise = FloatArray(cols * rows) { random.nextFloat() }
            for (i in 0 until SPARK_LEVELS) points[i] = FloatArray(cols * rows * 2)
        }
        counts.fill(0)

        val pitchDp = pitchPx / pxPerDp
        val wavelength = UltraBrandTokens.LETTER_WAVELENGTH.value
        val shift = time * UltraBrandTokens.LETTER_SPEED.value / wavelength
        val half = cellPx / 2f
        for (r in 0 until rows) {
            val rowShift = r * 0.035f
            val y = top + r * pitchPx + half
            for (c in 0 until cols) {
                val n = noise[r * cols + c]
                val w = wave(c * pitchDp / wavelength - shift + rowShift + n * 0.16f)
                val w2 = w * w
                val v = w2 * w2 * w2 * (0.45f + 0.55f * n)
                if (v < 0.1f) continue
                val level = ((v * SPARK_LEVELS).toInt()).coerceAtMost(SPARK_LEVELS - 1)
                val index = counts[level]
                points[level][index] = left + c * pitchPx + half
                points[level][index + 1] = y
                counts[level] = index + 2
            }
        }

        val stroke = cellPx.toFloat()
        for (level in 0 until SPARK_LEVELS) {
            if (counts[level] == 0) continue
            val paint = paints[level]
            paint.strokeWidth = stroke
            paint.color = withAlpha(sparkColor, ((level + 1f) / SPARK_LEVELS) * strength)
            canvas.drawPoints(points[level], 0, counts[level], paint)
        }
    }

    private companion object {
        const val SPARK_LEVELS = 3
    }
}

internal fun withAlpha(argb: Int, alpha: Float): Int {
    val a = floor(alpha.coerceIn(0f, 1f) * 255f + 0.5f).toInt()
    return (argb and 0x00FFFFFF) or (a shl 24)
}
