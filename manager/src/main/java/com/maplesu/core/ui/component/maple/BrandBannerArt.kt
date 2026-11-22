package com.maplesu.core.ui.component.maple

import android.graphics.Bitmap
import android.graphics.BitmapShader
import android.graphics.BlurMaskFilter
import android.graphics.Canvas
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.PorterDuff
import android.graphics.PorterDuffXfermode
import android.graphics.Rect
import android.graphics.Shader
import android.graphics.Typeface
import androidx.compose.runtime.Immutable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import com.maplesu.core.ui.component.mapleLeafPath
import java.nio.ByteBuffer
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.ceil
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.roundToInt
import kotlin.math.sin
import kotlin.random.Random

/** 烘好的一张 Banner：构造在后台线程，[draw] 在绘制阶段调用且不分配对象。 */
internal interface BrandBannerArt {
    fun draw(canvas: Canvas, time: Float, reveal: Float)
}

internal fun bakeBrandBanner(
    kind: BrandBannerKind,
    width: Int,
    height: Int,
    pxPerDp: Float,
    dark: Boolean,
    soft: Boolean,
    accent: Int,
): BrandBannerArt = when (kind) {
    BrandBannerKind.ULTRA -> ultraBannerArt(width, height, pxPerDp, dark, soft)
    BrandBannerKind.NORMAL -> normalBannerArt(width, height, pxPerDp, dark, soft, accent)
    BrandBannerKind.MAPLE -> MapleBannerArt(width, height, pxPerDp, mapleBannerPalette(dark), soft)
}

// ── 配色 ─────────────────────────────────────────────────────────

/** 枫叶色与 Snowfall 同源，只用于这张 Banner，不进入用户主题。 */
@Immutable
private data class MapleBannerPalette(
    val stops: List<Color>,
    val sheen: Color,
    val bodyAlpha: Float,
    val bloomAlpha: Float,
)

private val MapleDark = MapleBannerPalette(
    stops = listOf(Color(0xFFEAC26C), Color(0xFFFFB05C), Color(0xFFF58B55), Color(0xFFD95343)),
    sheen = Color(0xFFFFF3E0),
    bodyAlpha = 0.28f,
    bloomAlpha = 0.34f,
)

private val MapleLight = MapleBannerPalette(
    stops = listOf(Color(0xFFA8650F), Color(0xFFBC5A1E), Color(0xFFB23F27), Color(0xFF962A28)),
    sheen = Color(0xFFFFE3C4),
    bodyAlpha = 0.58f,
    bloomAlpha = 0.12f,
)

private fun mapleBannerPalette(dark: Boolean) = if (dark) MapleDark else MapleLight

// ── 字形 ─────────────────────────────────────────────────────────

/** 微缩文字的内容：放大后能读到的署名。 */
private const val CREDIT_RIBBON = "MapleAutumn · 小酒 · 晚风 · FinaSU · KernelSU · 7kimisu · KernelPatch · "

private const val HEAVY = 800
private const val BOLD = 700
private const val TRACKING_EM = 0.02f
private const val SUPERSAMPLE = 4

/** 一个摆好位置的单词；同一份摆放同时用于点阵取样和辉光。 */
private class PlacedWord(val text: String, val paint: Paint, val x: Float, val y: Float) {
    val right: Float
    val top: Float

    init {
        val bounds = Rect()
        paint.getTextBounds(text, 0, text.length, bounds)
        right = x + bounds.right
        top = y + bounds.top
    }

    fun draw(canvas: Canvas, withPaint: Paint = paint) {
        canvas.drawText(text, x, y, withPaint)
    }
}

/** 把 [text] 缩放到 [fitWidth] × [fitHeight] 之内，并在 [boxWidth] × [boxHeight] 里居中。 */
private fun placeWord(
    text: String,
    weight: Int,
    fitWidth: Float,
    fitHeight: Float,
    boxWidth: Float,
    boxHeight: Float,
): PlacedWord {
    val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        typeface = Typeface.create(Typeface.DEFAULT, weight, false)
        letterSpacing = TRACKING_EM
        textSize = fitHeight
    }
    val bounds = Rect()
    paint.getTextBounds(text, 0, text.length, bounds)
    paint.textSize *= min(fitWidth / bounds.width(), fitHeight / bounds.height())
    paint.getTextBounds(text, 0, text.length, bounds)
    return PlacedWord(
        text = text,
        paint = paint,
        x = (boxWidth - bounds.width()) / 2f - bounds.left,
        y = (boxHeight - bounds.height()) / 2f - bounds.top,
    )
}

/** 字形在每个格子里的覆盖率，0..1。 */
private fun wordCoverage(word: PlacedWord, grid: BrandBannerGrid): FloatArray {
    val bitmap = Bitmap.createBitmap(grid.cols * SUPERSAMPLE, grid.rows * SUPERSAMPLE, Bitmap.Config.ALPHA_8)
    Canvas(bitmap).apply {
        val scale = SUPERSAMPLE.toFloat() / grid.pitch
        scale(scale, scale)
        translate(-grid.left, -grid.top)
        word.draw(this)
    }
    val stride = bitmap.rowBytes
    val pixels = ByteArray(stride * bitmap.height)
    bitmap.copyPixelsToBuffer(ByteBuffer.wrap(pixels))
    bitmap.recycle()

    val perCell = 255f * SUPERSAMPLE * SUPERSAMPLE
    return FloatArray(grid.cols * grid.rows) { index ->
        val row = index / grid.cols
        val col = index % grid.cols
        var sum = 0
        for (y in 0 until SUPERSAMPLE) {
            val offset = (row * SUPERSAMPLE + y) * stride + col * SUPERSAMPLE
            for (x in 0 until SUPERSAMPLE) sum += pixels[offset + x].toInt() and 0xFF
        }
        sum / perCell
    }
}

private fun bakeGlow(word: PlacedWord, width: Int, height: Int, pxPerDp: Float, shader: Shader?, color: Int): Bitmap {
    val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
    val paint = Paint(word.paint).apply {
        this.color = color
        this.shader = shader
        maskFilter = BlurMaskFilter(BrandBannerTokens.BLOOM_RADIUS.value * pxPerDp, BlurMaskFilter.Blur.NORMAL)
    }
    word.draw(Canvas(bitmap), paint)
    return bitmap
}

// ── 点阵（Ultra 方格 / Normal 圆点）──────────────────────────────

/** 每种点阵自己的亮度算法；绘制循环是共用的。 */
private interface DotMotion {
    fun prepare(time: Float)
    fun value(col: Int, row: Int, noise: Float, coverage: Float): Float
    fun crest(noise: Float): Float
}

private fun ultraBannerArt(width: Int, height: Int, pxPerDp: Float, dark: Boolean, soft: Boolean): BrandBannerArt {
    val palette = ultraBrandPalette(dark)
    val pitch = (BrandBannerTokens.SQUARE_PITCH.value * pxPerDp).roundToInt().coerceAtLeast(3)
    val cell = (BrandBannerTokens.SQUARE_CELL.value * pxPerDp).roundToInt().coerceAtLeast(2)
    val grid = brandBannerGrid(width, height, pitch)
    val word = placeWord("ULTRA", HEAVY, grid.cols * pitch * 0.94f, grid.rows * pitch * 0.8f, width.toFloat(), height.toFloat())
    val levels = palette.cells.size
    return DotBannerArt(
        width = width,
        grid = grid,
        pxPerDp = pxPerDp,
        coverage = wordCoverage(word, grid).sharpenedUnless(soft),
        motion = UltraDotMotion(grid, pxPerDp, soft),
        half = cell / 2f,
        colors = IntArray(levels) { level ->
            val opacity = (((level + 0.5f) / levels) * BrandBannerTokens.SQUARE_GAIN + 0.15f).coerceAtMost(1f)
            withAlpha(palette.cells[level].toArgb(), opacity)
        },
        strokes = FloatArray(levels) { cell.toFloat() },
        cap = Paint.Cap.SQUARE,
        antiAlias = soft,
        glow = if (soft) bakeGlow(word, width, height, pxPerDp, null, palette.bloom.toArgb()) else null,
        glowAlpha = if (dark) BrandBannerTokens.SQUARE_BLOOM_ALPHA_DARK else BrandBannerTokens.SQUARE_BLOOM_ALPHA_LIGHT,
    )
}

private fun normalBannerArt(width: Int, height: Int, pxPerDp: Float, dark: Boolean, soft: Boolean, accent: Int): BrandBannerArt {
    val pitch = (BrandBannerTokens.DOT_PITCH.value * pxPerDp).roundToInt().coerceAtLeast(3)
    val grid = brandBannerGrid(width, height, pitch)
    val word = placeWord("NORMAL", BOLD, grid.cols * pitch * 0.9f, grid.rows * pitch * 0.74f, width.toFloat(), height.toFloat())
    val levels = BrandBannerTokens.DOT_LEVELS
    return DotBannerArt(
        width = width,
        grid = grid,
        pxPerDp = pxPerDp,
        coverage = wordCoverage(word, grid).sharpenedUnless(soft),
        motion = NormalDotMotion(grid, pxPerDp, soft),
        half = pitch / 2f,
        colors = IntArray(levels) { level ->
            withAlpha(accent, (0.2f + (level + 0.5f) / levels * 0.95f).coerceAtMost(1f))
        },
        strokes = FloatArray(levels) { level ->
            val radiusDp = BrandBannerTokens.DOT_MIN_RADIUS.value +
                BrandBannerTokens.DOT_RADIUS_RANGE.value * (level + 0.5f) / levels
            2f * radiusDp * pxPerDp
        },
        cap = Paint.Cap.ROUND,
        antiAlias = true,
        glow = if (soft) bakeGlow(word, width, height, pxPerDp, null, accent) else null,
        glowAlpha = if (dark) BrandBannerTokens.DOT_BLOOM_ALPHA_DARK else BrandBannerTokens.DOT_BLOOM_ALPHA_LIGHT,
    )
}

/** Material 的字形边缘利落：覆盖率取整成有或无。 */
private fun FloatArray.sharpenedUnless(soft: Boolean): FloatArray =
    if (soft) this else FloatArray(size) { if (this[it] >= 0.5f) 1f else 0f }

private fun lerp(from: Float, to: Float, fraction: Float) = from + (to - from) * fraction

private fun rowEnvelope(rows: Int, edge: Float) = FloatArray(rows) { row ->
    val v = abs(2f * row / (rows - 1).coerceAtLeast(1) - 1f)
    1f - v * v * edge
}

/** 字母恒亮，字外是首页同款流动场：左暗右亮，亮斑持续右移。 */
private class UltraDotMotion(grid: BrandBannerGrid, pxPerDp: Float, soft: Boolean) : DotMotion {
    private val rise = FloatArray(grid.cols)
    private val riseSoft = FloatArray(grid.cols)
    private val tail = FloatArray(grid.cols)
    private val swellPhase = FloatArray(grid.cols)
    private val spotPhase = FloatArray(grid.cols)
    private val twinklePhase = FloatArray(grid.cols)
    private val envelope = rowEnvelope(grid.rows, if (soft) 0.92f else 0.5f)

    private var swellShift = 0f
    private var spotShift = 0f
    private var twinkleShift = 0f

    init {
        val last = (grid.cols - 1).coerceAtLeast(1).toFloat()
        val pitchDp = grid.pitch / pxPerDp
        for (col in 0 until grid.cols) {
            val u = col / last
            rise[col] = u.pow(1.5f)
            riseSoft[col] = rise[col].pow(0.7f)
            tail[col] = ((1f - u) / 0.12f).coerceIn(0f, 1f)
            val xDp = col * pitchDp
            swellPhase[col] = xDp / UltraBrandTokens.SWELL_WAVELENGTH.value
            spotPhase[col] = xDp / UltraBrandTokens.SPOT_WAVELENGTH.value
            twinklePhase[col] = xDp / UltraBrandTokens.TWINKLE_WAVELENGTH.value
        }
    }

    override fun prepare(time: Float) {
        swellShift = time * UltraBrandTokens.SWELL_SPEED.value / UltraBrandTokens.SWELL_WAVELENGTH.value
        spotShift = time * UltraBrandTokens.SPOT_SPEED.value / UltraBrandTokens.SPOT_WAVELENGTH.value
        twinkleShift = time * UltraBrandTokens.TWINKLE_SPEED.value / UltraBrandTokens.TWINKLE_WAVELENGTH.value
    }

    override fun value(col: Int, row: Int, noise: Float, coverage: Float): Float {
        val swell = wave(swellPhase[col] - swellShift)
        val spot = wave(spotPhase[col] - spotShift + row / 9f + noise * 0.1f)
        val tw = wave(twinklePhase[col] - twinkleShift + noise)
        val tw2 = tw * tw
        val twinkle = tw2 * tw2 * tw
        val r = rise[col]
        val field = (r * (0.3f + 0.26f * swell + 0.28f * spot) + riseSoft[col] * twinkle * 0.4f) *
            envelope[row] * (0.72f + 0.28f * noise) * 0.62f * tail[col]
        if (coverage <= 0f) return field
        val letter = (lerp(0.42f, 0.86f, r) + 0.16f * spot + 0.1f * swell - 0.08f + twinkle * 0.22f) *
            (0.86f + 0.14f * noise)
        return lerp(field, letter, coverage)
    }

    override fun crest(noise: Float): Float = (0.55f + 0.45f * noise) * 0.9f
}

/** 比 Ultra 安静得多：没有闪烁，只有一道很慢的起伏。 */
private class NormalDotMotion(grid: BrandBannerGrid, pxPerDp: Float, soft: Boolean) : DotMotion {
    private val phase = FloatArray(grid.cols)
    private val edge = FloatArray(grid.cols)
    private val envelope = rowEnvelope(grid.rows, if (soft) 0.9f else 0.55f)
    private var shift = 0f

    init {
        val last = (grid.cols - 1).coerceAtLeast(1).toFloat()
        val pitchDp = grid.pitch / pxPerDp
        for (col in 0 until grid.cols) {
            phase[col] = col * pitchDp / BrandBannerTokens.DOT_SWELL_WAVELENGTH.value
            edge[col] = sin(PI.toFloat() * col / last).coerceAtLeast(0f).pow(0.9f)
        }
    }

    override fun prepare(time: Float) {
        shift = time * BrandBannerTokens.DOT_SWELL_SPEED.value / BrandBannerTokens.DOT_SWELL_WAVELENGTH.value
    }

    override fun value(col: Int, row: Int, noise: Float, coverage: Float): Float {
        val swell = wave(phase[col] - shift + row * 0.012f)
        val env = envelope[row]
        val field = (0.1f + 0.1f * swell) * env * env * (0.7f + 0.3f * noise) * edge[col]
        if (coverage <= 0f) return field
        return lerp(field, 0.58f + 0.34f * swell + 0.06f * noise, coverage)
    }

    override fun crest(noise: Float): Float = 0.7f
}

/**
 * 点阵的绘制循环：按亮度分进若干色阶，同一色阶一次 [Canvas.drawPoints] 画完，
 * 数组全部预分配，和 [UltraPixelField] 是同一套约束。
 */
private class DotBannerArt(
    private val width: Int,
    private val grid: BrandBannerGrid,
    pxPerDp: Float,
    private val coverage: FloatArray,
    private val motion: DotMotion,
    private val half: Float,
    colors: IntArray,
    strokes: FloatArray,
    cap: Paint.Cap,
    antiAlias: Boolean,
    private val glow: Bitmap?,
    private val glowAlpha: Float,
) : BrandBannerArt {
    private val levels = colors.size
    private val paints = Array(levels) { level ->
        Paint().apply {
            isAntiAlias = antiAlias
            style = Paint.Style.STROKE
            strokeCap = cap
            strokeWidth = strokes[level]
            color = colors[level]
        }
    }
    private val points = Array(levels) { FloatArray(grid.cols * grid.rows * 2) }
    private val counts = IntArray(levels)
    private val noise = Random(0x4D61706C).let { random -> FloatArray(grid.cols * grid.rows) { random.nextFloat() } }
    private val glowPaint = Paint(Paint.FILTER_BITMAP_FLAG)
    private val crestPx = UltraBrandTokens.SWEEP_CREST.value * pxPerDp
    private val settlePx = UltraBrandTokens.SWEEP_SETTLE.value * pxPerDp
    private val ditherPx = UltraBrandTokens.SWEEP_DITHER.value * pxPerDp
    private val envelope = rowEnvelope(grid.rows, 0.7f)

    override fun draw(canvas: Canvas, time: Float, reveal: Float) {
        if (reveal <= 0f) return
        val settled = reveal >= 1f
        val front = if (settled) {
            NO_SWEEP_FRONT
        } else {
            UltraIntroTimeline.front(reveal, -crestPx, width + crestPx + settlePx)
        }
        val hasFront = front != NO_SWEEP_FRONT

        if (glow != null) {
            val presence = if (settled) 1f else (reveal * 1.4f - 0.3f).coerceIn(0f, 1f)
            glowPaint.alpha = (glowAlpha * presence * 255f).roundToInt().coerceIn(0, 255)
            canvas.drawBitmap(glow, 0f, 0f, glowPaint)
        }

        motion.prepare(time)
        counts.fill(0)
        val cols = grid.cols
        for (row in 0 until grid.rows) {
            val y = grid.top + row * grid.pitch + half
            val rowOffset = row * cols
            for (col in 0 until cols) {
                val n = noise[rowOffset + col]
                var v = motion.value(col, row, n, coverage[rowOffset + col])
                val x = grid.left + col * grid.pitch + half
                if (hasFront) {
                    val ahead = x - front
                    if (ahead > ditherPx * n) continue
                    val behind = -ahead
                    val glowing = (1f - behind / crestPx).coerceIn(0f, 1f)
                    v = v * (behind / settlePx).coerceIn(0f, 1f) + glowing * motion.crest(n) * envelope[row]
                }
                if (v < 0.035f) continue
                val level = (v * levels).toInt().coerceAtMost(levels - 1)
                val index = counts[level]
                val slot = points[level]
                slot[index] = x
                slot[index + 1] = y
                counts[level] = index + 2
            }
        }
        for (level in 0 until levels) {
            val count = counts[level]
            if (count != 0) canvas.drawPoints(points[level], 0, count, paints[level])
        }
    }
}

// ── 微缩文字（MapleSU）───────────────────────────────────────────

/**
 * 字形实心，一眼能读；字形里印满署名，凑近能读到人名。
 *
 * 微缩文字是一张整幅贴图，用 [BitmapShader] 填进字形，所以字形边缘始终是矢量的利落，
 * 不会像按格子取舍那样把小字母啃坏。
 */
private class MapleBannerArt(
    private val width: Int,
    private val height: Int,
    private val pxPerDp: Float,
    palette: MapleBannerPalette,
    soft: Boolean,
) : BrandBannerArt {
    private val word: Bitmap
    private val leaf: Bitmap
    private val glow: Bitmap?
    private val glowAlpha = palette.bloomAlpha
    private val leafHalf: Float
    private val leafX: Float
    private val leafY: Float

    private val glowPaint = Paint(Paint.FILTER_BITMAP_FLAG)
    private val leafPaint = Paint(Paint.ANTI_ALIAS_FLAG or Paint.FILTER_BITMAP_FLAG)
    private val sheenHalf = BrandBannerTokens.SHEEN_HALF_WIDTH.value * pxPerDp
    private val sheenPaint = Paint().apply {
        val sheen = palette.sheen.toArgb()
        shader = LinearGradient(
            -sheenHalf, 0f, sheenHalf, 0f,
            intArrayOf(withAlpha(sheen, 0f), withAlpha(sheen, 0.95f), withAlpha(sheen, 0f)),
            null,
            Shader.TileMode.CLAMP,
        )
        xfermode = PorterDuffXfermode(PorterDuff.Mode.SRC_ATOP)
    }

    init {
        val w = width.toFloat()
        val h = height.toFloat()
        val leafSize = h * BrandBannerTokens.LEAF_SIZE_RATIO
        val leafGap = h * BrandBannerTokens.LEAF_GAP_RATIO
        // 枫叶只有叶身占视觉宽度，叶尖可以探出去一点。
        val leafInk = leafSize * 0.72f
        val placed = placeWord("MapleSU", HEAVY, w * 0.9f - leafInk - leafGap, h * 0.88f, w - leafInk - leafGap, h)
        val gradient = LinearGradient(
            0f, 0f, w, 0f,
            IntArray(palette.stops.size) { palette.stops[it].toArgb() },
            null,
            Shader.TileMode.CLAMP,
        )

        word = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(word)
        placed.draw(canvas, Paint(placed.paint).apply {
            shader = gradient
            alpha = (palette.bodyAlpha * 255f).roundToInt()
        })
        val sheet = microprintSheet(gradient)
        placed.draw(canvas, Paint(placed.paint).apply {
            shader = BitmapShader(sheet, Shader.TileMode.CLAMP, Shader.TileMode.CLAMP)
        })
        sheet.recycle()

        leaf = bakeLeaf(leafSize, palette)
        leafHalf = leaf.width / 2f
        leafX = placed.right + leafGap + leafSize * 0.3f
        leafY = placed.top + leafSize * 0.46f
        glow = if (soft) bakeGlow(placed, width, height, pxPerDp, gradient, 0xFFFFFFFF.toInt()) else null
    }

    private fun microprintSheet(gradient: Shader): Bitmap {
        val sheet = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(sheet)
        val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            shader = gradient
            typeface = Typeface.create(Typeface.MONOSPACE, 600, false)
            textSize = BrandBannerTokens.MICRO_TEXT.value * pxPerDp
            isSubpixelText = true
        }
        val ribbonWidth = paint.measureText(CREDIT_RIBBON)
        val rowHeight = BrandBannerTokens.MICRO_ROW.value * pxPerDp
        val rowShift = BrandBannerTokens.MICRO_ROW_SHIFT.value * pxPerDp
        var row = 0
        var baseline = -paint.ascent()
        while (baseline - paint.textSize < height) {
            var x = -((row * rowShift) % ribbonWidth)
            while (x < width) {
                canvas.drawText(CREDIT_RIBBON, x, baseline, paint)
                x += ribbonWidth
            }
            row += 1
            baseline += rowHeight
        }
        return sheet
    }

    private fun bakeLeaf(size: Float, palette: MapleBannerPalette): Bitmap {
        val side = ceil(size * 1.1f).toInt().coerceAtLeast(1)
        val sprite = Bitmap.createBitmap(side, side, Bitmap.Config.ARGB_8888)
        val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            shader = LinearGradient(
                20f, 8f, 72f, 84f,
                palette.stops[1].toArgb(),
                palette.stops[3].toArgb(),
                Shader.TileMode.CLAMP,
            )
        }
        Canvas(sprite).apply {
            translate(side / 2f, side / 2f)
            scale(size / LEAF_UNITS, size / LEAF_UNITS)
            translate(-LEAF_UNITS / 2f, -LEAF_UNITS / 2f)
            drawPath(mapleLeafPath(), paint)
            paint.style = Paint.Style.STROKE
            paint.strokeWidth = 2.6f
            paint.strokeCap = Paint.Cap.ROUND
            drawLine(48f, 70f, 49f, 92f, paint)
        }
        return sprite
    }

    override fun draw(canvas: Canvas, time: Float, reveal: Float) {
        if (reveal <= 0f) return
        val w = width.toFloat()
        val h = height.toFloat()
        val settled = reveal >= 1f
        val crest = UltraBrandTokens.SWEEP_CREST.value * pxPerDp
        val front = if (settled) {
            w
        } else {
            UltraIntroTimeline.front(reveal, -crest, w + crest + UltraBrandTokens.SWEEP_SETTLE.value * pxPerDp)
        }

        val clip = canvas.save()
        if (!settled) canvas.clipRect(0f, 0f, max(front, 0f), h)

        if (glow != null) {
            glowPaint.alpha = (glowAlpha * 255f).roundToInt()
            canvas.drawBitmap(glow, 0f, 0f, glowPaint)
        }

        val layer = canvas.saveLayer(0f, 0f, w, h, null)
        canvas.drawBitmap(word, 0f, 0f, null)
        val sheenX = if (settled) {
            val travel = w + BrandBannerTokens.SHEEN_REST.value * pxPerDp
            (time * BrandBannerTokens.SHEEN_SPEED.value * pxPerDp) % travel - sheenHalf
        } else {
            front - crest
        }
        canvas.translate(sheenX, 0f)
        canvas.drawRect(-sheenHalf, 0f, sheenHalf, h, sheenPaint)
        canvas.restoreToCount(layer)

        val sway = sin(2f * PI.toFloat() * time / BrandBannerTokens.LEAF_SWAY_SECONDS)
        canvas.save()
        canvas.translate(leafX, leafY + BrandBannerTokens.LEAF_BOB.value * pxPerDp * sway)
        canvas.rotate(BrandBannerTokens.LEAF_TILT_DEGREES + BrandBannerTokens.LEAF_SWAY_DEGREES * sway)
        canvas.drawBitmap(leaf, -leafHalf, -leafHalf, leafPaint)
        canvas.restoreToCount(clip)
    }

    private companion object {
        /** [mapleLeafPath] 的设计网格边长。 */
        const val LEAF_UNITS = 96f
    }
}
