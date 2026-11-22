package com.maplesu.core.ui.component

import android.graphics.Bitmap
import android.graphics.Canvas as AndroidCanvas
import android.graphics.Paint
import android.graphics.Path
import android.graphics.LinearGradient
import android.graphics.Shader
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.roundToInt
import kotlin.math.sin
import kotlin.random.Random

/**
 * 枫叶飘落(纯 Compose + Android Canvas 自绘,不依赖任何第三方库)。
 *
 * 枫叶是真正的枫叶(预渲染 3 种暖色贴图),并且受【重力系统】驱动:
 *   · 重力加速 + 空气阻力 → 加速到终速(远的小而慢,近的大而快)
 *   · 跟随手机倾斜(见 GravityField),朝低的一侧流
 *   · 出屏环绕,保证连续飘落
 *   · 【3D 翻滚】每个枫叶带 2D 自转 + 双轴翻面:
 *       横轴 scaleX = cos(主相位) —— 像巨魔雨那样的“翻面”
 *       副轴 scaleY = 小幅 cos(副相位) —— 让翻滚不只在同一平面上,更像在空中翻
 *       侧身(接近 90°)时亮度略降 → 立体感更强
 *
 * @param sizeScale  枫叶大小倍率
 * @param speedScale 下落速度倍率(直接乘在重力加速度上)
 * @param tiltEnabled 是否跟随手机倾斜
 */
@Composable
fun SnowfallOverlay(
    modifier: Modifier = Modifier,
    flakeCount: Int = 38,
    sizeScale: Float = 1f,
    speedScale: Float = 1f,
    tiltEnabled: Boolean = true,
    gravityMode: Int = 0,
) {
    val sprites by produceState<List<ImageBitmap>>(emptyList()) {
        value = withContext(Dispatchers.Default) { makeMapleLeafSprites() }
    }
    if (sprites.isEmpty()) return
    val flakes = remember(flakeCount) { makeFlakes(flakeCount, sprites.size) }
    val depths = remember(flakes) { FloatArray(flakes.size) { flakes[it].depth } }

    val field = rememberGravityField(
        depths = depths,
        speedScale = speedScale,
        tiltEnabled = tiltEnabled,
        gravityMode = gravityMode,
        baseAccel = 230f,
        dragForFar = 6f,
        dragForNear = 3f,
    )

    val sizeScaleState = rememberUpdatedState(sizeScale)

    Canvas(modifier = modifier.fillMaxSize()) {
        field.w = size.width
        field.h = size.height
        field.ensureReady()
        val t = field.time.floatValue
        val sz = sizeScaleState.value
        val cull = 0.15f * (if (size.width > size.height) size.width else size.height)

        for (i in flakes.indices) {
            val f = flakes[i]
            val x = field.px[i] + sin(t * .65f + f.flipPhase) * (6f + f.depth * 14f)
            val y = field.py[i]
            if (x < -cull || x > size.width + cull || y < -cull || y > size.height + cull) continue

            val px = (f.sizeDp * sz).dp.toPx()
            val img = sprites[f.sprite]
            val sizePx = px.roundToInt().coerceAtLeast(1)
            val deg = f.rot + f.rotSpeed * t

            // 3D 翻滚(和巨魔雨同思路,但多一轴):
            //   横轴翻面 0.28~1.00 —— 侧到接近 90° 时被“压扁”,像绕竖轴转
            //   副轴 0.72~1.00   —— 轻微绕横轴转,两轴叠加就不像一张纸片在翻
            val spin = f.flipPhase + f.flipSpeed * t
            val flipX = 0.28f + 0.72f * cos(spin)
            val flipY = 0.72f + 0.28f * cos(f.tiltPhase + f.tiltSpeed * t)
            // 侧身时亮度略降,增强立体感
            val shade = (f.alpha * (0.74f + 0.26f * flipX)).coerceIn(0f, 1f)

            withTransform({
                rotate(degrees = deg, pivot = Offset(x, y))
                scale(scaleX = flipX, scaleY = flipY, pivot = Offset(x, y))
            }) {
                drawImage(
                    image = img,
                    srcOffset = IntOffset.Zero,
                    srcSize = IntSize(img.width, img.height),
                    dstOffset = IntOffset((x - px / 2f).roundToInt(), (y - px / 2f).roundToInt()),
                    dstSize = IntSize(sizePx, sizePx),
                    alpha = shade,
                    filterQuality = FilterQuality.Medium,
                )
            }
        }
    }
}

private class Flake(
    val sprite: Int,
    val depth: Float,
    val sizeDp: Float,
    val alpha: Float,
    val rot: Float,
    val rotSpeed: Float,
    /** 横轴翻面速度 / 副轴摆动速度(弧度/秒) */
    val flipSpeed: Float,
    val flipPhase: Float,
    val tiltSpeed: Float,
    val tiltPhase: Float,
)

private fun makeFlakes(count: Int, spriteCount: Int): List<Flake> {
    val r = Random(20260914L)
    return List(count) {
        val depth = r.nextFloat()                       // 0=远 1=近
        Flake(
            sprite = r.nextInt(spriteCount),
            depth = depth,
            sizeDp = 9f + depth * 18f,                  // 5dp(远) ~ 21dp(近)
            alpha = 0.25f + depth * 0.42f,
            rot = r.nextFloat() * 360f,
            rotSpeed = (r.nextFloat() - 0.5f) * 40f,    // -20~20 度/秒
            // 小枫叶翻得快一点,大枫叶慢一点(和真实飘落的感觉接近)
            flipSpeed = 0.35f + r.nextFloat() * 0.65f - depth * 0.15f,
            flipPhase = r.nextFloat() * (2f * PI.toFloat()),
            tiltSpeed = 0.5f + r.nextFloat() * 1.6f,
            tiltPhase = r.nextFloat() * (2f * PI.toFloat()),
        )
    }
}

// Warm five-lobed silhouettes are baked once off the UI thread; drawing allocates no paths.
private const val SPRITE_PX = 96

/** The maple leaf silhouette on a 96 × 96 grid, shared by the falling leaves and the brand banner. */
internal fun mapleLeafPath(): Path = Path().apply {
    moveTo(48f, 7f); lineTo(57f, 28f); lineTo(64f, 22f); lineTo(62f, 43f)
    lineTo(79f, 31f); lineTo(78f, 43f); lineTo(91f, 44f); lineTo(75f, 60f)
    lineTo(80f, 66f); lineTo(56f, 70f); lineTo(52f, 78f)
    lineTo(47f, 78f); lineTo(42f, 70f); lineTo(17f, 66f); lineTo(22f, 60f)
    lineTo(6f, 44f); lineTo(20f, 43f); lineTo(18f, 31f); lineTo(35f, 43f)
    lineTo(33f, 22f); lineTo(40f, 28f); close()
}

private fun makeMapleLeafSprites(): List<ImageBitmap> = List(3) { variant ->
    val bmp = Bitmap.createBitmap(SPRITE_PX, SPRITE_PX, Bitmap.Config.ARGB_8888)
    val canvas = AndroidCanvas(bmp)
    val colors = when (variant) {
        0 -> intArrayOf(0xFFFFB05C.toInt(), 0xFFD95343.toInt())
        1 -> intArrayOf(0xFFF58B55.toInt(), 0xFFB94446.toInt())
        else -> intArrayOf(0xFFEAC26C.toInt(), 0xFFD7823D.toInt())
    }
    val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        shader = LinearGradient(20f, 8f, 72f, 84f, colors, null, Shader.TileMode.CLAMP)
        style = Paint.Style.FILL
    }
    canvas.drawPath(mapleLeafPath(), paint)
    paint.shader = null
    paint.color = 0x806F3C31.toInt()
    paint.style = Paint.Style.STROKE
    paint.strokeWidth = 1.4f
    paint.strokeCap = Paint.Cap.ROUND
    canvas.drawLine(48f, 23f, 49f, 88f, paint)
    canvas.drawLine(49f, 66f, 29f, 47f, paint)
    canvas.drawLine(49f, 66f, 70f, 47f, paint)
    bmp.asImageBitmap()
}
