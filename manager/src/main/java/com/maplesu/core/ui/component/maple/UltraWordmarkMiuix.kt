package com.maplesu.core.ui.component.maple

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.unit.dp
import com.maplesu.core.ui.theme.isInDarkTheme
import top.yukonga.miuix.kmp.basic.ScrollBehavior
import top.yukonga.miuix.kmp.basic.TopAppBarDefaults
import top.yukonga.miuix.kmp.theme.MiuixTheme
import kotlin.math.roundToInt

/** miuix `TopAppBar` 里动作区的典型宽度：只用来算折叠标题的避让，和库内布局一致。 */
private val MiuixActionWidth = 56.dp

/** 大标题字重（miuix 0.9.4 写死 Normal）。 */
private val LargeTitleWeight = FontWeight.Normal

/** 折叠标题字重（miuix 0.9.4 写死 Medium）。 */
private val SmallTitleWeight = FontWeight.Medium

/** `Ultra` 比同行的 `MapleSU` 略重一档，字样才立得住。 */
private val WordWeight = FontWeight.Medium

/**
 * 叠在 miuix `TopAppBar` 上方的字样层。
 *
 * miuix 0.9.4 的 `TopAppBar` 标题只接受 String，没有 slot。这里不改库：
 *  - 大标题仍由 miuix 绘制 `MapleSU`，本层只补 `Ultra` 与点阵；
 *  - 折叠标题由调用方把颜色设为透明（文字仍在，无障碍读得到），本层画完整两段字。
 *
 * 位置按 miuix 布局公式换算：大标题左缘 = `TitlePadding`，顶边 = `CollapsedHeight + heightOffset`，
 * 透明度 = `1 - collapsedFraction * 3`；折叠标题在 `CollapsedHeight` 内垂直居中、水平居中。
 * 这些量都在绘制阶段读取，滚动时和 miuix 自身同一帧更新，不会错位。
 *
 * 调用方需把它放进与 `TopAppBar` 等大的 `Box` 里并传 `matchParentSize`。
 */
@Composable
fun UltraTopBarOverlayMiuix(
    state: UltraWordmarkState,
    scrollBehavior: ScrollBehavior,
    baseTitle: String,
    modifier: Modifier = Modifier,
) {
    val titleColor = MiuixTheme.colorScheme.onSurface
    val mainStyle = MiuixTheme.textStyles.main
    val largeSize = MiuixTheme.textStyles.title1.fontSize
    val smallSize = MiuixTheme.textStyles.title3.fontSize
    val dark = isInDarkTheme()

    val measurer = rememberTextMeasurer(cacheSize = 8)
    val large = remember(measurer, mainStyle, largeSize, titleColor, baseTitle) {
        val style = mainStyle.copy(fontSize = largeSize, fontWeight = LargeTitleWeight, color = titleColor)
        val full = measurer.measure("$baseTitle $ULTRA_WORD", style = style)
        TitleLayouts(
            base = measurer.measure(baseTitle, style = style),
            word = measurer.measure(ULTRA_WORD, style = style.copy(fontWeight = WordWeight)),
            wordOffset = full.getBoundingBox(baseTitle.length + 1).left,
            fullWidth = full.size.width.toFloat(),
        )
    }
    val small = remember(measurer, mainStyle, smallSize, titleColor, baseTitle) {
        val style = mainStyle.copy(fontSize = smallSize, fontWeight = SmallTitleWeight, color = titleColor)
        val full = measurer.measure("$baseTitle $ULTRA_WORD", style = style)
        TitleLayouts(
            base = measurer.measure(baseTitle, style = style),
            word = measurer.measure(ULTRA_WORD, style = style),
            wordOffset = full.getBoundingBox(baseTitle.length + 1).left,
            fullWidth = full.size.width.toFloat(),
        )
    }

    val palette = remember(dark) { ultraBrandPalette(dark) }
    val largeRenderer = remember(palette) { UltraWordmarkRenderer(palette, bloom = true) }
    val smallRenderer = remember(palette) { UltraWordmarkRenderer(palette, bloom = true) }

    val barState = scrollBehavior.state
    val smallVisible by remember(barState) { derivedStateOf { barState.collapsedFraction * 3f >= 1f } }
    val smallAlpha = animateFloatAsState(
        targetValue = if (smallVisible) 1f else 0f,
        animationSpec = tween(durationMillis = 200),
        label = "ultraSmallTitle",
    )

    Spacer(
        modifier = modifier
            .windowInsetsPadding(WindowInsets.displayCutout.only(WindowInsetsSides.Horizontal))
            .windowInsetsPadding(WindowInsets.navigationBars.only(WindowInsetsSides.Horizontal))
            .windowInsetsPadding(WindowInsets.systemBars.only(WindowInsetsSides.Top))
            .clipToBounds()
            // 独立图层：每帧重绘只重放这一层，不牵动顶栏其余内容。
            .graphicsLayer()
            .drawBehind {
                if (!state.visible) return@drawBehind
                val reveal = state.reveal.value
                val time = state.time.floatValue
                val collapsedHeight = TopAppBarDefaults.CollapsedHeight.toPx()
                val titlePadding = TopAppBarDefaults.TitlePadding.toPx()

                val largeAlpha = 1f - (barState.collapsedFraction * 3f).coerceIn(0f, 1f)
                if (largeAlpha > 0f) {
                    val wordTop = collapsedHeight + barState.heightOffset.roundToInt()
                    val wordLeft = titlePadding + large.wordOffset
                    val pitch = UltraBrandTokens.PITCH.toPx().roundToInt().coerceAtLeast(3)
                    val rows = UltraBrandTokens.ROWS
                    val fieldHeight = rows * pitch
                    val available = size.width - titlePadding
                    val capped = UltraBrandTokens.FIELD_MAX_WIDTH.toPx()
                    val fit = (available / large.fullWidth).coerceAtMost(1f)
                    scale(fit, pivot = Offset(titlePadding, wordTop)) {
                    drawText(large.base, topLeft = Offset(titlePadding, wordTop), alpha = largeAlpha)
                    with(largeRenderer) {
                        drawWordmark(
                            word = large.word,
                            wordLeft = wordLeft,
                            wordTop = wordTop,
                            fieldLeft = titlePadding,
                            fieldTop = wordTop + (large.word.size.height - fieldHeight) / 2f,
                            fieldWidth = available.coerceAtMost(capped),
                            pitchPx = pitch,
                            cellPx = UltraBrandTokens.CELL.toPx().roundToInt().coerceAtLeast(2),
                            rows = rows,
                            fadeEnd = available > capped,
                            reveal = reveal,
                            time = time,
                            alpha = largeAlpha,
                            intensity = 1f,
                        )
                    }
                    }
                }

                val small0 = smallAlpha.value
                if (small0 > 0f) {
                    val textPad = titlePadding
                    val fit = ((size.width - MiuixActionWidth.toPx() - textPad * 2f) / small.fullWidth).coerceIn(.1f, 1f)
                    var baseX = (size.width - (small.fullWidth * fit + textPad * 2f)) / 2f
                    val actionWidth = MiuixActionWidth.toPx()
                    if (baseX + small.fullWidth * fit + textPad * 2f > size.width - actionWidth) {
                        baseX = size.width - actionWidth - small.fullWidth * fit - textPad * 2f
                    }
                    val textLeft = baseX + textPad
                    val textTop = (collapsedHeight - small.base.size.height) / 2f + (1f - small0) * 20f
                    scale(fit, pivot = Offset(textLeft, collapsedHeight / 2f)) {
                    drawText(small.base, topLeft = Offset(textLeft, textTop), alpha = small0)

                    val pitch = UltraBrandTokens.COLLAPSED_PITCH.toPx().roundToInt().coerceAtLeast(3)
                    val rows = UltraBrandTokens.COLLAPSED_ROWS
                    val fieldHeight = rows * pitch
                    val wordLeft = textLeft + small.wordOffset
                    val fieldLeft = wordLeft
                    val fieldRight = size.width - actionWidth - 4.dp.toPx()
                    with(smallRenderer) {
                        drawWordmark(
                            word = small.word,
                            wordLeft = wordLeft,
                            wordTop = textTop,
                            fieldLeft = fieldLeft,
                            fieldTop = (collapsedHeight - fieldHeight) / 2f,
                            fieldWidth = fieldRight - fieldLeft,
                            pitchPx = pitch,
                            cellPx = UltraBrandTokens.COLLAPSED_CELL.toPx().roundToInt().coerceAtLeast(1),
                            rows = rows,
                            fadeEnd = false,
                            reveal = reveal,
                            time = time,
                            alpha = small0,
                            intensity = UltraBrandTokens.COLLAPSED_INTENSITY,
                        )
                    }
                    }
                }
            },
    )
}

private class TitleLayouts(
    val base: androidx.compose.ui.text.TextLayoutResult,
    val word: androidx.compose.ui.text.TextLayoutResult,
    val wordOffset: Float,
    val fullWidth: Float,
)
