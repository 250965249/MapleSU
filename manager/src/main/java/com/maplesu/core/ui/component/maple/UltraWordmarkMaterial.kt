package com.maplesu.core.ui.component.maple

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.LocalContentColor
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.text.drawText
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.text
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import com.maplesu.core.ui.theme.isInDarkTheme
import kotlin.math.roundToInt

/**
 * `LargeFlexibleTopAppBar` 的标题 slot。
 *
 * 大、小两行标题各组合一份，文字样式来自 slot 提供的 [LocalTextStyle]，折叠淡入淡出由 M3 负责。
 * Material 皮肤的字样：同样的点阵，没有辉光，边缘利落。
 *
 * [state] 为 null 或不可见时就是普通标题；从右到左的语言下字样无法按设计展开，退回纯文字。
 */
@Composable
fun UltraTitleMaterial(
    state: UltraWordmarkState?,
    baseTitle: String,
    modifier: Modifier = Modifier,
) {
    if (state == null || !state.visible) {
        Text(text = baseTitle, modifier = modifier, maxLines = 1, overflow = TextOverflow.Ellipsis)
        return
    }
    if (LocalLayoutDirection.current == LayoutDirection.Rtl) {
        Text(text = "$baseTitle $ULTRA_WORD", modifier = modifier, maxLines = 1, overflow = TextOverflow.Ellipsis)
        return
    }

    val textStyle = LocalTextStyle.current.copy(color = LocalContentColor.current)
    val base = rememberTextMeasurer().measure(baseTitle, style = textStyle)
    val dark = isInDarkTheme()
    val measurer = rememberTextMeasurer(cacheSize = 4)
    val word = remember(measurer, textStyle) {
        measurer.measure(ULTRA_WORD, style = textStyle.copy(fontWeight = FontWeight.Medium))
    }
    val wordOffset = remember(measurer, textStyle, baseTitle) {
        measurer.measure("$baseTitle $ULTRA_WORD", style = textStyle).getBoundingBox(baseTitle.length + 1).left
    }
    val renderer = remember(dark) { UltraWordmarkRenderer(ultraBrandPalette(dark), bloom = false) }

    Box(modifier = modifier.fillMaxWidth().clearAndSetSemantics { text = AnnotatedString("$baseTitle $ULTRA_WORD"); heading() }) {
        Text(text = baseTitle, color = Color.Transparent, maxLines = 1, overflow = TextOverflow.Clip)
        Spacer(
            modifier = Modifier
                .matchParentSize()
                .clipToBounds()
                .graphicsLayer()
                .drawBehind {
                    val pitch = UltraBrandTokens.PITCH.toPx().roundToInt().coerceAtLeast(3)
                    val rows = (size.height / pitch).toInt().coerceIn(1, UltraBrandTokens.ROWS)
                    val capped = UltraBrandTokens.FIELD_MAX_WIDTH.toPx()
                    val fit = (size.width / (wordOffset + word.size.width)).coerceAtMost(1f)
                    scale(fit, pivot = Offset(0f, size.height / 2f)) {
                    drawText(base, topLeft = Offset(0f, (size.height - base.size.height) / 2f))
                    with(renderer) {
                        drawWordmark(
                            word = word,
                            wordLeft = wordOffset,
                            wordTop = (size.height - word.size.height) / 2f,
                            fieldLeft = 0f,
                            fieldTop = (size.height - rows * pitch) / 2f,
                            fieldWidth = size.width.coerceAtMost(capped),
                            pitchPx = pitch,
                            cellPx = UltraBrandTokens.CELL.toPx().roundToInt().coerceAtLeast(2),
                            rows = rows,
                            fadeEnd = false,
                            reveal = state.reveal.value,
                            time = state.time.floatValue,
                            alpha = 1f,
                            intensity = 1f,
                        )
                    }
                    }
                },
        )
    }
}
