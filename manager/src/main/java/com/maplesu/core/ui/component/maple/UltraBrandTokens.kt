package com.maplesu.core.ui.component.maple

import androidx.compose.runtime.Immutable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

/**
 * Ultra 字样的全部可调参数，装机目视后只改这里。
 *
 * 颜色是规范 §4 明确的品牌色，只用于字样与点阵，不进入用户主题。
 */
internal object UltraBrandTokens {
    // ── 开场时序 ─────────────────────────────────────────────
    /** 判定落定后先让 `MapleSU` 停留的时间，避免和闪屏退场重叠。 */
    const val INTRO_HOLD_MS = 280L

    /** 开场总长（规范约 900ms）。 */
    const val INTRO_DURATION_MS = 900

    /** 像素波头部的亮带宽度。 */
    val SWEEP_CREST = 44.dp

    /** 波头经过后，点阵回落到常驻亮度所需的距离。 */
    val SWEEP_SETTLE = 96.dp

    /** 波头前缘的抖动宽度，让边缘呈颗粒状而不是一条直线。 */
    val SWEEP_DITHER = 16.dp

    /** `Ultra` 展开时从左侧滑入的距离。 */
    val WORD_SLIDE = 10.dp

    // ── 点阵网格 ─────────────────────────────────────────────
    val PITCH = 4.dp
    val CELL = 2.6.dp
    const val ROWS = 10

    val COLLAPSED_PITCH = 3.2.dp
    val COLLAPSED_CELL = 2.dp
    const val COLLAPSED_ROWS = 6

    /** 字母内亮斑用更细的网格，笔画里才放得下。 */
    val LETTER_PITCH = 2.4.dp
    val LETTER_CELL = 1.8.dp

    /** 大屏上点阵不铺满整条顶栏。 */
    val FIELD_MAX_WIDTH = 560.dp

    /** 点阵短于这个宽度时不画（小窗、折叠态空间不够）。 */
    val FIELD_MIN_WIDTH = 28.dp

    // ── 流动 ─────────────────────────────────────────────────
    /** 从标题左缘算起，这段比例内几乎不亮，保证 `MapleSU` 干净。 */
    const val RAMP_START = 0.16f
    const val RAMP_POWER = 1.75f

    val SWELL_WAVELENGTH = 170.dp
    val SWELL_SPEED = 48.dp
    val SPOT_WAVELENGTH = 62.dp
    val SPOT_SPEED = 72.dp
    val TWINKLE_WAVELENGTH = 23.dp
    val TWINKLE_SPEED = 96.dp
    val LETTER_WAVELENGTH = 58.dp
    val LETTER_SPEED = 64.dp

    /** 字样范围内点阵的压暗系数，保证字可读。 */
    const val UNDER_WORD_DIM = 0.26f

    /** 折叠后点阵整体更克制。 */
    const val COLLAPSED_INTENSITY = 0.72f

    // ── 辉光（仅 Miuix）────────────────────────────────────
    val BLOOM_WIDE = 9.dp
    val BLOOM_NEAR = 4.dp

    /** 开场时辉光的过冲量。 */
    const val BLOOM_OVERSHOOT = 0.4f
    const val AMBIENT_BREATH_SECONDS = 4.6f

    /** 字母内亮斑的强度上限。 */
    const val LETTER_SPARK_GAIN = 0.85f
}

/** 一种明暗下的全套品牌配色。 */
@Immutable
internal data class UltraBrandPalette(
    val wordStart: Color,
    val wordEnd: Color,
    val bloom: Color,
    val bloomAlpha: Float,
    val ambientAlpha: Float,
    /** 由暗到亮的点阵色阶。 */
    val cells: List<Color>,
    /** 点阵不透明度增益，浅色下压低以保证可读。 */
    val cellGain: Float,
    /** 点阵不透明度上限。 */
    val cellCeiling: Float,
    /** 字母内亮斑颜色。 */
    val spark: Color,
)

private val DarkPalette = UltraBrandPalette(
    wordStart = Color(0xFFC4A1FF),
    wordEnd = Color(0xFF8B5CF6),
    bloom = Color(0xFF8B5CF6),
    bloomAlpha = 0.9f,
    ambientAlpha = 0.16f,
    cells = listOf(
        Color(0xFF3B1F7A),
        Color(0xFF5B2EC0),
        Color(0xFF8B5CF6),
        Color(0xFFA780FA),
        Color(0xFFC4A1FF),
        Color(0xFFDDC8FF),
        Color(0xFFF3E8FF),
    ),
    cellGain = 1.5f,
    cellCeiling = 1f,
    spark = Color(0xFFF3E8FF),
)

private val LightPalette = UltraBrandPalette(
    wordStart = Color(0xFF7C3AED),
    wordEnd = Color(0xFF5B21B6),
    bloom = Color(0xFF7C3AED),
    bloomAlpha = 0.38f,
    ambientAlpha = 0.07f,
    cells = listOf(
        Color(0xFFC9B6F2),
        Color(0xFFA88AEE),
        Color(0xFF8B5CF6),
        Color(0xFF7C3AED),
        Color(0xFF6D28D9),
        Color(0xFF5B21B6),
        Color(0xFF4C1D95),
    ),
    cellGain = 1.05f,
    cellCeiling = 0.72f,
    spark = Color(0xFFE9D5FF),
)

internal fun ultraBrandPalette(dark: Boolean): UltraBrandPalette = if (dark) DarkPalette else LightPalette
