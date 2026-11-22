package com.maplesu.core.ui.util

/**
 * 外观设置的**纯映射/策略**（不依赖 Android，可在普通 JVM 上断言）。
 *
 * 收口三件事，避免同一个换算散落在两套皮肤 / Repository / 测试里：
 * · 「界面扁平化」已下线：旧键 `flat_home` 仍可读（兼容），但取值**恒为 false**；
 * · 「界面透明化」恢复：默认**关**，第一次选壁纸时自动打开（用户手动关过则尊重用户）；
 *   `ui_translucent_alpha` 仍按原有 0.02~1.0 语义保存与钳制；
 * · 壁纸类型判空：`""` / `"none"` 都算没有壁纸（纯主题背景，不铺任何默认图）。
 */
object AppearancePrefsPolicy {

    const val HOME_LARGE_CARD = "home_large_card"
    const val DECORATION_SOURCE = "status_decoration_source"
    const val DECORATION_COMIC = "comic"
    const val DECORATION_CHECK = "check"
    const val DECORATION_CUSTOM = "custom"

    /** Comic artwork is explicit; an unset choice uses the checkmark or a saved custom image. */
    fun decorationSource(stored: String?, hasCustom: Boolean): String = when (stored) {
        DECORATION_CHECK, DECORATION_COMIC -> stored
        DECORATION_CUSTOM -> if (hasCustom) DECORATION_CUSTOM else DECORATION_CHECK
        else -> if (hasCustom) DECORATION_CUSTOM else DECORATION_CHECK
    }

    /** Apply a whole preset in one preference transaction; independent controls stay independent. */
    fun comicPreset(enabled: Boolean): Map<String, Any> = mapOf(
        HOME_LARGE_CARD to enabled,
        "snow_enabled" to enabled,
        "troll_rain_enabled" to false,
        "enable_blur" to enabled,
        "enable_floating_bottom_bar" to enabled,
        "enable_floating_bottom_bar_blur" to enabled,
        DECORATION_SOURCE to if (enabled) DECORATION_COMIC else DECORATION_CHECK,
        "status_decoration_anchor" to 0,
        "status_decoration_bias_x" to 0f,
        "status_decoration_bias_y" to 0f,
        "status_decoration_zoom" to 1f,
        "status_decoration_dim" to 0.35f,
        "status_decoration_hide_text" to false,
    )

    val MIUIX_EFFECT_KEYS = setOf(
        "enable_blur", "enable_floating_bottom_bar", "enable_floating_bottom_bar_blur",
        "enable_predictive_back",
    )

    /** A stored choice, including false, always wins over the skin's default. */
    fun effectiveMiuixEffect(stored: Boolean?, isMiuix: Boolean): Boolean = stored ?: isMiuix

    /** 「界面透明化」默认关闭（用户要求：默认关，选壁纸后自动打开）。 */
    const val DEFAULT_TRANSLUCENT: Boolean = false

    /** 原实现的透明度默认值 / 下限：0.02 = 几乎全透明，1.0 = 不透明。 */
    const val DEFAULT_TRANSLUCENT_ALPHA: Float = 0.02f
    const val MIN_TRANSLUCENT_ALPHA: Float = 0.02f
    const val MAX_TRANSLUCENT_ALPHA: Float = 1f

    private const val VISIBILITY_SPAN = 1f - MIN_TRANSLUCENT_ALPHA

    /**
     * 「界面扁平化」的最终生效值：**恒 false**。
     *
     * 设置页已不再渲染该开关；这里仍接收旧键的值只是为了兼容读取，
     * 不会因为旧版本写过 `flat_home=true` 就让界面变扁平。
     */
    fun effectiveFlatUi(stored: Boolean): Boolean = stored.let { false }

    /** `null` = prefs 里没有这个键（走默认值 false）；有值则原样沿用。 */
    fun effectiveTranslucent(stored: Boolean?): Boolean = stored ?: DEFAULT_TRANSLUCENT

    /** 旧版本可能写过越界值；读写都收口到 [MIN_TRANSLUCENT_ALPHA]~[MAX_TRANSLUCENT_ALPHA]。 */
    fun normalizeTranslucentAlpha(stored: Float): Float =
        stored.coerceIn(MIN_TRANSLUCENT_ALPHA, MAX_TRANSLUCENT_ALPHA)

    /**
     * 用户选好壁纸后是否要顺手打开「界面透明化」。
     *
     * 只在 `ui_translucent` **从未保存过**时自动打开；用户主动关过
     * （键存在且为 false）就不再覆盖他的选择。
     */
    fun autoEnableTranslucentOnWallpaperPick(hasStoredPreference: Boolean): Boolean =
        !hasStoredPreference

    /** 设置页「壁纸可见度」滑杆值(0~1) ← alpha(0.02~1)。 */
    fun visibilityForAlpha(alpha: Float): Float =
        ((1f - normalizeTranslucentAlpha(alpha)) / VISIBILITY_SPAN).coerceIn(0f, 1f)

    /** 设置页「壁纸可见度」滑杆值(0~1) → alpha(0.02~1)。 */
    fun alphaForVisibility(visibility: Float): Float =
        normalizeTranslucentAlpha(1f - visibility.coerceIn(0f, 1f) * VISIBILITY_SPAN)

    /** 壁纸类型是否代表"有壁纸"：空串 / `none` 都算没有（纯主题背景）。 */
    fun hasWallpaper(kind: String): Boolean = kind.isNotEmpty() && kind != "none"
}
