package com.maplesu.core.ui.theme

import android.graphics.Typeface
import androidx.compose.material3.Typography
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import com.maplesu.core.theme.ThemeRuntime
import com.maplesu.core.theme.ThemeStartupResource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import top.yukonga.miuix.kmp.theme.TextStyles

@Composable
internal fun themeFontFamily(): FontFamily? {
    val context = LocalContext.current
    val j = ThemeRuntime.observe()
    val mode = j.optString("fontMode", if (j.optBoolean("isFontEnabled")) "custom" else "app")
    val file = remember(j) { if (mode == "custom") ThemeRuntime.file(context,"font") else null }
    return key(file?.absolutePath,mode) {
        var loaded by remember { mutableStateOf(mode != "custom" || file == null) }
        val family by produceState<FontFamily?>(if (mode == "system") FontFamily.Default else null) {
            value = when (mode) {
                "system" -> FontFamily.Default
                "custom" -> file?.let { withContext(Dispatchers.IO) { runCatching { FontFamily(Typeface.createFromFile(it)) }.getOrNull() } }
                else -> null
            }
            loaded = true
        }
        ThemeStartupResource(loaded)
        family
    }
}

internal fun Typography.withFamily(f: FontFamily?) = if (f == null) this else copy(
    displayLarge=displayLarge.copy(fontFamily=f),displayMedium=displayMedium.copy(fontFamily=f),displaySmall=displaySmall.copy(fontFamily=f),
    headlineLarge=headlineLarge.copy(fontFamily=f),headlineMedium=headlineMedium.copy(fontFamily=f),headlineSmall=headlineSmall.copy(fontFamily=f),
    titleLarge=titleLarge.copy(fontFamily=f),titleMedium=titleMedium.copy(fontFamily=f),titleSmall=titleSmall.copy(fontFamily=f),
    bodyLarge=bodyLarge.copy(fontFamily=f),bodyMedium=bodyMedium.copy(fontFamily=f),bodySmall=bodySmall.copy(fontFamily=f),
    labelLarge=labelLarge.copy(fontFamily=f),labelMedium=labelMedium.copy(fontFamily=f),labelSmall=labelSmall.copy(fontFamily=f),
    displayLargeEmphasized=displayLargeEmphasized.copy(fontFamily=f),displayMediumEmphasized=displayMediumEmphasized.copy(fontFamily=f),displaySmallEmphasized=displaySmallEmphasized.copy(fontFamily=f),
    headlineLargeEmphasized=headlineLargeEmphasized.copy(fontFamily=f),headlineMediumEmphasized=headlineMediumEmphasized.copy(fontFamily=f),headlineSmallEmphasized=headlineSmallEmphasized.copy(fontFamily=f),
    titleLargeEmphasized=titleLargeEmphasized.copy(fontFamily=f),titleMediumEmphasized=titleMediumEmphasized.copy(fontFamily=f),titleSmallEmphasized=titleSmallEmphasized.copy(fontFamily=f),
    bodyLargeEmphasized=bodyLargeEmphasized.copy(fontFamily=f),bodyMediumEmphasized=bodyMediumEmphasized.copy(fontFamily=f),bodySmallEmphasized=bodySmallEmphasized.copy(fontFamily=f),
    labelLargeEmphasized=labelLargeEmphasized.copy(fontFamily=f),labelMediumEmphasized=labelMediumEmphasized.copy(fontFamily=f),labelSmallEmphasized=labelSmallEmphasized.copy(fontFamily=f),
)

internal fun TextStyles.withFamily(f: FontFamily?) = if (f == null) this else copy(
    main=main.copy(fontFamily=f),paragraph=paragraph.copy(fontFamily=f),body1=body1.copy(fontFamily=f),body2=body2.copy(fontFamily=f),
    button=button.copy(fontFamily=f),footnote1=footnote1.copy(fontFamily=f),footnote2=footnote2.copy(fontFamily=f),
    headline1=headline1.copy(fontFamily=f),headline2=headline2.copy(fontFamily=f),subtitle=subtitle.copy(fontFamily=f),
    title1=title1.copy(fontFamily=f),title2=title2.copy(fontFamily=f),title3=title3.copy(fontFamily=f),title4=title4.copy(fontFamily=f),
)
