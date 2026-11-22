package com.maplesu.core.theme

import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.compositeOver
import androidx.compose.ui.graphics.luminance
import org.junit.Assert.*
import org.junit.Test

class ThemeWallpaperTest {
    @Test fun wallpaperCardsKeepReadableBodyAndSummaryInkAtFullTransparency() {
        for (dark in listOf(false,true)) {
            val original = if (dark) darkColorScheme() else lightColorScheme()
            val adapted = original.withThemeWallpaper(ThemeWallpaperStyle(0f,dark,0f))
            for (wallpaper in listOf(Color.Black,Color.White)) {
                val surface = adapted.surfaceContainer.compositeOver(wallpaper)
                for (ink in listOf(adapted.onSurface,adapted.onSurfaceVariant)) {
                    val a=ink.luminance(); val b=surface.luminance()
                    val contrast=(maxOf(a,b)+.05f)/(minOf(a,b)+.05f)
                    assertTrue("dark=$dark contrast=$contrast",contrast>=4.5f)
                }
            }
        }
    }
    @Test fun surfaceRolesKeepMapleCardDefinitionWithoutMultiplyingTheCanvas() {
        val style = ThemeWallpaperStyle(.2f,false,.2f)
        assertTrue(style.group in .64f..1f); assertTrue(style.raised >= style.group)
        assertEquals(.28f,style.chrome,.001f); assertEquals(.56f,style.selection,.001f)
        assertEquals(.96f,style.overlay,.001f)
        assertEquals(0f,darkColorScheme().withThemeWallpaper(style).background.alpha,.001f)
        assertEquals(style.group,darkColorScheme().withThemeWallpaper(style).surfaceContainer.alpha,.001f)
        assertEquals(.2f,style.dim,.001f)
        assertTrue(ThemeWallpaperStyle(0f,true,0f).group < 1f)
        assertEquals(1f,ThemeWallpaperStyle(1f,false,0f).group,.001f)
    }
    @Test fun imagePolarityNeverFlipsDarkThemeOrUsesTheDimAsAnInput() {
        assertTrue(useThemeDarkNeutral(true,1f)); assertTrue(useThemeDarkNeutral(false,.2f))
        assertFalse(useThemeDarkNeutral(false,.8f)); assertFalse(useThemeDarkNeutral(false,-1f))
    }
    @Test fun photoTextTracksTheDecodedImageAndItsOwnDim() {
        assertEquals(androidx.compose.ui.graphics.Color(0xFF141218),themePhotoForeground(.9f,0f))
        assertEquals(androidx.compose.ui.graphics.Color.White,themePhotoForeground(.2f,0f))
        assertEquals(androidx.compose.ui.graphics.Color.White,themePhotoForeground(.9f,.5f))
        assertEquals(androidx.compose.ui.graphics.Color.White,themePhotoForeground(-1f,0f))
    }
}
