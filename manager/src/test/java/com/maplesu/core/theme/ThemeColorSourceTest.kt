package com.maplesu.core.theme

import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.maplesu.core.ui.theme.AppSettings
import com.maplesu.core.ui.theme.ColorMode
import org.junit.Assert.*
import org.junit.Test

class ThemeColorSourceTest {
    @Test fun wallpaperAccentTakesPriorityOverSystemDynamicColorInBothSkins() {
        val settings = AppSettings(ColorMode.SYSTEM,0xff6750a4.toInt(),PaletteStyle.TonalSpot,
            ColorSpec.SpecVersion.SPEC_2025,dynamicColor=true,wallpaperColor=0xff006876.toInt())
        assertFalse(settings.effectiveDynamicColor)
        assertEquals(0xff006876.toInt(),settings.effectiveKeyColor)
        assertTrue(settings.copy(wallpaperColor=0).effectiveDynamicColor)
        assertEquals(0xff6750a4.toInt(),settings.copy(wallpaperColor=0).effectiveKeyColor)
    }
}
