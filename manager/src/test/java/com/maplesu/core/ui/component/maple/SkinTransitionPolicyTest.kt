package com.maplesu.core.ui.component.maple

import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.theme.AppSettings
import com.maplesu.core.ui.theme.ColorMode
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SkinTransitionPolicyTest {
    private val settings = AppSettings(ColorMode.SYSTEM, 0, PaletteStyle.TonalSpot, ColorSpec.SpecVersion.SPEC_2025)
    private val base = SkinRequest(UiMode.Miuix, settings, scene = false, systemDark = false)

    @Test fun sameAppearanceDoesNotCaptureAnotherFrame() {
        assertFalse(skinChangeNeedsTransition(base, base))
    }

    @Test fun bothSkinDirectionsReveal() {
        val material = base.copy(mode = UiMode.Material)
        assertTrue(skinChangeNeedsTransition(base, material))
        assertTrue(skinChangeNeedsTransition(material, base))
    }

    @Test fun leavingFirstRunPreviewRevealsHome() {
        assertTrue(skinChangeNeedsTransition(base, base.copy(scene = true)))
    }

    @Test fun systemDarkChangeIsAnIndependentRequest() {
        assertTrue(skinChangeNeedsTransition(base, base.copy(systemDark = true)))
    }

    @Test fun fixedThemeIgnoresSystemDarkChanges() {
        val light = base.copy(settings = settings.copy(colorMode = ColorMode.LIGHT))
        assertFalse(skinChangeNeedsTransition(light, light.copy(systemDark = true)))
    }

    @Test fun equivalentDarkModesDoNotFlash() {
        val dark = base.copy(settings = settings.copy(colorMode = ColorMode.DARK))
        assertFalse(skinChangeNeedsTransition(dark, dark.copy(settings = settings.copy(colorMode = ColorMode.MONET_DARK))))
    }

    @Test fun paletteOnlyChangeDoesNotCapture() {
        assertFalse(skinChangeNeedsTransition(base, base.copy(settings = settings.copy(keyColor = 0xFF8866AA.toInt()))))
    }
}
