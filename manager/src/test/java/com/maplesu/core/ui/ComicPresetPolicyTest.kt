package com.maplesu.core.ui

import com.maplesu.core.ui.util.AppearancePrefsPolicy as Policy
import org.junit.Assert.*
import org.junit.Test

class ComicPresetPolicyTest {
    @Test fun compactPresetDisablesAllDecorativeNavigationEffects() {
        val values = Policy.comicPreset(false)
        listOf(Policy.HOME_LARGE_CARD, "snow_enabled", "troll_rain_enabled", "enable_blur",
            "enable_floating_bottom_bar", "enable_floating_bottom_bar_blur").forEach {
            assertEquals(it, false, values[it])
        }
        assertEquals(Policy.DECORATION_CHECK, values[Policy.DECORATION_SOURCE])
        assertEquals(false, values["status_decoration_hide_text"])
    }

    @Test fun comicPresetRestoresArtworkAndReadableFraming() {
        val values = Policy.comicPreset(true)
        listOf(Policy.HOME_LARGE_CARD, "snow_enabled", "enable_blur",
            "enable_floating_bottom_bar", "enable_floating_bottom_bar_blur").forEach {
            assertEquals(it, true, values[it])
        }
        assertEquals(Policy.DECORATION_COMIC, values[Policy.DECORATION_SOURCE])
        assertEquals(0, values["status_decoration_anchor"])
        assertEquals(1f, values["status_decoration_zoom"])
        assertEquals(false, values["status_decoration_hide_text"])
        assertFalse(values.keys.any { it.startsWith("wallpaper") || it == "ui_translucent" || it == "ui_mode" })
        assertEquals(false, values["troll_rain_enabled"])
    }

    @Test fun defaultUsesTheCheckmarkAndKeepsPreviouslySelectedCustomImages() {
        assertEquals(Policy.DECORATION_CHECK, Policy.decorationSource(null, false))
        assertEquals(Policy.DECORATION_CUSTOM, Policy.decorationSource(null, true))
    }

    @Test fun explicitCheckOrComicSelectionWinsOverSavedCustomFile() {
        assertEquals(Policy.DECORATION_CHECK, Policy.decorationSource(Policy.DECORATION_CHECK, true))
        assertEquals(Policy.DECORATION_COMIC, Policy.decorationSource(Policy.DECORATION_COMIC, true))
    }

    @Test fun missingSelectedImageUsesTheCheckmark() {
        assertEquals(Policy.DECORATION_CHECK, Policy.decorationSource(Policy.DECORATION_CUSTOM, false))
        assertEquals(Policy.DECORATION_CUSTOM, Policy.decorationSource(Policy.DECORATION_CUSTOM, true))
    }
}
