package com.maplesu.core.ui

import com.maplesu.core.ui.util.AppearancePrefsPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MiuixEffectDefaultsTest {
    @Test fun missingChoiceUsesTheSelectedSkinDefault() {
        assertTrue(AppearancePrefsPolicy.effectiveMiuixEffect(null, isMiuix = true))
        assertFalse(AppearancePrefsPolicy.effectiveMiuixEffect(null, isMiuix = false))
    }

    @Test fun switchingSkinsKeepsAnExplicitlyDisabledEffectOff() {
        listOf(true, false, true).forEach { isMiuix ->
            assertFalse(AppearancePrefsPolicy.effectiveMiuixEffect(false, isMiuix))
        }
    }

    @Test fun switchingSkinsKeepsAnExplicitlyEnabledEffectOn() {
        listOf(false, true, false).forEach { isMiuix ->
            assertTrue(AppearancePrefsPolicy.effectiveMiuixEffect(true, isMiuix))
        }
    }

    @Test fun miuixDefaultsCoverExactlyTheFourRequestedEffects() {
        assertEquals(
            setOf("enable_blur", "enable_floating_bottom_bar", "enable_floating_bottom_bar_blur", "enable_predictive_back"),
            AppearancePrefsPolicy.MIUIX_EFFECT_KEYS,
        )
    }
}
