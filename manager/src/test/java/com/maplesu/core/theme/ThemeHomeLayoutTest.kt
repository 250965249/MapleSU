package com.maplesu.core.theme

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class ThemeHomeLayoutTest {
    @Test fun originalLargeCardPreferenceMigratesWithoutFollowingTheThemeLayout() {
        assertEquals(ThemeHomeLayout.Large,ThemeHomeLayout.read(null,true))
        assertEquals(ThemeHomeLayout.Small,ThemeHomeLayout.read(null,false))
        assertEquals(ThemeHomeLayout.Small,ThemeHomeLayout.read("future",false))
        assertEquals(ThemeHomeLayout.Three,ThemeHomeLayout.read("three",false))
        assertEquals(ThemeHomeLayout.Three,ThemeHomeLayout.read("three",true))
        assertFalse(ThemeHomeLayout.PREFERENCE in ThemeRepository.ownedPreferences)
    }

    @Test fun upstreamLayoutsMapOnlyTheirStatusSurfaceAndNeverInventOtherCards() {
        val expected = mapOf("circle" to "", "kernelsu" to "grid_working_card_background",
            "focus" to "focus_card_kernel_bg", "dashboard_ui" to "dashboard_card_bg", "stats" to "")
        expected.forEach { (layout,base) ->
            assertEquals(base,ThemeHomeLayout.statusResource(JSONObject().put("homeLayoutStyle",layout)))
        }
        assertEquals("grid_working_card_background",ThemeHomeLayout.statusResource(
            JSONObject().put("homeLayoutStyle","stats").put("statsTopLayout","grid")))
        assertEquals("",ThemeHomeLayout.statusResource(JSONObject().put("homeLayoutStyle","future")))
    }
}
