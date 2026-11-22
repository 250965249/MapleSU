package dev.maplesu.manager.installer

import org.junit.Assert.assertEquals
import org.junit.Test

class VivoCompatibilityStatusTest {
    @Test fun bothModesRequireTheirActualFilterStatus() {
        VivoCompatibilityStatus.requireActive("LITE", "Y\n", "other 1 0 - Live 0\n")
        VivoCompatibilityStatus.requireActive("KSU", "Feature: vr_filter (7)\nValue: 1\nStatus: enabled\n", "")
        for ((mode, status) in listOf("LITE" to "N", "LITE" to "", "KSU" to "Value: 1\n",
            "KSU" to "Feature: vr_filter (7)\nValue: 0", "KSU" to "Feature 'vr_filter' is not supported by kernel")) {
            assertEquals("INSTALLER_VR_FILTER_INACTIVE", runCatching {
                VivoCompatibilityStatus.requireActive(mode, status, "")
            }.exceptionOrNull()?.message)
        }
    }

    @Test fun loadedVrFailsEvenWhenTheHookIsActiveAndSimilarNamesRemainAllowed() {
        VivoCompatibilityStatus.requireActive("LITE", "1", "vrouter 1 0 - Live 0\nvklp 1 0 - Live 0\n")
        assertEquals("INSTALLER_VR_ALREADY_LOADED", runCatching {
            VivoCompatibilityStatus.requireActive("LITE", "Y", "other 1 0 - Live 0\nvr 1 0 - Live 0\n")
        }.exceptionOrNull()?.message)
    }
}
