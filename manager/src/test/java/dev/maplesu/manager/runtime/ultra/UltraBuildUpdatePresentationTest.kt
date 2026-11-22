package dev.maplesu.manager.runtime.ultra

import java.io.File
import org.junit.Assert.*
import org.junit.Test

class UltraBuildUpdatePresentationTest {
    @Test fun sameVersionRepairHasItsOwnPresentation() {
        assertTrue(UltraEnvUpgrade.Available("5.1.0", "5.1.0").isBuildUpdate)
        assertFalse(UltraEnvUpgrade.Available("5.0.5", "5.1.0").isBuildUpdate)
        val panel = File("src/main/java/com/maplesu/core/ui/screen/settings/UltraEnvironmentPanel.kt").readText()
        assertTrue(panel.contains("else if (upgrade.isBuildUpdate)"))
        assertTrue(panel.contains("R.string.ultra_env_build_update_available"))
        assertTrue(panel.contains("R.string.ultra_env_build_update_confirm"))
    }

    @Test fun identicalDeployedHelperDoesNotPromptEvenIfTheBuildLabelChanged() {
        val same = "a".repeat(64)
        assertEquals(UltraEnvUpgrade.None, UltraEnvUpgradePolicy.decide(UltraEnvFacts(
            running = true, installedVersion = "5.1.0", bundledVersion = "5.1.0", identityKnown = true,
            installedBuildId = "maplesu-ultra-5.1.0-r9", bundledBuildId = "maplesu-ultra-5.1.0-r10",
            installedHelperSha256 = same, bundledHelperSha256 = same,
        )))
    }
}
