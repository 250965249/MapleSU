package dev.maplesu.manager.runtime.ultra

import java.io.File
import org.junit.Assert.*
import org.junit.Test

class UltraEnvironmentInstallReadinessWiringTest {
    @Test fun explicitInstallDelegatesToTheSdkWithoutASeparateChannelGate() {
        val panel = File("src/main/java/com/maplesu/core/ui/screen/settings/UltraEnvironmentSettings.kt")
            .readText().substringAfter("class UltraEnvironmentInstallPanel")
        assertFalse("single Channel observations must not gate explicit SDK installation", panel.contains("testBasics(\"Channel\")"))
        assertTrue(panel.contains("UltraEnvironmentInstaller.Intent.InstallToBundledBuild"))
        assertTrue(panel.contains("UltraEnvironmentInstallReadiness.NotChecked"))
        for (ui in listOf("HomeMaterial.kt", "HomeMiuix.kt")) {
            assertTrue("Missing image recovery route in $ui",
                File("src/main/java/com/maplesu/core/ui/screen/home/$ui").readText()
                    .contains("onInstallImage = actions.onInstallClick"))
        }
    }
}
