package com.maplesu.core.ui.screen.install

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Access errors must keep their meaning rather than becoming a missing-root assertion. */
class InstallSourceFailureWiringTest {
    @Test fun directSourceDoesNotMapEveryFailureToMissingRoot() {
        val source = File("src/main/java/com/maplesu/core/ui/screen/install/InstallSteps.kt").readText()
        val status = source.substringAfter("internal fun InstallSourceStatusSection")
            .substringBefore("internal fun InstallOriginalImageSection")
        assertFalse(status.contains("else -> R.string.install_source_root_required"))
        assertTrue(status.contains("InstallSourceAccessFailure.CHANNEL_UNAVAILABLE"))
    }

    @Test fun onlyDirectPreflightRetainsAccessFailureClassification() {
        val source = File("src/main/java/com/maplesu/core/ui/screen/install/InstallScreen.kt").readText()
        val direct = source.substringAfter("LaunchedEffect(sourceRequest,")
            .substringBefore("val selectFileTip")
        val guard = direct.indexOf("installMethod != InstallMethod.DirectInstall || !existingRootConflictAccepted")
        val discover = direct.indexOf("StockInstallPreflight.discoverTarget(context, targetMode)")
        assertTrue("Only an explicitly accepted direct install may request access", guard in 0 until discover)
        assertFalse(direct.contains("StockInstallPreflight.inspect("))
        val classification = "sourceAccessFailure = installSourceAccessFailure(error, rootWasRunning || UltraEnvironmentProbe.isRunning())"
        assertTrue(direct.contains(classification))
        assertEquals(1, Regex(Regex.escape(classification)).findAll(source).count())
        val selected = source.substringAfter("val selectImageLauncher =")
            .substringBefore("val normalDecision =")
        assertTrue(selected.contains("installMethod = InstallMethod.SelectFile(uri, summary = selectFileTip)"))
        assertFalse(selected.contains("StockInstallPreflight"))
        assertFalse(selected.contains("UltraEnvironmentProbe"))
        assertFalse(selected.contains("showConflict = true"))
        assertFalse(source.contains("filePreflightRequested"))
        assertFalse(source.contains("sourceAccessFailed = true"))
    }
}
