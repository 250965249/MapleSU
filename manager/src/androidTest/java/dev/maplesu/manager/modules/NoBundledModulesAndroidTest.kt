package dev.maplesu.manager.modules

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Test

/** The shipped manager has no module ZIPs to install on first launch or after removal. */
class NoBundledModulesAndroidTest {
    @Test fun managerShipsNoPreinstalledModules() {
        val assets = InstrumentationRegistry.getInstrumentation().targetContext.assets
        assertTrue("The APK must not contain bundled modules",
            assets.list("maplesu/bundled").orEmpty().isEmpty())
    }
}
