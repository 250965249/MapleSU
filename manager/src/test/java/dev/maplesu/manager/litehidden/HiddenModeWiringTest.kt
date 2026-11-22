package dev.maplesu.manager.litehidden

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

class HiddenModeWiringTest {
    @Test
    fun startupRegistersLazyRecoveryBeforeAnyModeOrWatcherEarlyReturn() {
        val source = File("src/main/java/dev/maplesu/manager/litehidden/HiddenModeWiring.kt").readText()
        val startup = source.substringAfter("fun installOnStartup(context: Context)")
            .substringBefore("/** 立即装配")
        val provider = startup.indexOf("HiddenModeBackends.ensureProvider =")
        assertTrue("Late mode detection needs a production lazy provider", provider >= 0)
        assertTrue(provider < startup.indexOf("if (ModeRuntime.active != null)"))
        assertTrue(startup.substring(provider).substringBefore("if (ModeRuntime.active != null)")
            .contains("installNow(app)"))
        assertTrue(source.substringAfter("internal fun resetForTest()").contains("ensureProvider = null"))
    }
}
