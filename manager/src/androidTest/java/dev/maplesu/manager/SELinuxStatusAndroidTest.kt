package dev.maplesu.manager

import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.ui.util.getSELinuxStatusRaw
import dev.maplesu.manager.runtime.MapleSuRuntime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

class SELinuxStatusAndroidTest {
    @Test fun displayedStatusMatchesReadOnlyAuthenticatedQuery() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val expected = MapleSuRuntime.openShell(context).use { shell ->
            val result = shell.newJob().add("/system/bin/getenforce")
                .to(ArrayList<String>(), ArrayList<String>()).exec()
            assertTrue(result.err.joinToString("\n"), result.isSuccess)
            result.out.joinToString("\n").trim()
        }
        assertTrue(expected, expected in setOf("Enforcing", "Permissive", "Disabled"))
        assertEquals(expected, getSELinuxStatusRaw())
    }
}
