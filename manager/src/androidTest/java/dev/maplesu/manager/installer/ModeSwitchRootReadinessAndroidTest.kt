package dev.maplesu.manager.installer

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.core.app.ActivityScenario
import android.os.Bundle
import com.maplesu.core.ui.MainActivity
import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootExec
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.workmode.service.ModeSwitchRootSession
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Opt-in, read-only production Binder/FD integration; never acquires a lease or writes a partition. */
class ModeSwitchRootReadinessAndroidTest {
    @Test(timeout = 90_000)
    fun concurrentManagerSessionsShareTheTokenAndKeepRootAccess() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyModeSwitchRoot") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        ActivityScenario.launch(MainActivity::class.java).use {
            assertEquals(UltraEnvironmentProbe.State.Running, UltraEnvironmentProbe.refresh(context))
            val workers = Executors.newFixedThreadPool(4)
            val start = CountDownLatch(1)
            try {
                val results = (0 until 8).map {
                    workers.submit {
                        check(start.await(5, TimeUnit.SECONDS))
                        val session = ModeSwitchRootSession(context)
                        val ready = session.ensureReady()
                        assertTrue("Concurrent root readiness failed: ${ready.code}", ready.ok)
                        val result = session.execute("/system/bin/id -u")
                        assertTrue("Concurrent root command failed: ${result.detail}", result.ok)
                        assertEquals("0", result.output.trim())
                    }
                }
                start.countDown()
                results.forEach { it.get(30, TimeUnit.SECONDS) }
            } finally {
                start.countDown()
                workers.shutdownNow()
                assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS))
            }
        }
    }

    @Test
    fun ultraRootSurvivesBinderHandoverAndASecondManagerSession() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyModeSwitchRoot") == "true")
        // Exercise the foreground manager flow; this device freezes background-only test apps.
        ActivityScenario.launch(MainActivity::class.java).use { verifyProductionRoot() }
    }

    private fun verifyProductionRoot() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        stage("ultra-refresh")
        assertEquals(UltraEnvironmentProbe.State.Running, UltraEnvironmentProbe.refresh(context))
        stage("ultra-id")
        val root = RootExec.execute(context, "/system/bin/id -u")
        assertTrue("Ultra root failed: ${root.detail}", root.ok)
        assertEquals(RootBackend.ULTRA_ENV, root.backend)
        assertEquals("0", root.output.trim())
        stage("ui-capability")
        assertTrue("Ultra UI must observe its available Ultra root without a legacy shell",
            com.maplesu.core.ui.util.rootAvailable())

        repeat(2) { sessionIndex ->
            stage("session-$sessionIndex-ready")
            val session = ModeSwitchRootSession(context)
            val ready = session.ensureReady()
            assertTrue("Mode root readiness failed: ${ready.code}", ready.ok)
            repeat(2) { commandIndex ->
                stage("session-$sessionIndex-id-$commandIndex")
                val result = session.execute("/system/bin/id -u")
                assertTrue("Mode root command failed: ${result.detail}", result.ok)
                assertEquals("0", result.output.trim())
            }
        }
        // The same discovery entry used by the installation page, without stock restore or flash.
        stage("install-discovery")
        StockInstallPreflight.discoverTarget(context, InstallTargetMode.ULTRA)
        stage("complete")
    }

    private fun stage(value: String) {
        InstrumentationRegistry.getInstrumentation().sendStatus(2, Bundle().apply {
            putString("stage", value)
        })
    }
}
