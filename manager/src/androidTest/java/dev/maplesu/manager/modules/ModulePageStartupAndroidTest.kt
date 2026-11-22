package dev.maplesu.manager.modules

import android.os.Bundle
import android.os.SystemClock
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.data.repository.ModuleRepositoryImpl
import com.maplesu.core.ui.MainActivity
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Opt-in real repository read, including the production five-second page deadline. */
class ModulePageStartupAndroidTest {
    @Test fun coldModuleListCompletesWithinThePageBudget() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val args = InstrumentationRegistry.getArguments()
        assumeTrue(args.getString("verifyModulePageStartup") == "true")
        val launchStart = SystemClock.elapsedRealtime()
        ActivityScenario.launch(MainActivity::class.java).use {
            val activityLaunchMillis = SystemClock.elapsedRealtime() - launchStart
            assertEquals(WorkMode.LITE, runBlocking { ModeRuntime.awaitPageMode(5_000) })
            val modeReadyMillis = SystemClock.elapsedRealtime() - launchStart
            assertTrue("Mode detection took ${modeReadyMillis}ms", modeReadyMillis < 5_000)
            val start = SystemClock.elapsedRealtime()
            val result = runBlocking { ModuleRepositoryImpl().getModules() }
            val modules = result.getOrElse { throw AssertionError("Cold module repository failed", it) }
            val elapsed = SystemClock.elapsedRealtime() - start
            val expected = args.getString("minimumModules")?.toInt() ?: 1
            assertTrue("Expected installed modules, got ${modules.size}", modules.size >= expected)
            assertTrue("Module query exceeded its page budget: ${elapsed}ms", elapsed < 5_000)
            instrumentation.sendStatus(2, Bundle().apply {
                putLong("coldActivityLaunchMillis", activityLaunchMillis)
                putLong("coldModeReadyMillis", modeReadyMillis)
                putLong("coldManagementReadyMillis", SystemClock.elapsedRealtime() - launchStart)
                putLong("coldModuleListMillis", elapsed)
                putInt("moduleCount", modules.size)
            })
        }
    }
}
