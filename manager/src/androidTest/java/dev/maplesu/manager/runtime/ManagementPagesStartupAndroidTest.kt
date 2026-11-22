package dev.maplesu.manager.runtime

import android.os.Bundle
import android.os.SystemClock
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.data.repository.ModuleRepositoryImpl
import com.maplesu.core.data.repository.SuperUserRepositoryImpl
import com.maplesu.core.ui.MainActivity
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Opt-in cold reads against both real repositories while boot preparation is active. */
class ManagementPagesStartupAndroidTest {
    @Test fun coldModuleAndSuperuserReadsBothCompleteWithinTheirPageBudget() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val args = InstrumentationRegistry.getArguments()
        assumeTrue(args.getString("verifyManagementPagesStartup") == "true")
        val launchStart = SystemClock.elapsedRealtime()
        ActivityScenario.launch(MainActivity::class.java).use {
            val activityLaunchMillis = SystemClock.elapsedRealtime() - launchStart
            assertEquals(WorkMode.LITE, runBlocking { ModeRuntime.awaitPageMode(5_000) })
            val modeReadyMillis = SystemClock.elapsedRealtime() - launchStart
            assertTrue("Mode detection took ${modeReadyMillis}ms", modeReadyMillis < 5_000)
            val (modules, applications) = runBlocking {
                val moduleRead = async(Dispatchers.IO) {
                    val start = SystemClock.elapsedRealtime()
                    val result = ModuleRepositoryImpl().getModules()
                        .getOrElse { throw AssertionError("Cold module repository failed", it) }
                    result.size to (SystemClock.elapsedRealtime() - start)
                }
                val appRead = async(Dispatchers.IO) {
                    val start = SystemClock.elapsedRealtime()
                    val result = SuperUserRepositoryImpl().getAppList()
                        .getOrElse { throw AssertionError("Cold superuser repository failed", it) }
                    result.first.size to (SystemClock.elapsedRealtime() - start)
                }
                moduleRead.await() to appRead.await()
            }
            val minimum = args.getString("minimumModules")?.toInt() ?: 1
            assertTrue("Expected installed modules, got ${modules.first}", modules.first >= minimum)
            assertTrue("Expected installed applications", applications.first > 0)
            assertTrue("Module read took ${modules.second}ms", modules.second < 5_000)
            assertTrue("Superuser read took ${applications.second}ms", applications.second < 5_000)
            instrumentation.sendStatus(2, Bundle().apply {
                putLong("coldActivityLaunchMillis", activityLaunchMillis)
                putLong("coldModeReadyMillis", modeReadyMillis)
                putLong("coldManagementReadyMillis", SystemClock.elapsedRealtime() - launchStart)
                putLong("coldModuleListMillis", modules.second)
                putLong("coldSuperuserListMillis", applications.second)
                putInt("moduleCount", modules.first)
                putInt("applicationCount", applications.first)
            })
        }
    }
}
