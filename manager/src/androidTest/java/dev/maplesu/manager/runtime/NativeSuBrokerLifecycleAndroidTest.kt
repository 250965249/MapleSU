package dev.maplesu.manager.runtime

import android.app.ActivityManager
import android.content.Intent
import android.os.Bundle
import android.os.SystemClock
import android.os.UserManager
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.jailbreak.JailbreakStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Preparation/publication regression only; UI exit and task removal are separate device checks. */
class NativeSuBrokerLifecycleAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    @Suppress("DEPRECATION")
    @Test(timeout = 60_000) fun existingHookKeepsItsPublishedEndpointOutsideTheManagerPage() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("reproveExistingHook") == "true")
        val before = requireNotNull(JailbreakStatus.read(context))
        context.startActivity(Intent().setClassName(context, "com.maplesu.core.ui.MainActivity")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        val result = requireNotNull(NativeSuDaemon.reproveHookOutcome(context))
        assertEquals(JailbreakStatus.STAGE_DAEMON_READY, result.stage)
        assertEquals(before.attemptId, result.attemptId)
        assertEquals(null, result.failure)
        val endpoint = NativeSuDiscovery.peek(context.applicationInfo.uid)
        context.startActivity(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        val activity = requireNotNull(context.getSystemService(ActivityManager::class.java))
        repeat(20) {
            SystemClock.sleep(500)
            assertTrue("The Hook keeper must remain foreground", activity.getRunningServices(Int.MAX_VALUE).any {
                it.service.className == HookSuKeeperService::class.java.name && it.foreground
            })
            val process = requireNotNull(activity.runningAppProcesses.firstOrNull {
                it.processName == context.packageName + ":root_directory"
            })
            assertTrue("Published Hook endpoint became cached: ${process.importance}",
                process.importance <= ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE)
            assertTrue(NativeSuDiscovery.peek(context.applicationInfo.uid).isBinderAlive)
            assertTrue(endpoint.pingBinder())
        }
        instrumentation.sendStatus(2, Bundle().apply {
            putString("hookLifetime", "background=10s; original restricted Binder alive; foreground keeper; same attempt")
        })
    }

    @Test(timeout = 60_000) fun repeatedPreparationRetainsOnePublishedRootWithoutForegroundBroker() {
        val arguments = InstrumentationRegistry.getArguments()
        assumeTrue(arguments.getString("verifyMapleSuBoot") == "true")
        assumeTrue(arguments.getString("verifyProductionRootOwner") == "true")
        assertTrue(requireNotNull(context.getSystemService(UserManager::class.java)).isUserUnlocked)
        NativeSuDaemon.ensure(context)
        val first = NativeSuDaemon.management(context).status()
        val endpoint = NativeSuDiscovery.peek(context.applicationInfo.uid)
        assertEquals(0, first.getInt("rootUid", -1))
        assertTrue(first.getInt("rootPid", -1) > 1)
        assertTrue(endpoint.isBinderAlive)
        assertNoForegroundBroker()
        repeat(4) {
            NativeSuDaemon.ensure(context)
            val state = NativeSuDaemon.management(context).status()
            assertEquals(first.getInt("rootPid"), state.getInt("rootPid", -1))
            assertEquals(context.applicationInfo.uid, state.getInt("managerUid", -1))
            assertEquals(endpoint, NativeSuDiscovery.peek(context.applicationInfo.uid))
            assertNoForegroundBroker()
        }
        instrumentation.sendStatus(2, Bundle().apply {
            putString("productionPreparation", "rootPid=${first.getInt("rootPid")}; repeated=4; same raw Binder; foregroundBroker=false")
            putString("lifecycleCoverage", "UI exit/task removal/force-stop/recovery are separate checks")
        })
    }

    @Suppress("DEPRECATION")
    private fun assertNoForegroundBroker() {
        val activity = requireNotNull(context.getSystemService(ActivityManager::class.java))
        assertFalse("Publication unexpectedly uses a foreground Broker", activity.getRunningServices(Int.MAX_VALUE).any {
            it.service.className == NativeSuBrokerService::class.java.name && it.foreground
        })
    }
}
