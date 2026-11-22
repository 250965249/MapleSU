package dev.maplesu.manager.runtime

import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.Natives
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The case users actually hit: the application is granted while it is **closed**, so the
 * grant-time wiring cannot run, and a bare `su` inside it fails even though the grant is
 * valid. Opening the Manager later has to complete the wiring once the target runs.
 */
class AutoWireReconcileAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val fixture = "dev.maplesu.wiredtarget"

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use {
            ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText()
        }

    @Test fun wiringIsCompletedAfterTheTargetStarts() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        val uid = context.packageManager.getApplicationInfo(fixture, 0).uid
        val policy = ManagerAuthorizations.policy(context)
        val originalEnabled = policy.isEnabled
        val originalGrant = policy.hasCurrentGrant(uid)
        try {
            policy.setEnabled(true)
            SuDelivery.withdraw(context, fixture)
            // Granted while closed: delivery happens, wiring cannot.
            shell("am force-stop $fixture")
            Thread.sleep(1_200)
            val profile = Natives.getAppProfile(fixture, uid)?.copy(allowSu = true)
            assertTrue("grant failed", profile?.let { ManagerAuthorizations.saveProfile(context, it) } == true)
            val imageDeadline = android.os.SystemClock.elapsedRealtime() + 20_000
            while (android.os.SystemClock.elapsedRealtime() < imageDeadline &&
                !SuDelivery.imagePresent(context, fixture)) Thread.sleep(300)
            val afterGrant = stateFor(context, fixture, true)
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE auto_wire after_grant=$afterGrant")

            // Now the target runs; the Manager's own startup pass must finish the wiring.
            shell("am start -n $fixture/dev.maplesu.wiredtarget.Main --es scenario probe")
            Thread.sleep(2_000)
            SuAutoWire.reconcile(context)
            val afterReconcile = stateFor(context, fixture, true)
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE auto_wire after_reconcile=$afterReconcile")
            assertEquals("reconcile did not wire the running target", State.WIRED, afterReconcile)
        } finally {
            SuDelivery.withdraw(context, fixture)
            if (originalGrant) policy.grant(uid) else policy.revoke(uid)
            policy.setEnabled(originalEnabled)
        }
    }
}
