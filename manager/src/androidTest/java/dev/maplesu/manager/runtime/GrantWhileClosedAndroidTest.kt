package dev.maplesu.manager.runtime

import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.Natives
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * A grant on a closed application must finish now: the Manager opens it for a moment,
 * wires it, and the application is usable the next time the user starts it.
 */
class GrantWhileClosedAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val fixture = "dev.maplesu.wiredtarget"

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use {
            ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText()
        }

    @Test fun closedApplicationIsOpenedAndWired() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        val uid = context.packageManager.getApplicationInfo(fixture, 0).uid
        val policy = ManagerAuthorizations.policy(context)
        val originalEnabled = policy.isEnabled
        val originalGrant = policy.hasCurrentGrant(uid)
        try {
            policy.setEnabled(true)
            shell("am force-stop $fixture")
            Thread.sleep(1_500)
            val runningBefore = SuPathWiring.runningCommandLineFor(context, fixture) != null
            val uidProfile = Natives.getAppProfile(fixture, uid)?.copy(allowSu = true)
            val granted = uidProfile?.let { ManagerAuthorizations.saveProfile(context, it) }
            // The post runs on a worker: give it the delivery + launch window.
            val deadline = android.os.SystemClock.elapsedRealtime() + 25_000
            var running = false
            while (android.os.SystemClock.elapsedRealtime() < deadline) {
                running = SuPathWiring.runningCommandLineFor(context, fixture) != null
                if (running) break
                Thread.sleep(300)
            }
            android.util.Log.i("MapleSU",
                "MAPLESU_EVIDENCE grant_closed granted=$granted runningBefore=$runningBefore runningAfter=$running")
            assertTrue("grant failed", granted == true)
            assertTrue("the application was not opened for wiring", running)
        } finally {
            if (originalGrant == true) policy.grant(uid) else policy.revoke(uid)
            policy.setEnabled(originalEnabled)
        }
    }
}
