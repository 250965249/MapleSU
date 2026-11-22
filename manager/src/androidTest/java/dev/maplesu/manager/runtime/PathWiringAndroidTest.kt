package dev.maplesu.manager.runtime

import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Persistent-PATH wiring, end to end, for a granted application.
 *
 * <p>A delivered image makes `su` available by absolute path. Wiring goes one step
 * further: it puts that application's own directory on the PATH of its processes, so a
 * bare `su` resolves inside the application - the MapleSU convenience, restricted to the
 * one application that was granted and wired.
 *
 * <p>The assertion is made by the fixture from inside its own process, because neither a
 * shell nor `run-as` can reproduce that PATH.
 */
class PathWiringAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val fixture = "dev.maplesu.wiredtarget"

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use {
            ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText()
        }

    private fun probeLine(): String {
        val deadline = android.os.SystemClock.elapsedRealtime() + 20_000
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            val line = shell("logcat -d -s WIREDTARGET").lineSequence().lastOrNull { it.contains("PROBE") }
            if (line != null) return line
            Thread.sleep(500)
        }
        return ""
    }

    @Test fun grantedApplicationResolvesBareSuAfterWiring() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        val uid = context.packageManager.getApplicationInfo(fixture, 0).uid
        android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE wiring_stage start uid=$uid")
        // Test setup only: grant through the long-standing endpoint so the wiring path
        // under test is the only new code exercised here.
        val policy = ManagerAuthorizations.policy(context)
        try {
            policy.setEnabled(true)
            policy.grant(uid)
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE wiring_stage granted")

            // The precheck matches a running process, so the target must be up.
            shell("am force-stop $fixture")
            shell("am start -W -n $fixture/dev.maplesu.wiredtarget.Main")
            Thread.sleep(1_500)

            val delivered = SuDelivery.deliver(context, fixture)
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE wiring_stage delivered ok=${delivered.ok} ${delivered.detail}")
            assertTrue("delivery failed: ${delivered.detail}", delivered.ok)
            val wiring = SuPathWiring.wire(context, fixture)
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE wiring ok=${wiring.ok} code=${wiring.code} detail=${wiring.detail}")
            assertTrue("wiring failed: ${wiring.detail} (${wiring.code})", wiring.ok)

            // Relaunch so the fixture starts with the wired environment.
            shell("logcat -c")
            shell("am force-stop $fixture")
            shell("am start -W -n $fixture/dev.maplesu.wiredtarget.Main")
            val line = probeLine()
            assertTrue("fixture produced no probe line", line.contains("PROBE"))
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE wiring_probe [$line]")
            // bare=[rc=0 out=0 | ] - a bare `su` now resolves inside the application.
            assertTrue("bare su did not resolve after wiring: $line",
                line.contains("bare=[rc=0") && line.contains("out=0"))
        } finally {
            SuDelivery.withdraw(context, fixture)
            policy.revoke(uid)
        }
    }
}
