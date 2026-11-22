package dev.maplesu.manager.runtime

import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

class SuPathWiringAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val fixture = "dev.maplesu.wiredtarget"

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use { descriptor ->
            ParcelFileDescriptor.AutoCloseInputStream(descriptor).bufferedReader().readText()
        }

    private fun uid(): Int = context.packageManager.getApplicationInfo(fixture, 0).uid

    /** Last PROBE line the fixture logged, which contains the bare-su outcome. */
    private fun lastProbe(): String {
        val deadline = android.os.SystemClock.elapsedRealtime() + 15_000
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            val line = shell("logcat -d -s WIREDTARGET").lineSequence()
                .lastOrNull { it.contains("PROBE") }
            if (line != null) return line
            Thread.sleep(400)
        }
        return ""
    }

    private fun launchAndReadProbe(): String {
        shell("logcat -c")
        shell("am force-stop $fixture")
        shell("am start -W -n $fixture/dev.maplesu.wiredtarget.Main")
        return lastProbe()
    }

    @Test fun onlyGrantedApplicationIsWired() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        assertTrue(MapleSuRuntime.refresh(context))
        RuntimeDeployment.start(context)
        val policy = ManagerAuthorizations.policy(context)
        val target = uid()
        val enabled = policy.isEnabled
        val granted = policy.hasCurrentGrant(target)
        try {
            policy.setEnabled(true)

            // (1) Not granted: refused before any native call, and nothing is written.
            policy.revoke(target)
            val refused = SuPathWiring.wire(context, fixture)
            assertFalse("an unauthorised application must not be wired: ${refused.detail}", refused.ok)
            assertEquals("AUTH_NOT_GRANTED", refused.detail)

            // Baseline: the fixture is running, has its JNI library loaded, and a bare
            // `su` does not resolve for it yet.
            val before = launchAndReadProbe()
            assertTrue("fixture did not report: $before", before.contains("PROBE"))
            assertTrue("fixture is not running with its JNI library: $before",
                before.contains("native=ok"))
            assertTrue("bare su unexpectedly resolved before wiring: $before",
                before.contains("inaccessible") || before.contains("not found"))

            // (2) Granted: wired, then a fresh process resolves a bare `su`.
            policy.grant(target)
            val wired = SuPathWiring.wire(context, fixture)
            assertTrue("wiring failed: ${wired.detail}", wired.ok)
            val after = launchAndReadProbe()
            assertTrue("fixture did not report after wiring: $after", after.contains("PROBE"))
            assertTrue("bare su still does not resolve after wiring: $after",
                after.contains("rc=0") && after.contains("out=0 |"))
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE wiring before=[$before] after=[$after]")

            // (3) Nobody else was touched: the manager's own library directory has no
            // extra side library, and an unwired app still cannot resolve a bare `su`.
            val ownLibraries = File(context.applicationInfo.nativeLibraryDir).list()?.toList() ?: emptyList()
            assertTrue("the manager itself must not be wired: $ownLibraries",
                ownLibraries.none { it.startsWith("lib") && it.length in 12..18 && it.endsWith(".so") })
            val foreign = shell("run-as dev.maplesu.manager sh -c 'su -c id -u' 2>&1")
            assertTrue("an unwired application must not resolve su: $foreign",
                foreign.contains("inaccessible") || foreign.contains("not found"))
        } finally {
            policy.revoke(target)
            if (granted) policy.grant(target)
            policy.setEnabled(enabled)
        }
    }
}
