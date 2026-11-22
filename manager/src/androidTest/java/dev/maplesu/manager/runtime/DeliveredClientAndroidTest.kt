package dev.maplesu.manager.runtime

import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The composition the non-resident requirements actually ask for: an **authorised
 * application**, running under its own UID, executes the image delivered into its own
 * library directory and obtains root - with no Manager UI, no Binder endpoint, no
 * directory owner and no resident root service alive.
 *
 * <p>The fixture (`dev.maplesu.wiredtarget`) reports the result from inside its own
 * process, because neither `run-as` nor a shell can reproduce that PATH and identity.
 * The resident chain is killed first, so a passing result cannot be explained by a live
 * endpoint.
 */
class DeliveredClientAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val fixture = "dev.maplesu.wiredtarget"

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use {
            ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText()
        }

    /** One short-lived direct-admission process: no libsu connection is held. */
    private fun runRoot(command: String): String = DirectRoot.run(context, command).output

    private fun probeLine(): String {
        val deadline = android.os.SystemClock.elapsedRealtime() + 15_000
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            val line = shell("logcat -d -s WIREDTARGET").lineSequence().lastOrNull { it.contains("PROBE") }
            if (line != null) return line
            Thread.sleep(400)
        }
        return ""
    }

    @Test fun grantedApplicationRunsItsDeliveredImage() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        val policy = ManagerAuthorizations.policy(context)
        val uid = context.packageManager.getApplicationInfo(fixture, 0).uid
        val granted = policy.hasCurrentGrant(uid)
        val enabled = policy.isEnabled
        try {
            policy.setEnabled(true)
            policy.grant(uid)
            val delivered = SuDelivery.deliver(context, fixture)
            assertTrue("delivery failed: ${delivered.detail}", delivered.ok)

            // Remove the resident chain: nothing of ours may be waiting when the target
            // application starts.
            runRoot("kill -9 \$(ps -A -o PID,NAME | grep -E 'root:0|libmaplesu_runtime' | awk '{print \$1}') 2>/dev/null; true")
            Thread.sleep(1_200)
            val resident = shell("ps -A -o USER,PID,NAME | grep -E 'root.*maplesu|libmaplesu_runtime'")
            assertTrue("resident root chain still present: $resident", resident.isBlank())

            shell("am force-stop $fixture")
            shell("logcat -c")
            shell("am start -W -n $fixture/dev.maplesu.wiredtarget.Main")
            val line = probeLine()
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE delivered_client resident=[$resident] line=[${line.trim()}]")
            assertTrue("fixture produced no probe line", line.contains("PROBE"))
            assertTrue("fixture did not run with its JNI library: $line", line.contains("native=ok"))
            // delivered=[rc=0 out=0 | ] - its own image admitted it.
            assertTrue("delivered image did not admit the application: $line",
                line.contains("delivered=[rc=0") && line.contains("out=0"))
            // Without persistent-PATH wiring a bare `su` still does not resolve.
            assertTrue("bare su unexpectedly resolved before wiring: $line",
                line.contains("bare=[rc=") && (line.contains("inaccessible") || line.contains("not found")))
        } finally {
            SuDelivery.withdraw(context, fixture)
            if (granted) policy.grant(uid) else policy.revoke(uid)
            policy.setEnabled(enabled)
        }
    }
}
