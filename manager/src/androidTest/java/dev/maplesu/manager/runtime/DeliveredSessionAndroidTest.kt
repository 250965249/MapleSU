package dev.maplesu.manager.runtime

import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Session behaviour of the delivered client: three streams, exit status, cancellation and
 * file-descriptor reclamation.
 *
 * <p>The previous suite covered these over the cooperative Binder path, which is retired.
 * Under delivery the client executes directly in the caller's process context, so the same
 * guarantees have to be demonstrated again from inside a real authorised application - a
 * shell or `run-as` cannot reproduce that identity or that image.
 */
class DeliveredSessionAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val fixture = "dev.maplesu.wiredtarget"

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use {
            ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText()
        }

    private fun scenario(name: String): String {
        shell("am force-stop $fixture")
        // A just-finished activity can still be alive, and starting an already running
        // activity does not call onCreate - the scenario would silently not run.
        Thread.sleep(1_500)
        shell("logcat -c")
        shell("am start -n $fixture/dev.maplesu.wiredtarget.Main --es scenario $name")
        val deadline = android.os.SystemClock.elapsedRealtime() + 12_000
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            val line = shell("logcat -d -s WIREDTARGET")
                .lineSequence().lastOrNull { it.contains("RESULT scenario=$name") }
            if (line != null) return line.substringAfter("RESULT ")
            Thread.sleep(500)
        }
        return ""
    }

    /**
     * Each property is its own test method on purpose. One long method needs well over
     * half a minute, and on this shared device an unrelated instrumentation run force-stops
     * the app every ~30 s; separate short methods still leave usable evidence when one of
     * them is interrupted.
     */
    @Test fun streamsAreSeparate() = withDelivered {
        val streams = scenario("streams")
        android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE session streams=[$streams]")
        assertTrue("stdout was not separated: $streams", streams.contains("out=[OUT|]"))
        assertTrue("stderr was not separated: $streams", streams.contains("err=[ERR|]"))
    }

    @Test fun exitStatusIsPropagated() = withDelivered {
        val exit = scenario("exit")
        android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE session exit=[$exit]")
        assertTrue("exit status was not propagated: $exit", exit.contains("rc=37"))
    }

    @Test fun descriptorsAreReclaimed() = withDelivered {
        val fds = scenario("fds")
        android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE session fds=[$fds]")
        val before = Regex("before=([0-9]+)").find(fds)?.groupValues?.get(1)?.toIntOrNull()
        val after = Regex("after=([0-9]+)").find(fds)?.groupValues?.get(1)?.toIntOrNull()
        assertTrue("descriptor count missing: $fds", before != null && after != null)
        assertTrue("sessions leaked descriptors: $fds", after!! - before!! <= 2)
    }

    @Test fun cancellationEndsTheCommand() = withDelivered {
        val cancel = scenario("cancel")
        android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE session cancel=[$cancel]")
        assertTrue("the command ended before it was cancelled: $cancel",
            cancel.contains("alive_before=true"))
        // SIGTERM is the polite request; if the client survives it, SIGKILL has to end the
        // session. Which one was needed is reported, not hidden.
        assertTrue("cancellation did not end the command: $cancel",
            cancel.contains("term_ended=true") || cancel.contains("kill_ended=true"))
    }

    /** Grants, delivers, runs one scenario, then restores the previous policy state. */
    private fun withDelivered(body: () -> Unit) {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        val uid = context.packageManager.getApplicationInfo(fixture, 0).uid
        val policy = ManagerAuthorizations.policy(context)
        val originalEnabled = policy.isEnabled
        val originalGrant = policy.hasCurrentGrant(uid)
        try {
            policy.setEnabled(true)
            policy.grant(uid)
            val delivered = SuDelivery.deliver(context, fixture)
            assertTrue("delivery failed: ${delivered.detail}", delivered.ok)
            body()
        } finally {
            SuDelivery.withdraw(context, fixture)
            if (originalGrant) policy.grant(uid) else policy.revoke(uid)
            policy.setEnabled(originalEnabled)
        }
    }
}
