package dev.maplesu.manager.runtime

import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.authorization.DirectPolicy
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The library-free path end to end: an application with no `.so` at all is granted, its
 * library directory is created, the shared directory reaches its PATH, and a bare `su`
 * resolves and admits.
 */
class ZeroLibRootAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val target = "dev.maplesu.purejava"

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use {
            ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText()
        }

    @Test fun libraryFreeApplicationGetsRoot() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        val uid = context.packageManager.getApplicationInfo(target, 0).uid
        val original = DirectPolicy.hasGrantStrict(context, uid)
        DirectPolicy.grant(context, uid)
        try {
            shell("am force-stop $target")
            Thread.sleep(1_200)
            shell("logcat -c")
            shell("am start -n $target/.Main")
            Thread.sleep(2_500)
            val published = SuPublication.publish(context)
            val delivered = SuDelivery.deliver(context, target)
            // Injection rewrites the environment of a LIVE process, so it has to happen while
            // the application is running - and the probe has to run in that same process.
            val injected = SuPathWiring.injectPath(context, target)
            shell("logcat -c")
            // Re-run the probe inside the same (already injected) process via its broadcast.
            shell("am broadcast -a dev.maplesu.purejava.PROBE -n $target/.Probe")
            Thread.sleep(3_000)
            val line = shell("logcat -d -s PUREJAVA").lineSequence()
                .lastOrNull { it.contains("BARE") }.orEmpty()
            android.util.Log.i("MapleSU",
                "MAPLESU_EVIDENCE zero_lib published=$published delivered=${delivered.ok} " +
                    "injected=${injected.ok} reason=${injected.detail} bare=[${line.trim().take(160)}]")
            assertTrue("delivery failed: ${delivered.detail}", delivered.ok)
            assertTrue("injection failed: ${injected.detail}", injected.ok)
            assertTrue("bare su did not resolve: $line", line.contains("su=rc=0"))
        } finally {
            if (original == true) DirectPolicy.grant(context, uid) else DirectPolicy.revoke(context, uid)
        }
    }
}
