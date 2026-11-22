package dev.maplesu.manager.runtime

import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.Natives
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/** The last link of Plan A: after granting and wiring, a bare `su` resolves inside the app. */
class BareSuAfterWiringAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val fixture = "dev.maplesu.wiredtarget"

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use {
            ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText()
        }

    @Test fun bareSuResolvesInsideTheApplication() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        val uid = context.packageManager.getApplicationInfo(fixture, 0).uid
        val policy = ManagerAuthorizations.policy(context)
        val originalEnabled = policy.isEnabled
        val originalGrant = policy.hasCurrentGrant(uid)
        val path = SuDelivery.deliveredPath(context, fixture)!!
        try {
            policy.setEnabled(true)
            shell("am force-stop $fixture")
            Thread.sleep(1_000)
            shell("am start -n $fixture/dev.maplesu.wiredtarget.Main --es scenario probe")
            Thread.sleep(1_500)

            val profile = Natives.getAppProfile(fixture, uid)?.copy(allowSu = true)
            val granted = profile?.let { ManagerAuthorizations.saveProfile(context, it) }
            val deadline = android.os.SystemClock.elapsedRealtime() + 20_000
            while (android.os.SystemClock.elapsedRealtime() < deadline && !File(path).isFile) {
                Thread.sleep(300)
            }
            assertTrue("granting did not deliver the image", File(path).isFile)

            // The application started before the grant, so its PATH was wired by the post;
            // a fresh start now has to see it.
            shell("logcat -c")
            shell("am force-stop $fixture")
            Thread.sleep(1_200)
            shell("am start -n $fixture/dev.maplesu.wiredtarget.Main")
            Thread.sleep(5_000)
            val probe = shell("logcat -d -s WIREDTARGET").lineSequence()
                .lastOrNull { it.contains("PROBE") }.orEmpty()
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE bare_su grant=$granted probe=[${probe.trim()}]")
            assertTrue("no probe line: $probe", probe.contains("PROBE"))
            assertTrue("bare su did not resolve: $probe",
                probe.contains("bare=[rc=0") && probe.contains("out=0"))
        } finally {
            if (originalGrant) policy.grant(uid) else policy.revoke(uid)
            policy.setEnabled(originalEnabled)
        }
    }
}
