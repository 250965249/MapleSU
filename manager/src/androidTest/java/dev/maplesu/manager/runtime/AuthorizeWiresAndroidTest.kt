package dev.maplesu.manager.runtime

import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.Natives
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Plan A, wiring half: granting an application whose process is already running must leave
 * a bare `su` resolvable inside that application.
 *
 * <p>Granting returns immediately and the delivery/wiring post runs on a worker, so this
 * waits for the post rather than sampling it.
 */
class AuthorizeWiresAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val fixture = "dev.maplesu.wiredtarget"

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use {
            ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText()
        }

    private fun awaitLog(marker: String, timeoutMs: Long = 25_000): String {
        val deadline = android.os.SystemClock.elapsedRealtime() + timeoutMs
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            val line = shell("logcat -d -s MapleSU").lineSequence().lastOrNull { it.contains(marker) }
            if (line != null) return line
            Thread.sleep(400)
        }
        return ""
    }

    @Test fun grantingWiresARunningApplication() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        val uid = context.packageManager.getApplicationInfo(fixture, 0).uid
        val policy = ManagerAuthorizations.policy(context)
        val originalEnabled = policy.isEnabled
        val originalGrant = policy.hasCurrentGrant(uid)
        val path = SuDelivery.deliveredPath(context, fixture)!!
        try {
            policy.setEnabled(true)
            SuDelivery.withdraw(context, fixture)

            // The target has to be running before the grant: the wiring precheck matches a
            // live process, and Plan A wires at authorization time.
            shell("am force-stop $fixture")
            Thread.sleep(1_200)
            shell("am start -n $fixture/dev.maplesu.wiredtarget.Main --es scenario probe")
            Thread.sleep(2_000)

            val profile = Natives.getAppProfile(fixture, uid)?.copy(allowSu = true)
            val granted = profile?.let { ManagerAuthorizations.saveProfile(context, it) }

            var image = false
            val imageDeadline = android.os.SystemClock.elapsedRealtime() + 25_000
            while (android.os.SystemClock.elapsedRealtime() < imageDeadline && !image) {
                image = File(path).isFile
                if (!image) Thread.sleep(300)
            }
            val wire = awaitLog("SU_AUTH_WIRE package=$fixture")
            android.util.Log.i("MapleSU",
                "MAPLESU_EVIDENCE authorize_wire grant=$granted image=$image wire=[$wire]")

            assertTrue("granting did not report success", granted == true)
            assertTrue("the client image was not delivered", image)
            assertTrue("wiring was not attempted or failed: $wire", wire.contains("ok=true"))

            // And the application itself must now resolve a bare `su`.
            shell("logcat -c")
            shell("am force-stop $fixture")
            Thread.sleep(1_200)
            shell("am start -n $fixture/dev.maplesu.wiredtarget.Main")
            Thread.sleep(4_000)
            val probe = shell("logcat -d -s WIREDTARGET").lineSequence()
                .lastOrNull { it.contains("PROBE") }.orEmpty()
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE authorize_wire probe=[${probe.trim()}]")
            assertTrue("bare su did not resolve after granting: $probe",
                probe.contains("bare=[rc=0") && probe.contains("out=0"))
        } finally {
            SuDelivery.withdraw(context, fixture)
            if (originalGrant) policy.grant(uid) else policy.revoke(uid)
            policy.setEnabled(originalEnabled)
        }
    }
}
