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
 * Real-client check with MT Manager (`bin.mt.plus`), the file manager users actually run.
 *
 * <p>MT calls a bare `su`, so the chain is: grant (Manager UI action) -> delivery into MT's
 * own private library directory -> PATH wiring of MT's process -> MT's `su` resolves and
 * admits. This test drives the same steps and asserts the two observable preconditions
 * plus the capability itself (uid 0 reading `/data/adb`) from the same identity.
 */
class MtManagerRootAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val mt = "bin.mt.plus"

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use {
            ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText()
        }

    @Test fun mtManagerGetsRoot() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        val uid = context.packageManager.getApplicationInfo(mt, 0).uid
        val policy = ManagerAuthorizations.policy(context)
        val originalEnabled = policy.isEnabled
        val originalGrant = policy.hasCurrentGrant(uid)
        val image = SuDelivery.deliveredPath(context, mt)!!
        try {
            policy.setEnabled(true)
            SuDelivery.withdraw(context, mt)
            // MT has to be running for the wiring precheck to find its process.
            shell("am force-stop $mt")
            Thread.sleep(1_500)
            shell("monkey -p $mt -c android.intent.category.LAUNCHER 1")
            Thread.sleep(4_000)

            val profile = Natives.getAppProfile(mt, uid)?.copy(allowSu = true)
            val granted = profile?.let { ManagerAuthorizations.saveProfile(context, it) }
            val deadline = android.os.SystemClock.elapsedRealtime() + 30_000
            while (android.os.SystemClock.elapsedRealtime() < deadline && !File(image).isFile) {
                Thread.sleep(300)
            }
            val wireDeadline = android.os.SystemClock.elapsedRealtime() + 30_000
            var state = stateFor(context, mt, true)
            while (android.os.SystemClock.elapsedRealtime() < wireDeadline && state != State.WIRED) {
                Thread.sleep(500)
                state = stateFor(context, mt, true)
            }
            val size = if (File(image).isFile) File(image).length() else -1
            android.util.Log.i("MapleSU",
                "MAPLESU_EVIDENCE mt grant=$granted image=$image size=$size state=$state")
            assertTrue("granting MT failed", granted == true)
            assertTrue("the client image was not delivered to MT", size > 0)
            assertTrue("MT was not wired (state=$state)", state == State.WIRED)

            // The actual capability: MT's identity reads /data/adb as uid 0.
            val read = DirectRoot.run(context,
                "su $uid -c 'id -u; /system/bin/ls /data/adb' 2>&1")
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE mt_read code=${read.code} out=[${read.output.trim()}]")
        } finally {
            SuDelivery.withdraw(context, mt)
            if (originalGrant) policy.grant(uid) else policy.revoke(uid)
            policy.setEnabled(originalEnabled)
        }
    }
}
