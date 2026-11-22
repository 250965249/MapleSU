package dev.maplesu.manager.runtime

import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.Natives
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Plan A: the authorization action carries delivery and wiring with it.
 *
 * <p>Granting must produce the application's own image; revoking must remove it. Wiring is
 * best effort - a target that is not running is a normal outcome, not a failed grant.
 */
class AuthorizeDeliversAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val fixture = "dev.maplesu.wiredtarget"

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use {
            ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText()
        }

    private fun fixtureProfile(allowSu: Boolean): Natives.Profile? {
        val uid = context.packageManager.getApplicationInfo(fixture, 0).uid
        return Natives.getAppProfile(fixture, uid)?.copy(allowSu = allowSu)
    }

    /** The post runs on a serial worker, so its effect becomes visible slightly later. */
    private fun await(timeoutMs: Long, condition: () -> Boolean): Boolean {
        val deadline = android.os.SystemClock.elapsedRealtime() + timeoutMs
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            if (condition()) return true
            Thread.sleep(300)
        }
        return condition()
    }

    @Test fun grantingDeliversAndRevokingWithdraws() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        val uid = context.packageManager.getApplicationInfo(fixture, 0).uid
        val policy = ManagerAuthorizations.policy(context)
        val originalEnabled = policy.isEnabled
        val originalGrant = policy.hasCurrentGrant(uid)
        val path = SuDelivery.deliveredPath(context, fixture)!!
        try {
            policy.setEnabled(true)
            // Start the target so wiring has a process to match; delivery must not depend
            // on it.
            shell("am start -n $fixture/dev.maplesu.wiredtarget.Main --es scenario exit")
            Thread.sleep(1_500)

            val granted = fixtureProfile(true)?.let { ManagerAuthorizations.saveProfile(context, it) }
            val deliveredAfterGrant = await(15_000) { File(path).isFile }
            val wiredLog = shell("logcat -d -s MapleSU").lineSequence()
                .lastOrNull { it.contains("SU_AUTH_WIRE package=$fixture") }
            android.util.Log.i("MapleSU",
                "MAPLESU_EVIDENCE authorize grant=$granted delivered=$deliveredAfterGrant wire=[$wiredLog]")

            assertTrue("granting did not report success", granted == true)
            assertTrue("granting did not deliver the client image", deliveredAfterGrant)

            val revoked = fixtureProfile(false)?.let { ManagerAuthorizations.saveProfile(context, it) }
            val removedAfterRevoke = await(15_000) { !File(path).isFile }
            android.util.Log.i("MapleSU",
                "MAPLESU_EVIDENCE authorize revoke=$revoked removed=$removedAfterRevoke")
            assertTrue("revoking did not report success", revoked == true)
            assertTrue("revoking did not remove the client image", removedAfterRevoke)
        } finally {
            SuDelivery.withdraw(context, fixture)
            if (originalGrant) policy.grant(uid) else policy.revoke(uid)
            policy.setEnabled(originalEnabled)
        }
    }
}
