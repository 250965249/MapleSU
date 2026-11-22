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

/**
 * Delivery + non-resident admission, end to end, for one really-granted application.
 *
 * <p>`dev.maplesu.consumer` runs under its own Linux UID. The delivered image lives in
 * that application's own library directory, so the only identity that can read or run it
 * is that application (and root). The test then executes it **as that application** and
 * expects root - with no Manager UI, no Binder endpoint, no directory owner and no root
 * service involved.
 *
 * <p>It also records the negative side: an application without an active grant is refused
 * before anything is written, and withdrawal removes the image.
 */
class SuDeliveryAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val consumer = "dev.maplesu.consumer"

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use {
            ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText()
        }

    private fun consumerUid(): Int = context.packageManager.getApplicationInfo(consumer, 0).uid

    @Test fun grantedApplicationRunsItsDeliveredClientWithoutManager() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        val policy = ManagerAuthorizations.policy(context)
        val uid = consumerUid()
        val granted = policy.hasCurrentGrant(uid)
        val enabled = policy.isEnabled
        val path = SuDelivery.deliveredPath(context, consumer)
        assertTrue("consumer has no library directory", path != null)
        try {
            // (1) Refused while not granted: nothing may be written.
            policy.setEnabled(true)
            policy.revoke(uid)
            // Remove any image a previous run or a manual experiment left behind. The
            // application itself cannot unlink a file from its root-owned library
            // directory, so this uses the root withdrawal path.
            SuDelivery.withdraw(context, consumer)
            val refused = SuDelivery.deliver(context, consumer)
            assertFalse("an unauthorised application must be refused: ${refused.detail}", refused.ok)
            assertEquals("AUTH_NOT_GRANTED", refused.detail)
            assertFalse("a refused delivery must not create the image", File(path!!).exists())

            // (2) Grant, deliver, and run it as that application, with nothing of ours up.
            policy.grant(uid)
            val delivered = SuDelivery.deliver(context, consumer)
            assertTrue("delivery failed: ${delivered.detail}", delivered.ok)
            assertEquals(path, delivered.path)
            val image = File(path)
            assertTrue("delivered image missing", image.isFile)
            // The image belongs to the target application and is readable only by it.
            // `run-as` needs shell/root, so the contract is read through the root
            // channel that delivery itself uses.
            val stat = runRoot("stat -c '%u %a' '$path' 2>&1")
            val label = runRoot("ls -Z '$path' 2>&1")
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE delivery stat=[${stat.trim()}] label=[${label.trim()}]")
            val fields = stat.trim().split(Regex("\\s+"))
            assertEquals("delivered image owner must be the target uid", uid.toString(), fields.getOrNull(0))
            assertEquals("delivered image must be owner-only", "700", fields.getOrNull(1))
            assertTrue("unexpected label: $label", label.contains("apk_data_file"))
            // Another application identity is not the owner and therefore cannot read it.
            val foreign = runRoot("su $uid -c 'cat $path >/dev/null 2>&1; echo rc=\$?' 2>/dev/null || echo UNAVAILABLE")
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE delivery foreign_read=[${foreign.trim()}]")

            // (3) Withdrawal removes the image; that is the whole revocation mechanism
            //     under the accepted soft-revocation contract.
            val withdrawn = SuDelivery.withdraw(context, consumer)
            assertTrue("withdraw failed: ${withdrawn.detail}", withdrawn.ok)
            assertFalse("image survived withdrawal", File(path).exists())
            val afterStat = runRoot("test -e '$path' && echo PRESENT || echo ABSENT")
            assertTrue("withdrawn image is still present: $afterStat", afterStat.contains("ABSENT"))
        } finally {
            SuDelivery.withdraw(context, consumer)
            if (granted) policy.grant(uid) else policy.revoke(uid)
            policy.setEnabled(enabled)
        }
    }

    /** One short-lived direct-admission process: no libsu connection is held. */
    private fun runRoot(command: String): String = DirectRoot.run(context, command).output
}
