package dev.maplesu.manager.runtime

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.authorization.DirectPolicy
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The one-shot tool must support writes, not only reads: the UI grants and revokes
 * through it. A failure here is not cosmetic - it is the authorization path itself.
 */
class DirectPolicyWriteAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val fixture = "dev.maplesu.wiredtarget"

    @Test fun writesAreAppliedAndReadBack() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        val uid = context.packageManager.getApplicationInfo(fixture, 0).uid
        val originalEnabled = DirectPolicy.isEnabled(context)
        val originalGrant = DirectPolicy.hasGrant(context, uid)

        try {
            DirectPolicy.setEnabled(context, true)
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE write_stage enabled=${DirectPolicy.isEnabled(context)}")
            assertEquals(true, DirectPolicy.isEnabled(context))

            java.lang.Thread.sleep(2_100) // let the snapshot expire
            DirectPolicy.grant(context, uid)
            java.lang.Thread.sleep(2_100)
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE write_stage granted=${DirectPolicy.hasGrant(context, uid)}")
            assertEquals(true, DirectPolicy.hasGrant(context, uid))

            java.lang.Thread.sleep(2_100)
            DirectPolicy.revoke(context, uid)
            java.lang.Thread.sleep(2_100)
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE write_stage revoked=${DirectPolicy.hasGrant(context, uid)}")
            assertEquals(false, DirectPolicy.hasGrant(context, uid))
        } finally {
            if (originalGrant == true) DirectPolicy.grant(context, uid) else DirectPolicy.revoke(context, uid)
            DirectPolicy.setEnabled(context, originalEnabled ?: true)
        }
    }
}
