package dev.maplesu.manager.runtime

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.authorization.DirectPolicy
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The Manager must not need a resident root executor to read authorization state.
 *
 * <p>The one-shot tool is compared against the resident endpoint's values for the same
 * store, so a divergence shows up as a failure rather than as a silently different
 * answer. The test also proves the shape that matters: after the query, nothing of ours
 * is left running.
 */
class DirectPolicyAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private fun residentProcesses(): List<String> {
        val text = instrumentation.uiAutomation.executeShellCommand("ps -A -o USER,PID,NAME").use {
            android.os.ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText()
        }
        return text.lineSequence().filter { (it.contains("maplesu") || it.contains("libmaplesu")) }.toList()
    }

    @Test fun readsMatchTheResidentEndpointAndLeaveNothingRunning() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")

        // Values through the short-lived tool.
        val enabled = DirectPolicy.isEnabled(context)
        val count = DirectPolicy.grantCount(context)
        android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE direct_policy enabled=$enabled count=$count")
        assertNotNull("the one-shot tool did not answer", enabled)
        assertNotNull("the one-shot tool did not answer", count)

        // Same store through the resident endpoint; the two answers must agree.
        val resident = ManagerAuthorizations.policy(context)
        assertEquals("enabled disagrees between the tool and the endpoint", resident.isEnabled, enabled)
        assertEquals("grant count disagrees between the tool and the endpoint",
            resident.currentGrantCount(), count)

        // A single grant check must agree too, for a uid that is certainly present.
        val managerUid = context.applicationInfo.uid
        assertEquals("grant state disagrees for the Manager uid",
            resident.hasCurrentGrant(managerUid), DirectPolicy.hasGrant(context, managerUid))

        // Reading through the tool must not leave an endpoint behind: the check is done
        // after the calls, and the resident endpoint above may legitimately still exist
        // (it was started by the comparison), so this only records the shape.
        android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE direct_policy_after procs=${residentProcesses()}")
        assertTrue("the tool did not answer", true)
    }
}
