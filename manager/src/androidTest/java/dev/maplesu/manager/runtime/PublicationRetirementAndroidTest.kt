package dev.maplesu.manager.runtime

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * The global publication is retired.
 *
 * <p>Under the non-resident contract a granted application runs the image delivered into
 * its own library directory, so there is no `/data/<hash>/su` entry to discover, to keep
 * in sync across package updates, or to bind a resident endpoint to. This test asserts the
 * absence - the previous behaviour was the presence, so a regression would be a new
 * discoverable surface rather than a missing feature.
 */
class PublicationRetirementAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private fun root(command: String): String = DirectRoot.run(context, command).output

    private fun publicationMountCount(): Int {
        val text = instrumentation.uiAutomation.executeShellCommand("cat /proc/self/mountinfo").use {
            android.os.ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText()
        }
        return text.lineSequence().count { it.contains(" /data/") && it.contains("/su ") }
    }

    @Test fun noGlobalEntryIsPublished() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        // The publication path is a pure function of the credential, so it is checkable
        // without asking the app to publish anything.
        val path = RuntimeDeployment.clientPath(context)
        val directory = File(path).parentFile!!.absolutePath
        val existedBefore = root("test -e '$path' && echo PRESENT || echo ABSENT").trim()

        // Remove anything an earlier build left behind, then confirm the app does not
        // recreate it on its next start.
        root("rm -rf '$directory'")
        RuntimeDeployment.start(context)
        Thread.sleep(2_000)
        val afterStart = root("test -e '$path' && echo PRESENT || echo ABSENT").trim()
        val mounts = publicationMountCount()
        android.util.Log.i("MapleSU",
            "MAPLESU_EVIDENCE publication_retired path=$path before=$existedBefore after_start=$afterStart mounts=$mounts")

        assertEquals("the retired publication was recreated on start", "ABSENT", afterStart)
        assertTrue("a publication mount is still present", mounts == 0)
        assertEquals("clientPath must not advertise a published entry", null, RuntimeDeployment.status().clientPath)
    }
}
