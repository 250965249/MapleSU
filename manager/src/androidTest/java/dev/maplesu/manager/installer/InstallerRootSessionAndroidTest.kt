package dev.maplesu.manager.installer

import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.Natives
import com.maplesu.core.ui.util.rootAvailable
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Opt in only on a selected device with an existing su provider; never writes a partition. */
@RunWith(AndroidJUnit4::class)
class InstallerRootSessionAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()

    private fun requireSelectedDevice() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("existingRootInstaller") == "true")
    }

    @Test fun readsTheBootChainWithoutChangingManagerRootState() {
        requireSelectedDevice()
        val wasManager = Natives.isManager
        val managerRoot = rootAvailable()
        InstallerRootSession.open(instrumentation.targetContext).use { session ->
            val result = session.snapshotCurrentBoot()
            assertEquals(result.slotSuffix, session.discoverBootTarget().slotSuffix)
            assertTrue(result.kernelRelease.isNotBlank())
            assertTrue(result.firmware.isNotBlank())
            assertEquals("Enforcing", result.selinux)
            assertTrue(result.partitions.keys.containsAll(listOf("boot", "vbmeta")))
            instrumentation.sendStatus(2, Bundle().apply {
                putString("installerKernel", result.kernelRelease)
                putString("installerFirmware", result.firmware)
                putString("installerSlot", result.slotSuffix)
                putString("installerSelinux", result.selinux)
            })
            for ((name, value) in result.partitions) {
                assertEquals(name, value.name)
                assertTrue(value.size > 0)
                assertTrue(value.sha256.matches(Regex("[0-9a-f]{64}")))
                instrumentation.sendStatus(2, Bundle().apply {
                    putString("installerPartition", value.path)
                    putString("installerResolvedPath", value.resolvedPath)
                    putString("installerSha256", value.sha256)
                    putString("installerSize", value.size.toString())
                })
            }
            assertEquals(wasManager, Natives.isManager)
            assertEquals(managerRoot, rootAvailable())
        }
    }

    @Test fun closedInstallationSessionRejectsFurtherReads() {
        requireSelectedDevice()
        val session = InstallerRootSession.open(instrumentation.targetContext)
        session.close()
        session.close()
        try { session.snapshotCurrentBoot(); fail("Closed session accepted a device read") }
        catch (expected: IllegalStateException) { assertEquals("INSTALLER_SESSION_CLOSED", expected.message) }
        try { session.discoverBootTarget(); fail("Closed session accepted target discovery") }
        catch (expected: IllegalStateException) { assertEquals("INSTALLER_SESSION_CLOSED", expected.message) }
    }
}
