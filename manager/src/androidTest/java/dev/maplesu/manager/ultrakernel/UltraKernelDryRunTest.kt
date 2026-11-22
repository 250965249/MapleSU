package dev.maplesu.manager.ultrakernel

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.installer.InstallerServiceClient
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * On-device dry-run of the delivery path up to the installer's `PREPARED` state.
 *
 * It never commits: [InstallerServiceClient.prepareBootInstall] only stages the candidate and the
 * rollback image inside the root-owned task, then the test cancels that task. `boot_a` must stay
 * byte-identical, which the final re-read asserts.
 *
 * Requires a selected device with the existing root installer:
 * `adb shell am instrument -w -e existingRootInstaller true \
 *   dev.maplesu.manager.test/androidx.test.runner.AndroidJUnitRunner`
 * (add `-e class dev.maplesu.manager.ultrakernel.UltraKernelDryRunTest` to run only this test).
 *
 * The test is skipped when the device is not on the pinned firmware or `boot_a` is not pristine -
 * that is a scope statement, not a pass.
 */
@RunWith(AndroidJUnit4::class)
class UltraKernelDryRunTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun defaultVariantReachesPreparedThenCancelsWithoutWriting() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("existingRootInstaller") == "true")
        val snapshot = InstallerServiceClient.analyzeCurrentBoot(context)
        val flow = UltraKernelFlow(context)
        val selection = flow.selectForRelease(snapshot.kernelRelease)
        assumeTrue("no pinned variant for ${snapshot.kernelRelease}", selection != null)
        if (selection == null) return
        assertFalse("default must be k22, not the fallback", selection.fellBack)

        val base = flow.backupCurrentBoot()
        assertEquals(snapshot.partitions.getValue("boot").sha256, UltraKernelSpec.sha256(base))
        val inspection = flow.inspect(base, selection.primary)
        assumeTrue("boot_a is not the pristine base", inspection.pristine)

        val preparation = flow.prepare(base, selection) { Log.i(TAG, it) }
        val variant = requireNotNull(preparation.variant)
        assertEquals("unexpected build-level fallback", selection.primary.id, variant.id)
        val candidate = requireNotNull(preparation.candidate) { "expected a fresh candidate" }
        assertEquals(variant.expectedKernelSha256, candidate.kernelSha256)
        if (inspection.knownStockBase) {
            assertEquals(variant.knownBaseImageBootSha256, candidate.bootSha256)
        }

        val taskId = UUID.randomUUID().toString()
        InstallerServiceClient.beginInstallation(context, taskId)
        try {
            val prepared = InstallerServiceClient.prepareBootInstall(
                context, candidate.image, snapshot, base, taskId)
            assertEquals("PREPARED", prepared.getString("state"))
            assertEquals(taskId, prepared.getString("taskId"))
            assertFalse(prepared.getBoolean("rebootRequired"))
            Log.i(TAG, "PREPARED variant=${variant.id} task=$taskId " +
                "candidate=${candidate.bootSha256} kernel=${candidate.kernelSha256}")
        } finally {
            val cancelled = InstallerServiceClient.cancelInstallation(context, taskId)
            assertEquals("CANCELLED", cancelled.getString("state"))
        }

        val after = InstallerServiceClient.analyzeCurrentBoot(context)
        assertEquals(snapshot.partitions.getValue("boot").sha256, after.partitions.getValue("boot").sha256)
    }

    private companion object {
        const val TAG = "MapleSUKernelDryRun"
    }
}
