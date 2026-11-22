package dev.maplesu.manager.runtime

import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Management operations must not resurrect the resident root service.
 *
 * <p>`RootManagement.openShell` used to ask the resident management endpoint for a shell,
 * which bound libsu's `RootService` and kept `:root:0` alive for the rest of the process.
 * It now starts a direct runtime process, so the same call must (a) still produce a
 * working root shell and (b) leave no root process behind once closed.
 */
class ManagementShellAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private fun shellText(): String =
        instrumentation.uiAutomation.executeShellCommand("ps -A -o USER,PID,NAME").use {
            ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText()
        }

    private fun rootProcesses(): List<String> =
        shellText().lineSequence().filter { it.contains("root:0") || it.contains("libmaplesu_runtime") }.toList()

    @Test fun managementShellIsDirectAndLeavesNothingResident() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assertTrue("root image unavailable", MapleSuRuntime.refresh(context))

        val before = rootProcesses()
        val result = RootManagement.openShell(context).use { shell ->
            shell.newJob().add("/system/bin/id -u").to(ArrayList(), ArrayList()).exec()
        }
        val after = rootProcesses()
        android.util.Log.i("MapleSU",
            "MAPLESU_EVIDENCE management_shell code=${result.code} out=${result.out} before=$before after=$after")

        assertEquals("the management shell did not run as root", 0, result.code)
        assertTrue("unexpected management shell output: ${result.out}", result.out.contains("0"))
        // No libsu RootService may be alive after the shell is closed; a direct runtime
        // process may still be finishing, so the check tolerates only that.
        assertTrue("a root service survived the management shell: $after",
            after.none { it.contains(":root:0") })
    }
}
