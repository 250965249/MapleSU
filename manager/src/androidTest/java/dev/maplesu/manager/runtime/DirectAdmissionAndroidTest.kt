package dev.maplesu.manager.runtime

import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Non-resident admission: a caller that holds the delivered credential establishes root
 * with **no** Binder endpoint, no directory owner, no root service and no Manager UI.
 *
 * <p>The test deliberately stops every product process first, so a passing result cannot
 * be explained by a surviving session or a cached endpoint. The credential is written to
 * the child's stdin in the runtime's 4+48 frame and never appears in argv or the
 * environment.
 *
 * <p>This is the mechanism the non-resident migration depends on: under the accepted
 * contract the delivered credential is the admission material, and revocation is
 * entry-point removal (soft), which is recorded separately in the acceptance table.
 */
class DirectAdmissionAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    /** Runs the runtime's direct-admission mode with the credential on stdin only. */
    private fun admit(credential: ByteArray, vararg command: String): Pair<Int, String> {
        val runtime = File(context.applicationInfo.nativeLibraryDir, "libmaplesu_runtime.so")
        val process = ProcessBuilder(listOf(runtime.absolutePath, "--direct-stdin", "--") + command)
            .redirectErrorStream(true).start()
        process.outputStream.use { input ->
            input.write(byteArrayOf(0, 0, 0, 48))
            input.write(credential)
            input.flush()
        }
        val text = process.inputStream.bufferedReader().use { it.readText() }
        return process.waitFor() to text
    }

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use {
            ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText()
        }

    private fun residentRootProcesses(): List<String> {
        val text = shell("ps -A -o USER,PID,NAME")
        return text.lineSequence()
            .filter { it.contains("maplesu") || it.contains("libmaplesu") }
            .filter { it.trim().startsWith("root") }
            .toList()
    }

    @Test fun credentialHolderGetsRootWithNoResidentService() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val credential = MapleSuCredentialStore(context).load()
            ?: throw AssertionError("no paired credential")
        try {
            // (1) The instrumentation starts from a force-stopped package, so the
            //     resident chain is normally already down; anything that survived is
            //     removed with admission itself. Either way the target state is
            //     "nothing of ours is waiting for a request".
            val rootBefore = residentRootProcesses()
            val pids = rootBefore.mapNotNull { line ->
                line.trim().split(Regex("\\s+")).getOrNull(1)?.toIntOrNull()
            }
            if (pids.isNotEmpty()) {
                admit(credential, "/system/bin/kill", "-9", *pids.map { it.toString() }.toTypedArray())
                Thread.sleep(1_500)
            }
            val rootAfter = residentRootProcesses()
            assertTrue("resident root chain still present: $rootAfter", rootAfter.isEmpty())
            android.util.Log.i("MapleSU",
                "MAPLESU_EVIDENCE resident_chain before=$rootBefore after=$rootAfter")

            // (3) A credential holder still establishes root, with no endpoint, no
            //     directory owner and no root service alive.
            val (code, first) = admit(credential, "/system/bin/id", "-u")
            android.util.Log.i("MapleSU",
                "MAPLESU_EVIDENCE direct_admission no_resident code=$code out=[${first.trim()}]")
            assertEquals("direct admission must survive without any resident service: $first", 0, code)
            assertEquals("the process must really be root", "0", first.trim())

            // (4) Interactive shape: the same admission runs a command with arguments.
            val (secondCode, second) = admit(credential, "/system/bin/sh", "-c", "id -u; echo marker")
            assertEquals(0, secondCode)
            assertTrue("unexpected output: $second", second.contains("0") && second.contains("marker"))

            // (5) The credential never appears in a command line or environment.
            val ps = shell("ps -A -o ARGS")
            assertTrue("the credential leaked into a command line", !ps.contains(String(credential, Charsets.UTF_8)))
        } finally {
            credential.fill(0)
        }
    }
}
