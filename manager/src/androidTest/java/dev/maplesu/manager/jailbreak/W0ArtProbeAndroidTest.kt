package dev.maplesu.manager.jailbreak

import android.system.Os
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * W0 decision experiment (manual section 8): apply the patches, do **not** soft
 * reboot, then start ART and see whether the device survives.
 *
 * <p>The answer decides W4. Stable means the product can soft-reboot and let normal
 * mode take over; unstable means the takeover has to move to a native daemon
 * (appendix B). This test exists to produce that fact, so it records the boot id on
 * both sides of every step instead of asserting a conclusion it does not have:
 *
 * <ul>
 *   <li>before → after the patch must be equal, or the patch itself rebooted us;</li>
 *   <li>before → after starting ART must be equal, or ART in this kernel state is
 *       what rebooted us (the DEV-89 failure mode).</li>
 * </ul>
 *
 * <p>If the device does panic, this process dies and the boot id changes - which is
 * the result, read afterwards with `adb shell cat /proc/sys/kernel/random/boot_id`.
 */
@RunWith(AndroidJUnit4::class)
class W0ArtProbeAndroidTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun evidence(name: String, document: JSONObject) {
        val directory = File(context.getExternalFilesDir(null), "jailbreak-evidence")
        if (!directory.isDirectory) directory.mkdirs()
        File(directory, name).writeText(document.toString(2))
    }

    private fun moduleLoaded(): String = runCatching {
        val text = File("/proc/modules").readText()
        if (text.lineSequence().any { it.startsWith("maplesu_ir ") }) "present" else "absent"
    }.getOrElse { "unreadable:" + (it.javaClass.simpleName) }

    private fun runProbe(argv: List<String>): JSONObject {
        val started = System.currentTimeMillis()
        return runCatching {
            val process = ProcessBuilder(argv).redirectErrorStream(true).start()
            val finished = process.waitFor(20, TimeUnit.SECONDS)
            val output = process.inputStream.bufferedReader().readText().take(2000)
            JSONObject()
                .put("argv", argv.joinToString(" "))
                .put("finished", finished)
                .put("exit", if (finished) process.exitValue() else -1)
                .put("output", output)
                .put("elapsedMillis", System.currentTimeMillis() - started)
        }.getOrElse { error ->
            JSONObject()
                .put("argv", argv.joinToString(" "))
                .put("error", error.javaClass.simpleName + ": " + (error.message ?: ""))
                .put("elapsedMillis", System.currentTimeMillis() - started)
        }
    }

    @Test
    fun patchedKernelKeepsArtAliveWithoutReboot() {
        val bootBefore = DirtyfragAttempt.readBootId()
        assertNotNull("boot id must be readable", bootBefore)
        /*
         * An ordinary App is not allowed to read selinuxfs on this platform, so -1
         * means "not readable here", not "permissive". The Enforcing precondition is
         * checked from the harness (adb shell getenforce) before this test runs; the
         * value is recorded here for the evidence chain only.
         */
        val enforcingBefore = DirtyfragAttempt.readEnforcing()

        val request = JailbreakRequest(
            method = "dirtyfrag",
            attemptId = UUID.randomUUID().toString(),
            bootId = bootBefore,
            // The whole point: keep the kernel running after the patches land.
            softReboot = false,
            rootBackend = "ir",
        )
        val status = JailbreakExecutor.escalate(context, request)

        val bootAfterPatch = DirtyfragAttempt.readBootId()
        val record = JSONObject()
            .put("stage", status.stage)
            .put("failure", status.failure ?: JSONObject.NULL)
            .put("message", status.message)
            .put("rootBackend", status.rootBackend ?: JSONObject.NULL)
            .put("target", status.target ?: JSONObject.NULL)
            .put("bootIdBefore", bootBefore)
            .put("bootIdAfterPatch", bootAfterPatch)
            .put("enforcingBefore", enforcingBefore)
            .put("enforcingAfter", DirtyfragAttempt.readEnforcing() ?: JSONObject.NULL)
            .put("module", moduleLoaded())
            .put("sdk", android.os.Build.VERSION.SDK_INT)

        // 1) the patches have to land, otherwise the experiment measures nothing.
        assertEquals("patches did not land: " + status.failure, 
            JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED, status.stage)
        assertEquals("ir", status.rootBackend)
        // 2) applying them must not have rebooted the device.
        assertEquals("boot id changed while patching", bootBefore, bootAfterPatch)

        // 3) this instrumentation process is an ART process and is still answering.
        record.put("instrumentationAlive", true)

        // 4) cold ART start: a brand new VM on the patched kernel.
        val version = runProbe(listOf("/system/bin/app_process64", "-version"))
        val listing = runProbe(listOf("/system/bin/app_process64", "/system/bin/pm", "path",
            "android"))
        record.put("appProcessVersion", version)
        record.put("appProcessPm", listing)

        // 5) still the same boot => ART survived in the patched kernel.
        val bootAfterProbe = DirtyfragAttempt.readBootId()
        record.put("bootIdAfterProbe", bootAfterProbe)
        record.put("artSurvived", bootBefore == bootAfterProbe)
        evidence("w0-art-probe.json", record)

        assertEquals("ART in the patched kernel rebooted the device: W0 verdict = UNSTABLE",
            bootBefore, bootAfterProbe)
    }

    @Test
    fun deviceIdentityIsWhatTheSpecTargets() {
        // Cheap guard: the spec set only covers the releases it was generated from.
        val release = Os.uname().release
        val supported = IrImages.supports(context, release)
        val record = JSONObject()
            .put("release", release)
            .put("irSupported", supported)
            .put("unsupportedCode", IrImages.unsupported(release))
        evidence("w0-target.json", record)
        assertTrue("APK carries no spec for " + release, supported)
    }
}
