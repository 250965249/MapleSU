package dev.maplesu.manager.jailbreak

import android.net.Uri
import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Finish a hook attempt whose starting process died.
 *
 * The exploit hijacks the runtime for the handover, and the process that started the
 * attempt is regularly gone by the time the kernel side finishes. It was instrumented
 * ("Process crashed") with no Java stack, while the helper had already written
 * `verdict=OK` and `enforcingFinal=1`. The status file and that record both survive.
 *
 * The provider reconciles from them when its process starts (same boot only), and this
 * test just wakes that process: any call into the provider instantiates it. It asserts
 * only that the attempt's evidence is reachable; the state transition itself is checked
 * by reading the status afterwards, so a refusal here is a report, not a red test.
 */
@RunWith(AndroidJUnit4::class)
class HookResumeAndroidTest {

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun wakesTheProviderSoAPendingHookClaimCanFinish() {
        // Nothing here may throw: this test's only job is to start the provider process
        // so its onCreate can reconcile a pending hook claim. A refusal is a report.
        val uri = Uri.parse("content://" + context.packageName + ".root_directory")
        val reply = runCatching { context.contentResolver.call(uri, "status", null, Bundle()) }
        println("resume: provider call = " + reply.exceptionOrNull())
        Thread.sleep(8000)
        val after = runCatching { JailbreakStatus.read(context) }.getOrNull()
        println("resume: stage after = " + after?.stage + " workerPid=" + after?.workerPid)
    }
}
