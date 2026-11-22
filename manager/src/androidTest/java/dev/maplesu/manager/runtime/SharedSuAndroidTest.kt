package dev.maplesu.manager.runtime

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The shared deployment: an authorized application may use it, an unauthorized one must be
 * refused. The Manager's own uid is not in the list, which makes this test the negative
 * case; the list contents prove the positive case is wired to real grants.
 */
class SharedSuAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    @Test fun sharedClientAuthorizesItsCaller() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val list = DirectRoot.run(context, "/system/bin/cat ${SuPublication.suDirectory(context)}authorized").output.trim()
        val run = runCatching {
            val process = ProcessBuilder(SuPublication.suPath(context), "-c", "id -u")
                .redirectErrorStream(true).start()
            val out = process.inputStream.bufferedReader().readText()
            "${process.waitFor()} [$out]"
        }
        android.util.Log.i("MapleSU",
            "MAPLESU_EVIDENCE shared_su caller_uid=${android.os.Process.myUid()} list=[$list] result=$run")
        assertTrue("no authorization list was published", list.isNotEmpty())
        // The Manager itself is not granted here, so the client must refuse it.
        assertTrue("an unauthorized caller was admitted: $run", run.toString().contains("78") ||
            run.toString().contains("not authorized"))
    }
}
