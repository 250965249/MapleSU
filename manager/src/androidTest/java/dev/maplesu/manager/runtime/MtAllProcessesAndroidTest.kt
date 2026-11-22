package dev.maplesu.manager.runtime

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Every MT process: is its PATH wired, and did it map the patched library. */
class MtAllProcessesAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private fun root(c: String): String = DirectRoot.run(context, c).output

    @Test fun everyMtProcess() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val dir = SuDelivery.deliveredPath(context, "bin.mt.plus")!!.substringBeforeLast('/')
        val script = "for p in \$(/system/bin/ps -A -o PID,NAME | /system/bin/grep bin.mt.plus | " +
            "/system/bin/awk '{print \$1}'); do " +
            "n=\$(/system/bin/ps -p \$p -o NAME | /system/bin/tail -1); " +
            "w=no; /system/bin/grep -a -q '" + dir + ":' /proc/\$p/environ && w=yes; " +
            "m=no; /system/bin/grep -q 'lib/arm64/libmt1' /proc/\$p/maps && m=yes; " +
            "echo \"PROC \$p \$n path_wired=\$w mt1_mapped=\$m\"; done"
        val out = root(script).trim()
        android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE mt_procs dir=$dir\n$out")
        assertTrue("no MT process found", out.contains("PROC"))
    }
}
