package dev.maplesu.manager.runtime

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Why a wired application still does not get root: inspect its actual process instead of
 * guessing. Answers two questions at once - does its PATH contain the directory holding the
 * delivered client, and was the patched library actually mapped into that process.
 */
class MtProcessDiagnosticsAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private fun root(command: String): String = DirectRoot.run(context, command).output

    @Test fun inspectMtProcess() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val pid = root("/system/bin/ps -A -o PID,NAME | /system/bin/grep bin.mt.plus | " +
            "/system/bin/head -1 | /system/bin/awk '{print \$1}'").trim().lines().last().trim()
        val dir = SuDelivery.deliveredPath(context, "bin.mt.plus")?.substringBeforeLast('/') ?: ""
        val environ = root("/system/bin/tr '\\0' '\\n' < /proc/$pid/environ | /system/bin/grep -E '^PATH='")
        val mapped = root("/system/bin/grep -c 'lib/arm64' /proc/$pid/maps 2>/dev/null; " +
            "/system/bin/grep -o 'lib[a-z]*\\.so' /proc/$pid/maps 2>/dev/null | /system/bin/sort -u | /system/bin/head -8")
        val works = root("/system/bin/ls -l $dir/su 2>&1")
        android.util.Log.i("MapleSU",
            "MAPLESU_EVIDENCE mt_diag pid=$pid dir=$dir\nPATH_LINE=$environ\nMAPS=$mapped\nIMAGE=$works")
        assertTrue("MT is not running", pid.isNotEmpty())
    }
}
