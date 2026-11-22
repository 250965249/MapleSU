package dev.maplesu.manager.runtime

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Which libraries MT actually maps, and whether any of them references a side library. */
class MtWiringEvidenceAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private fun root(command: String): String = DirectRoot.run(context, command).output

    @Test fun mappedLibrariesAndPatchedReferences() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val pid = root("/system/bin/ps -A -o PID,NAME | /system/bin/grep bin.mt.plus | head -1 | awk '{print \$1}'")
            .trim().lines().last().trim()
        val dir = SuDelivery.deliveredPath(context, "bin.mt.plus")!!.substringBeforeLast('/')
        val side = root("/system/bin/ls $dir | /system/bin/grep -E '^(libawru|libiccuf|libobopl)[.]so$'")
            .trim().lines().filter { it.isNotBlank() }
        val mapped = root("/system/bin/grep -o '/data/app/[^ ]*lib/arm64/[^ ]*[.]so' /proc/$pid/maps | " +
            "/system/bin/sort -u").trim().lines().filter { it.isNotBlank() }
        val referenced = side.joinToString(" ") { name ->
            val hits = root("/system/bin/grep -l -a '$name' $dir/*.so 2>/dev/null | /system/bin/tr '\n' ','")
            "$name -> [${hits.trim()}]"
        }
        android.util.Log.i("MapleSU",
            "MAPLESU_EVIDENCE mt_wiring pid=$pid mapped=${mapped.size} mappedList=${mapped.joinToString(",")}\n" +
                "SIDE=${side.joinToString(",")}\nREFS=$referenced")
        assertTrue("MT not running", pid.isNotEmpty())
    }
}
