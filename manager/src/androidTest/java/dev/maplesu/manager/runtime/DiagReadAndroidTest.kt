package dev.maplesu.manager.runtime

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Test

/** Reads the client's diagnostic log through a root process and copies it to logcat. */
class DiagReadAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    @Test fun dumpDiagnostics() {
        val text = DirectRoot.run(context, "/system/bin/cat /data/local/tmp/maplesu-diag.log 2>&1").output
        // Which build is actually on disk: the markers only exist in the newest client.
        val fixture = "dev.maplesu.wiredtarget"
        val dir = runCatching { context.packageManager.getApplicationInfo(fixture, 0).nativeLibraryDir }.getOrNull()
        val markers = dir?.let {
            val path = "$it/su"
            val size = DirectRoot.run(context, "/system/bin/stat -c %s '$path' 2>/dev/null").output.trim()
            val enter = DirectRoot.run(context, "/system/bin/grep -a -c 'main-enter' '$path' 2>/dev/null").output.trim()
            val supervisor = DirectRoot.run(context, "/system/bin/grep -a -c 'enter-supervisor' '$path' 2>/dev/null").output.trim()
            "dir=$it size=$size mainEnter=$enter supervisor=$supervisor"
        } ?: "no dir"
        android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE diag=${markers} text=[${text.trim().replace('\n', '|').takeLast(600)}]")
    }
}
