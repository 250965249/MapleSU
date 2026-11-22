package dev.maplesu.manager.runtime

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Can an untrusted_app process execute a file from /data/local/tmp when it carries an
 * executable label? MapleSU's design deploys one shared `su` and points the target's PATH at
 * its directory; whether that is reproducible here decides the whole approach.
 */
class TmpExecProbeAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    @Test fun sharedDirectoryIsExecutable() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val directory = "/data/local/tmp/maplesu-ultrabe"
        val target = "$directory/su"
        val prepare = DirectRoot.run(context, """
            set -e
            /system/bin/mkdir -p $directory
            /system/bin/chmod 0755 $directory
            /system/bin/cp -f ${context.applicationInfo.nativeLibraryDir}/libmaplesu_su.so $target
            /system/bin/chmod 0755 $target
            /system/bin/chcon u:object_r:apk_data_file:s0 $target
            /system/bin/ls -lZ $target
        """.trimIndent())
        val result = runCatching {
            val process = ProcessBuilder(target, "--help").redirectErrorStream(true).start()
            val out = process.inputStream.bufferedReader().readText()
            process.waitFor() to out
        }
        android.util.Log.i("MapleSU",
            "MAPLESU_EVIDENCE tmp_exec prepare=[${prepare.output.trim()}] result=[$result]")
        assertTrue("prepare failed", prepare.code == 0)
    }
}
