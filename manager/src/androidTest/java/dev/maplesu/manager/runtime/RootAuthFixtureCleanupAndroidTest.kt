package dev.maplesu.manager.runtime

import android.os.Bundle
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.util.concurrent.TimeUnit

/** Opt-in recovery of one recorded debug fixture, using the real Manager Context. */
class RootAuthFixtureCleanupAndroidTest {
    @Test fun terminateRecordedDaemonFixture() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val arguments = InstrumentationRegistry.getArguments()
        assumeTrue(arguments.getString("cleanupRootAuthFixture") == "true")
        val bootId = requireNotNull(arguments.getString("fixtureBootId"))
        val pid = requireNotNull(arguments.getString("fixturePid")).toInt()
        val startTime = requireNotNull(arguments.getString("fixtureStartTime")).toLong()
        val apk = requireNotNull(arguments.getString("fixtureApkPath"))
        require(bootId.matches(Regex("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")))
        require(pid > 1 && startTime > 0)
        require(apk.startsWith("/data/app/") && apk.contains("/dev.maplesu.manager-") && apk.endsWith("/base.apk"))
        require(apk.matches(Regex("[A-Za-z0-9_~=/+.-]+")))
        val script = """
            set -eu
            test "${'$'}(id -u)" = 0
            test "${'$'}(cat /proc/sys/kernel/random/boot_id)" = '$bootId'
            test -d /proc/$pid
            test "${'$'}(stat -c %u /proc/$pid)" = 0
            test "${'$'}(awk '{print ${'$'}22}' /proc/$pid/stat)" = '$startTime'
            test "${'$'}(tr '\000' '\n' < /proc/$pid/cmdline | head -n 1)" = dev.maplesu.manager:root:daemon
            grep -Fq -- '$apk' /proc/$pid/maps
            printf 'FIXTURE_IDENTITY_VERIFIED:$pid:$startTime\n'
            kill -TERM $pid
            count=0
            while test -d /proc/$pid; do
                test "${'$'}(awk '{print ${'$'}22}' /proc/$pid/stat)" = '$startTime'
                count=${'$'}((count + 1))
                test "${'$'}count" -lt 30
                sleep 0.1
            done
            printf 'FIXTURE_TERMINATED:$pid\n'
        """.trimIndent()
        val result = MapleSuRuntime.openShell(instrumentation.targetContext).use { shell ->
            assertTrue("Manager internal Key Root is required", shell.isRoot && shell.isAlive)
            shell.newJob().add(script).to(ArrayList<String>(), ArrayList<String>())
                .enqueue().get(15, TimeUnit.SECONDS)
        }
        instrumentation.sendStatus(2, Bundle().apply {
            putString("rootAuthFixtureCleanup", result.out.joinToString("\n"))
            putString("cleanupError", result.err.joinToString("\n"))
            putInt("cleanupExitCode", result.code)
        })
        assertTrue(result.err.joinToString("\n"), result.isSuccess)
        assertEquals(listOf("FIXTURE_IDENTITY_VERIFIED:$pid:$startTime", "FIXTURE_TERMINATED:$pid"), result.out)
    }
}
