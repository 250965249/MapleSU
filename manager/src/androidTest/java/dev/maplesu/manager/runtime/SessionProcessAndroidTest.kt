package dev.maplesu.manager.runtime

import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.util.concurrent.TimeUnit

/** Exercise the actual native launcher: connected FD3, separate stdio and real exit. */
class SessionProcessAndroidTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test(timeout = 15_000) fun explicitControlAndOnlySelectedDescriptorsSurviveExec() {
        val sentinel = File(context.cacheDir, "session-inheritance-sentinel")
        ParcelFileDescriptor.open(sentinel, ParcelFileDescriptor.MODE_READ_WRITE or
            ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_TRUNCATE).use { extra ->
            // Deliberately test an unrelated descriptor without CLOEXEC.
            Os.fcntlInt(extra.fileDescriptor, OsConstants.F_SETFD, 0)
            val command = """
                test -S /proc/self/fd/3 || exit 41
                for fd in /proc/self/fd/*; do
                    test "${'$'}(readlink "${'$'}fd")" != "${'$'}1" || exit 42
                done
                IFS= read -r control <&3
                IFS= read -r value
                printf '%s:%s:%s\n' "${'$'}control" "${'$'}value" "${'$'}2"
                printf 'separate-error\n' >&2
                exit 37
            """.trimIndent()
            val process = NativeSessionProcess.start(context, listOf("/system/bin/sh", "-c", command,
                "session-test", sentinel.absolutePath, "MapleSU-测试-🍁"))
            try {
                process.control.timeout(5_000)
                process.control.outputStream.write("connected-control\n".toByteArray())
                process.outputStream.write("separate-input\n".toByteArray())
                process.outputStream.close()
                assertTrue(process.waitFor(5, TimeUnit.SECONDS))
                assertEquals(37, process.exitValue())
                assertEquals("connected-control:separate-input:MapleSU-测试-🍁\n", process.inputStream.bufferedReader().readText())
                assertEquals("separate-error\n", process.errorStream.bufferedReader().readText())
            } finally {
                process.control.close()
                if (process.isAlive) process.destroyForcibly()
                process.outputStream.close(); process.inputStream.close(); process.errorStream.close()
            }
        }
        assertTrue(sentinel.delete())
    }

    @Test(timeout = 20_000) fun credentialSupervisorUsesInheritedControl() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val running = MapleSuSupervisedProcess.start(context,
            listOf("/system/bin/sh", "-c", "id -u; printf 'supervised-error\\n' >&2; exit 37"))
        try {
            assertTrue(running.process.waitFor(10, TimeUnit.SECONDS))
            assertEquals(37, running.process.exitValue())
            assertEquals("0\n", running.process.inputStream.bufferedReader().readText())
            assertEquals("supervised-error\n", running.process.errorStream.bufferedReader().readText())
        } finally {
            running.cancel(); running.closeControl()
            running.process.outputStream.close(); running.process.inputStream.close(); running.process.errorStream.close()
        }
    }
}
