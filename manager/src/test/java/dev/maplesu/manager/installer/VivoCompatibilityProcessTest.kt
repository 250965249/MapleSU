package dev.maplesu.manager.installer

import dev.maplesu.manager.ksu.KsuLog
import dev.maplesu.manager.ksu.KsuPatchProcessFixture
import java.io.File
import java.lang.reflect.InvocationTargetException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

class VivoCompatibilityProcessTest {
    private val java = File(System.getProperty("java.home"), "bin/java.exe").takeIf(File::isFile)
        ?: File(System.getProperty("java.home"), "bin/java")

    private fun command(arguments: List<String>): String = try {
        val method = VivoCompatibility::class.java.getDeclaredMethod("command", File::class.java, List::class.java)
        method.isAccessible = true
        method.invoke(VivoCompatibility, java, arguments) as String
    } catch (error: InvocationTargetException) {
        throw error.targetException
    }

    @Test fun failedVendorProcessKeepsActualCodeAndSeparateStreamsInDeveloperLog() {
        val arguments = listOf("-cp", System.getProperty("java.class.path"),
            KsuPatchProcessFixture::class.java.name, "output")
        val failure = runCatching { command(arguments) }.exceptionOrNull()
        assertEquals("INSTALLER_VIVO_PRODUCER_FAILED:stage=-cp code=37", failure?.message)
        val log = KsuLog.snapshot().last { it.startsWith("ksu.vivo-compatibility:") }
        assertTrue(log.contains("argv=${listOf(java.path) + arguments} code=37"))
        assertTrue(log.contains("stdout=out-0\nout-1\n"))
        assertTrue(log.contains("out-1999 stderr=err-0\nerr-1\n"))
        assertTrue(log.endsWith("err-1999"))
    }

    @Test fun successfulStderrDoesNotBecomeFeatureStdout() {
        assertEquals("", command(listOf("-version")))
        val log = KsuLog.snapshot().last { it.startsWith("ksu.vivo-compatibility:") }
        assertTrue(log.contains("stage=-version"))
        assertTrue(log.contains("code=0 stdout= stderr="))
        assertTrue(log.substringAfter("stderr=").isNotEmpty())
    }

    @Test fun runtimeVerificationPreservesTheProcessCauseAndCode() {
        val failure = runCatching { VivoCompatibility.verifyRuntime("KSU", java) }.exceptionOrNull()
        assertEquals("INSTALLER_VIVO_PRODUCER_FAILED:stage=feature code=1", failure?.cause?.message)
        assertEquals("INSTALLER_VR_FILTER_INACTIVE: ${failure?.cause?.message}", failure?.message)
        assertEquals("INSTALLER_VR_FILTER_INACTIVE", installerFailureDiagnostic(failure))
    }

    @Test fun interruptedVendorProcessKeepsCancellationAndStopsItsWorker() {
        val failure = AtomicReference<Throwable>()
        val interrupted = AtomicBoolean()
        val worker = Thread {
            try {
                command(listOf("-cp", System.getProperty("java.class.path"),
                    KsuPatchProcessFixture::class.java.name, "sleep"))
            } catch (error: Throwable) {
                failure.set(error)
                interrupted.set(Thread.currentThread().isInterrupted)
            }
        }
        worker.start()
        worker.interrupt()
        worker.join(5_000)
        assertFalse("the interrupted command did not finish", worker.isAlive)
        assertTrue(failure.get() is InterruptedException)
        assertEquals("INSTALLER_CANCELLED:stage=-cp code=130", failure.get()?.message)
        assertTrue(interrupted.get())
    }
}
