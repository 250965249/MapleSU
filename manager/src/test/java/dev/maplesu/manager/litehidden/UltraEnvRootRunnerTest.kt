package dev.maplesu.manager.litehidden

import dev.maplesu.manager.recovery.RecoveryCommandResult
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.util.concurrent.TimeUnit

class UltraEnvRootRunnerTest {
    @Test fun sdkSuccessDoesNotHideShellFailureOrExplicitExit() {
        val runner = runner()
        val result = runner.run("printf 'partial output'; exit 7")
        assertEquals(7, result.code)
        assertEquals("partial output", result.output)
        assertEquals(0, runner.run("exec printf complete").code)
    }

    @Test fun truncatedSdkOutputDoesNotClaimCompletion() {
        val runner = UltraEnvRootRunner { RecoveryCommandResult(0, "truncated") }
        assertEquals(-1, runner.run("exit 0").code)
    }

    @Test fun hungShellTerminatesAndTheNextCallStillRuns() {
        val runner = runner(shortTimeout = true)
        val result = runner.run("sleep 30")
        assertTrue("the shell timeout must propagate: $result", result.code != 0)
        assertEquals("next", runner.run("printf next").output)
    }

    private fun runner(shortTimeout: Boolean = false): UltraEnvRootRunner {
        val shell = listOf("/bin/sh", "C:/Program Files/Git/bin/bash.exe").firstOrNull { File(it).canExecute() }
        assumeTrue(shell != null)
        return UltraEnvRootRunner { command ->
            val script = command.replace("/system/bin/timeout", "timeout")
                .replace("/system/bin/sh", "'${shell!!.replace('\\', '/')}'")
                .let { if (shortTimeout) it.replace("timeout -k 5 60", "timeout -k 0.1 0.1") else it }
            val process = ProcessBuilder(shell, "-c", script).redirectErrorStream(true).start()
            assertTrue("root command must leave the synchronous SDK call", process.waitFor(5, TimeUnit.SECONDS))
            RecoveryCommandResult(0, process.inputStream.bufferedReader().use { it.readText() })
        }
    }
}
