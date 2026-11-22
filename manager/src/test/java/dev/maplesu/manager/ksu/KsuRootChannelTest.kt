// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import com.topjohnwu.superuser.Shell
import dev.maplesu.manager.installer.InstallerRootSourceRegistry
import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.io.InputStream
import java.io.File
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.util.concurrent.TimeoutException

/**
 * Host tests for the Mode B root channel (no device, no libsu process).
 *
 * Covered here: the exact argv shape handed to libsu, the `isRoot`/`isAlive` gate and the
 * fail-closed `KSU_ROOT_CHANNEL_UNAVAILABLE:<cause>` tokens. The actual `debug su` round
 * trip is device evidence (`NormalTakeoverAndroidTest`), never a host claim.
 */
class KsuRootChannelTest {

    private val daemon = "/data/app/~~hash/dev.maplesu.manager-1/lib/arm64/libksud_ksu.so"

    @Test
    fun commandUsesPackagedKsudDebugSu() {
        assertEquals(
            listOf(daemon, "debug", "su"),
            KsuRootChannel.command(daemon, globalMnt = false),
        )
        assertEquals(
            listOf(daemon, "debug", "su", "-g"),
            KsuRootChannel.command(daemon, globalMnt = true),
        )
    }

    @Test
    fun commandRejectsForeignExecutable() {
        assertThrows(KsuCommandRejectedException::class.java) {
            KsuRootChannel.command("/system/bin/sh", globalMnt = false)
        }
    }

    @Test
    fun launchFailureCarriesNamedTokenAndCause() {
        val failure = assertThrows(IllegalStateException::class.java) {
            KsuRootChannel().openVerified(daemon, globalMnt = false) {
                throw IOException("libksud_ksu.so missing")
            }
        }
        val message = failure.message.orEmpty()
        assertTrue(message, message.startsWith("KSU_ROOT_CHANNEL_UNAVAILABLE:"))
        assertTrue(message, message.contains("LAUNCH_FAILED:IOException"))
        assertTrue(failure.cause is IOException)
    }

    @Test
    fun nonRootShellIsRejectedAndClosed() {
        val shell = FakeShell(status = Shell.NON_ROOT_SHELL)
        val failure = assertThrows(IllegalStateException::class.java) {
            KsuRootChannel().openVerified(daemon, globalMnt = false) { shell }
        }
        assertTrue(failure.message.orEmpty(), failure.message.orEmpty().endsWith("SHELL_NOT_ROOT"))
        assertTrue("a rejected shell must be closed", shell.closed)
    }

    @Test
    fun deadShellIsRejectedAndClosed() {
        val shell = FakeShell(alive = false)
        val failure = assertThrows(IllegalStateException::class.java) {
            KsuRootChannel().openVerified(daemon, globalMnt = false) { shell }
        }
        assertTrue(failure.message.orEmpty(), failure.message.orEmpty().endsWith("SHELL_NOT_ALIVE"))
        assertTrue("a rejected shell must be closed", shell.closed)
    }

    @Test
    fun usableRootShellIsReturnedUntouched() {
        val shell = FakeShell()
        val opened = KsuRootChannel().openVerified(daemon, globalMnt = true) { shell }
        assertSame(shell, opened)
        assertFalse("an accepted shell must stay open", shell.closed)
    }

    @Test
    fun causeOrderIsRootThenAlive() {
        assertEquals("SHELL_NOT_ROOT", KsuRootChannel.unusableCause(isRoot = false, isAlive = false))
        assertEquals("SHELL_NOT_ALIVE", KsuRootChannel.unusableCause(isRoot = true, isAlive = false))
        assertEquals(null, KsuRootChannel.unusableCause(isRoot = true, isAlive = true))
    }

    @Test
    fun channelIsRegisteredOnlyForKsuMode() {
        try {
            InstallerRootSourceRegistry.install(null)
            assertFalse(KsuRootChannel.installIfKsu(WorkMode.LITE))
            assertFalse(KsuRootChannel.installIfKsu(null))
            assertNull(runCatching { InstallerRootSourceRegistry.require() }.getOrNull())

            assertTrue(KsuRootChannel.installIfKsu(WorkMode.KSU))
            assertTrue(InstallerRootSourceRegistry.require() is KsuRootChannel)
        } finally {
            InstallerRootSourceRegistry.install(null)
        }
    }

    @Test
    fun hungCommandEndsWithNamedFailureAndClosesItsShell() {
        val shell = FakeShell(neverCompletes = true)
        val failure = assertThrows(IllegalStateException::class.java) {
            KsuRootChannel.execOn(shell, "sleep forever", timeoutMs = 10)
        }
        assertTrue(failure.message.orEmpty().endsWith("COMMAND_TIMEOUT"))
        assertEquals(10L, shell.waitTimeout)
        assertEquals(TimeUnit.MILLISECONDS, shell.waitUnit)
        assertEquals(true, shell.cancelInterrupt)
        assertTrue(shell.closed)
    }

    @Test
    fun commandWaitUsesEachRequestedTimeoutAndPreservesReceipt() {
        for (timeoutMs in listOf(30_000L, 300_000L, 12_345L)) {
            val shell = FakeShell(code = 7, out = listOf("out", ""), err = listOf("err", ""))
            val result = KsuRootChannel.execOn(shell, "module command", timeoutMs)
            assertEquals(timeoutMs, shell.waitTimeout)
            assertEquals(TimeUnit.MILLISECONDS, shell.waitUnit)
            assertEquals(KsuShellResult(7, listOf("out", ""), listOf("err", "")), result)
            assertNull(shell.cancelInterrupt)
            assertFalse(shell.closed)
        }
    }

    @Test
    fun streamingCallbacksArriveBeforeWaitingAndKeepTheCompleteReceipt() {
        val shell = FakeShell(code = 7, out = listOf("out", ""), err = listOf("err", ""))
        val stdout = mutableListOf<String>()
        val stderr = mutableListOf<String>()
        val result = KsuRootChannel.execOn(shell, "module command", 12_345L,
            { assertNull(shell.waitTimeout); stdout += it },
            { assertNull(shell.waitTimeout); stderr += it })

        assertEquals(listOf("out", ""), stdout)
        assertEquals(listOf("err", ""), stderr)
        assertEquals(KsuShellResult(7, stdout, stderr), result)
        assertEquals(12_345L, shell.waitTimeout)
    }

    @Test
    fun partialStreamingOutputIsVisibleWhenTheCommandTimesOut() {
        val shell = FakeShell(neverCompletes = true, out = listOf("still installing"))
        val stdout = mutableListOf<String>()
        assertThrows(IllegalStateException::class.java) {
            KsuRootChannel.execOn(shell, "slow module command", 10L, { stdout += it }, {})
        }
        assertEquals(listOf("still installing"), stdout)
        assertTrue(shell.closed)
    }

    @Test
    fun legacyCommandWaitKeepsItsDefaultTimeout() {
        val shell = FakeShell()
        KsuRootChannel.execOn(shell, "module command")
        assertEquals(120_000L, shell.waitTimeout)
        assertEquals(TimeUnit.MILLISECONDS, shell.waitUnit)
    }

    @Test
    fun defaultModuleInstallWaitsForTheScriptWithoutAnExecutionDeadline() {
        val shell = FakeShell(out = listOf("long-running customize.sh completed"))
        val backend = KsuCommandBackend(
            daemonPathProvider = { "/data/adb/ksud" },
            runner = KsuShellRunner { _, timeout -> KsuRootChannel.execOn(shell, "customize.sh", timeout) },
            probe = object : KsuPathProbe { override fun exists(path: String) = true },
        )
        val zip = File.createTempFile("long-install-", ".zip")
        try {
            val result = KsuModuleOps(backend).installResult(zip)
            assertEquals(0, result.code)
            assertEquals(listOf("long-running customize.sh completed"), result.out)
            assertTrue("KSU waits for the installer, without a fixed runtime limit", shell.untimedWait)
            assertNull(shell.waitTimeout)
        } finally { zip.delete() }
    }

    @Test
    fun interruptingAnUnboundedCommandCancelsItsJobAndClosesTheShell() {
        val shell = FakeShell(interruptWait = true)
        try {
            val failure = assertThrows(IllegalStateException::class.java) {
                KsuRootChannel.execOn(shell, "customize.sh", 0L)
            }
            assertTrue(failure.message.orEmpty().endsWith("COMMAND_INTERRUPTED"))
            assertEquals(true, shell.cancelInterrupt)
            assertTrue(shell.closed)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }

    @Test
    fun cancellingAnUnboundedInstallInterruptsTheShellWait() = runBlocking {
        val entered = CountDownLatch(1)
        val shell = FakeShell(neverCompletes = true, waitEntered = entered)
        val runner = RootShellKsuRunner(KsuRootShellExecutor { command ->
            KsuRootChannel.execOn(shell, command, KsuTimeouts.MODULE_INSTALL_MS)
        })
        val ops = KsuModuleOps(KsuCommandBackend(
            daemonPathProvider = { "/data/adb/ksud" }, runner = runner,
            probe = object : KsuPathProbe { override fun exists(path: String) = true },
        ))
        val zip = File.createTempFile("cancel-install-", ".zip")
        val job = launch(Dispatchers.IO) {
            runInterruptible { ops.installResult(zip) }
        }
        try {
            withContext(Dispatchers.IO) { assertTrue(entered.await(2, TimeUnit.SECONDS)) }
            withTimeout(2_000) { job.cancelAndJoin() }
            assertTrue(job.isCancelled)
            assertEquals(true, shell.cancelInterrupt)
            assertTrue(shell.closed)
        } finally { job.cancelAndJoin(); zip.delete() }
    }

    @Test
    fun scriptExitAndExecKeepTheOuterReceiptShellAliveWithTheOriginalStatus() {
        val bash = if (File("C:/Program Files/Git/bin/bash.exe").isFile)
            "C:/Program Files/Git/bin/bash.exe" else "/bin/sh"
        for ((script, expected) in listOf("echo body; exit 0" to "0", "exit 7" to "7",
                "exec sh -c 'exit 3'" to "3", "set -e; false" to "1")) {
            val shell = FakeShell()
            KsuRootChannel.execOn(shell, script)
            val process = ProcessBuilder(bash, "-c", shell.submitted + "\necho RECEIPT=\$?\n")
                .redirectErrorStream(true).start()
            val output = process.inputStream.bufferedReader().use { it.readText() }
            assertEquals(0, process.waitFor())
            assertTrue("$script: $output", output.lineSequence().any { it == "RECEIPT=$expected" })
        }
    }
}

/** Minimal libsu shell double: only the state probes the channel contract reads. */
private class FakeShell(
    private val status: Int = Shell.ROOT_SHELL,
    private val alive: Boolean = true,
    val neverCompletes: Boolean = false,
    private val code: Int = 0,
    private val out: List<String> = emptyList(),
    private val err: List<String> = emptyList(),
    private val interruptWait: Boolean = false,
    private val waitEntered: CountDownLatch? = null,
) : Shell() {
    var closed = false
        private set
    var submitted = ""
    var waitTimeout: Long? = null
    var waitUnit: TimeUnit? = null
    var cancelInterrupt: Boolean? = null
    var untimedWait = false

    override fun isAlive(): Boolean = alive

    override fun execTask(task: Shell.Task) = throw UnsupportedOperationException("execTask")

    override fun submitTask(task: Shell.Task) = throw UnsupportedOperationException("submitTask")

    override fun newJob(): Shell.Job = object : Shell.Job() {
        private var stdout: MutableList<String>? = null
        private var stderr: MutableList<String>? = null
        override fun add(vararg commands: String): Shell.Job = apply { submitted += commands.joinToString("\n") }
        override fun add(input: InputStream): Shell.Job = throw UnsupportedOperationException("add")
        override fun to(stdout: MutableList<String>?): Shell.Job = apply { this.stdout = stdout }
        override fun to(stdout: MutableList<String>?, stderr: MutableList<String>?): Shell.Job = apply {
            this.stdout = stdout
            this.stderr = stderr
        }
        override fun exec(): Shell.Result = object : Shell.Result() {
            override fun getCode(): Int = this@FakeShell.code
            override fun getOut(): MutableList<String> = this@FakeShell.out.toMutableList()
            override fun getErr(): MutableList<String> = this@FakeShell.err.toMutableList()
        }
        override fun submit(executor: Executor?, callback: Shell.ResultCallback?) = throw UnsupportedOperationException("submit")
        override fun enqueue(): Future<Shell.Result> {
            stdout?.addAll(out)
            stderr?.addAll(err)
            val completed = CompletableFuture.completedFuture(exec())
            return object : Future<Shell.Result> by completed {
                override fun get(): Shell.Result {
                    untimedWait = true
                    if (interruptWait) throw InterruptedException("fixture interrupted")
                    if (neverCompletes) {
                        waitEntered?.countDown()
                        CountDownLatch(1).await()
                    }
                    return completed.get()
                }
                override fun get(timeout: Long, unit: TimeUnit): Shell.Result {
                    waitTimeout = timeout
                    waitUnit = unit
                    if (neverCompletes) throw TimeoutException("fixture timeout")
                    return completed.get(timeout, unit)
                }
                override fun cancel(mayInterruptIfRunning: Boolean): Boolean {
                    cancelInterrupt = mayInterruptIfRunning
                    return completed.cancel(mayInterruptIfRunning)
                }
            }
        }
    }

    override fun getStatus(): Int = status

    override fun waitAndClose(timeout: Long, unit: TimeUnit): Boolean = false

    override fun close() {
        closed = true
    }
}
