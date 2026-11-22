// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime.ultra

import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class UltraSuProcessExecTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun startupFailureIncludesErrnoWithoutTheCommandOrPath() {
        val path = File(temporary.root, "private-helper-absent").absolutePath
        val result = ProcessSuExec.exec(listOf(path, "secret-command"), 2_000, null)
        assertTrue(result.failure.orEmpty(), result.failure.orEmpty().matches(Regex("START_FAILED:IOException:errno=[0-9]+")))
        assertFalse(result.failure.orEmpty().contains(path))
        assertFalse(result.failure.orEmpty().contains("secret-command"))
    }

    @Test
    fun timeoutIncludesBlockedStdinAndReapsTheOwnedProcess() {
        val pid = temporary.newFile("blocked.pid")
        // 与其它用例同形：先等宿主 fixture 真的起来（冷 JVM 在满载的主机上可能 >500 ms），
        // 再断言"超时回收"。原先直接 readText() 在满载时会读到空文件而抛
        // NumberFormatException —— 那是用例自身的竞态，不是 ProcessSuExec 的缺陷。
        val worker = Executors.newSingleThreadExecutor()
        try {
            val call = worker.submit<SuExecResult> {
                ProcessSuExec.exec(
                    fixtureArgs("blocked-input", pid),
                    2_000,
                    "x".repeat(2 * 1024 * 1024),
                )
            }
            awaitPid(pid)
            val result = call.get(8, TimeUnit.SECONDS)
            assertTrue(result.timedOut)
            assertFalse(ProcessHandle.of(pid.readText().trim().toLong()).map { it.isAlive }.orElse(false))
        } finally {
            killFixture(pid)
            worker.shutdownNow()
        }
    }

    @Test
    fun outputIsDrainedWhileTheChildIsWaitingForInput() {
        val pid = temporary.newFile("duplex.pid")
        val input = "x".repeat(256 * 1024)
        val result = executeFixture("output-first", pid, stdin = input)
        assertTrue(result.toString(), result.ok)
        assertEquals("o".repeat(256 * 1024) + "\ninput=${input.length}\n", result.output)
    }

    @Test
    fun concurrentCallersDoNotStartCompetingSuProcesses() {
        val workers = Executors.newFixedThreadPool(3)
        val start = CountDownLatch(1)
        val lock = temporary.newFile("single-process.lock")
        val pids = (1..3).map { temporary.newFile("parallel-$it.pid") }
        try {
            val calls = pids.map { pid -> workers.submit<SuExecResult> {
                start.await()
                ProcessSuExec.exec(fixtureArgs("exclusive", pid, lock.absolutePath), 4_000, null)
            } }
            start.countDown()
            calls.forEach { call ->
                val result = call.get(6, TimeUnit.SECONDS)
                assertTrue(result.toString(), result.ok)
            }
        } finally {
            pids.forEach(::killFixture)
            workers.shutdownNow()
        }
    }

    @Test
    fun queueTimeoutDoesNotStartAnotherProcess() {
        val ownerPid = temporary.newFile("owner.pid")
        val queuedPid = temporary.newFile("queued.pid")
        val worker = Executors.newSingleThreadExecutor()
        try {
            val owner = worker.submit<SuExecResult> {
                ProcessSuExec.exec(fixtureArgs("blocked-input", ownerPid), 1_200, null)
            }
            awaitPid(ownerPid)
            val queued = ProcessSuExec.exec(fixtureArgs("blocked-input", queuedPid), 100, null)
            assertTrue(queued.timedOut)
            assertEquals(0L, queuedPid.length())
            assertTrue(owner.get(4, TimeUnit.SECONDS).timedOut)
        } finally {
            killFixture(ownerPid)
            killFixture(queuedPid)
            worker.shutdownNow()
        }
    }

    @Test
    fun interruptionPreservesTheFlagAndReapsTheChild() {
        val pid = temporary.newFile("cancel.pid")
        var result: SuExecResult? = null
        var interrupted = false
        val caller = Thread {
            result = ProcessSuExec.exec(fixtureArgs("blocked-input", pid), 5_000, null)
            interrupted = Thread.currentThread().isInterrupted
        }
        try {
            caller.start()
            awaitPid(pid)
            caller.interrupt()
            caller.join(3_000)
            assertFalse(caller.isAlive)
            assertEquals("EXEC_INTERRUPTED", result?.failure)
            assertTrue(interrupted)
            assertFalse(ProcessHandle.of(pid.readText().trim().toLong()).map { it.isAlive }.orElse(false))
        } finally {
            killFixture(pid)
            caller.interrupt()
            caller.join(2_000)
        }
    }

    @Test
    fun overlappingRootProbesShareOneObservation() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        val channel = UltraSuChannel(exec = { _, _, _ ->
            calls.incrementAndGet()
            entered.countDown()
            release.await()
            SuExecResult(0, "0\n")
        })
        var firstUid: Int? = null
        var secondUid: Int? = null
        val first = Thread { firstUid = channel.rootUid() }
        val second = Thread { secondUid = channel.rootUid() }
        try {
            first.start()
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            second.start()
            val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
            while (second.state != Thread.State.BLOCKED && calls.get() < 2 && System.nanoTime() < until) {
                Thread.yield()
            }
        } finally {
            release.countDown()
            first.join(2_000)
            second.join(2_000)
        }
        assertEquals(0, firstUid)
        assertEquals(0, secondUid)
        assertEquals(1, calls.get())
        assertEquals(0, channel.rootUid())
        assertEquals("A later explicit probe must make a new observation", 2, calls.get())
    }

    @Test
    fun failedCommandInvalidatesThePathWithoutReplayingTheCommand() {
        val calls = mutableListOf<String>()
        val channel = UltraSuChannel(exec = { argv, _, _ ->
            val command = argv.last()
            calls += command
            if (command == "change-once") SuExecResult(-1, "", timedOut = true)
            else SuExecResult(0, if (command == "id -u") "0\n" else "done")
        })
        assertTrue(channel.runRoot("change-once")!!.timedOut)
        assertEquals("done", channel.runRoot("next")?.output)
        assertEquals(listOf("id -u", "change-once", "id -u", "next"), calls)
    }

    @Test
    fun failedRootProbeIsRetriedByTheNextExplicitCall() {
        var available = false
        val channel = UltraSuChannel(exec = { _, _, _ -> SuExecResult(0, if (available) "0\n" else "2000\n") })
        assertNull(channel.rootUid())
        available = true
        assertEquals(0, channel.rootUid())
    }

    @Test
    fun rootTextFromAFailedCommandIsNotSuccessfulPairingEvidence() {
        val channel = UltraSuChannel(exec = { _, _, _ -> SuExecResult(69, "0\n") })
        assertNull(channel.rootUid())
    }

    private fun executeFixture(mode: String, pid: File, stdin: String?, timeout: Long = 3_000): SuExecResult {
        val worker = Executors.newSingleThreadExecutor()
        try {
            return worker.submit<SuExecResult> {
                ProcessSuExec.exec(fixtureArgs(mode, pid), timeout, stdin)
            }.get(5, TimeUnit.SECONDS)
        } finally {
            killFixture(pid)
            worker.shutdownNow()
        }
    }

    private fun fixtureArgs(mode: String, pid: File, vararg extra: String): List<String> {
        val java = File(System.getProperty("java.home"), "bin/java" + if (File.separatorChar == '\\') ".exe" else "").absolutePath
        // Keep the Android test classpath out of Windows' process command-line limit.
        // TemporaryFolder retains each caller's argument file until its child has exited.
        val arguments = File.createTempFile("ultra-su-child-", ".args", temporary.root)
        arguments.writeText((listOf(
            "-cp", System.getProperty("java.class.path"), UltraSuChildFixture::class.java.name, mode, pid.absolutePath,
        ) + extra).joinToString("\n") {
            "\"${it.replace('\\', '/').replace("\"", "\\\"")}\""
        })
        return listOf(java, "@${arguments.absolutePath}")
    }

    private fun killFixture(pid: File) {
        pid.readText().trim().toLongOrNull()?.let { value -> ProcessHandle.of(value).ifPresent { it.destroyForcibly() } }
    }

    private fun awaitPid(pid: File) {
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (pid.length() == 0L && System.nanoTime() < until) Thread.sleep(5)
        assertTrue("The host fixture did not start", pid.length() > 0L)
    }
}

/** Host-only child process; it never invokes su or touches an Android device. */
object UltraSuChildFixture {
    @JvmStatic
    fun main(args: Array<String>) {
        File(args[1]).writeText(ProcessHandle.current().pid().toString())
        when (args[0]) {
            "blocked-input" -> Thread.sleep(30_000)
            "output-first" -> {
                System.out.print("o".repeat(256 * 1024))
                System.out.flush()
                val input = System.`in`.readBytes()
                System.out.print("\ninput=${input.size}\n")
            }
            "exclusive" -> File(args[2]).outputStream().channel.use { channel ->
                val lock = channel.tryLock() ?: kotlin.system.exitProcess(9)
                lock.use { Thread.sleep(180) }
            }
        }
    }
}
