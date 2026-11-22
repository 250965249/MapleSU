package dev.maplesu.manager.jailbreak

import dev.maplesu.manager.runtime.JailbreakDaemonMain
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.util.Base64

/**
 * Host regression for the executor protocol that E2 changed.
 *
 * <p>The review measured two concrete gaps in the resident executor: it had no way to
 * write a child's input at all, and `close` only removed the registry entry, so the child
 * kept running (`AFTER_CLOSE taskRegistered=false childAlive=true`). Both are asserted
 * here against the real dispatcher, on the host, so a later edit cannot quietly restore
 * the old behaviour.
 *
 * <p>The protocol is Android-independent on purpose: `android.util.Base64` was replaced by
 * `java.util.Base64` (both exist on this module's minSdk 31) precisely so this file can
 * drive `handle()` instead of a reimplementation of it. `main()` still needs
 * `android.os.Process`, so it is not exercised here - the uid-0 admission path is device
 * evidence, not host evidence.
 */
class JailbreakExecutorProtocolHostTest {
    private val windows = System.getProperty("os.name").orEmpty().lowercase().contains("win")

    private fun text(value: String): String =
        Base64.getEncoder().encodeToString(value.toByteArray(Charsets.UTF_8))

    private fun argv(vararg parts: String): String =
        Base64.getEncoder().encodeToString(parts.joinToString("\n").toByteArray(Charsets.UTF_8))

    private fun reply(request: String): String = JailbreakDaemonMain.handle(request, 4242, 10481)

    private fun token(reply: String): Int {
        assertTrue("not an accepted start: $reply", reply.startsWith("OK "))
        return reply.removePrefix("OK ").split(' ')
            .firstOrNull { it.startsWith("token=") }
            ?.substringAfter('=')?.toIntOrNull()
            ?: error("no token in $reply")
    }

    private fun tempDirectory(): File =
        File(System.getProperty("java.io.tmpdir"), "maplesu-executor-" + System.nanoTime())
            .also { assertTrue("could not create " + it, it.mkdirs()) }

    private fun await(reply: String): Int {
        val exit = reply.removePrefix("OK ").split(' ')
            .firstOrNull { it.startsWith("exit=") }?.substringAfter('=')
        assertTrue("no exit status in $reply", exit != null && exit != "running")
        return exit!!.toInt()
    }

    @Test fun protocolAdvertisesTheInteractiveSurface() {
        val reply = reply("protocol")
        assertTrue(reply, reply.startsWith("OK "))
        // What the App needs before it can honestly offer a shell or a signal.
        assertTrue(reply, reply.contains("stdin=1"))
        assertTrue(reply, reply.contains("signal=1"))
        assertTrue(reply, reply.contains("close=terminate"))
        // No PTY in this executor: saying so is what keeps a terminal client honest.
        assertTrue(reply, reply.contains("pty=0"))
    }

    @Test fun stdinReachesTheChildAndEndOfInputClosesIt() {
        assumeTrue("POSIX host has no cmd.exe", windows)
        val directory = tempDirectory()
        val started = reply("start " + argv("cmd.exe", "/c", "findstr . > stdin.txt") +
            " cwd=" + text(directory.absolutePath))
        val token = token(started)
        try {
            assertEquals("OK", reply("stdin $token " + text("host-stdin-line" + System.lineSeparator())))
            // `-` is the end-of-input marker: without it the child would wait forever.
            assertEquals("OK", reply("stdin $token -"))
            val exit = await(reply("wait $token 15000"))
            assertEquals("findstr exits only after EOF reaches it", 0, exit)
            val written = File(directory, "stdin.txt")
            assertTrue("the child wrote no file", written.isFile)
            val body = written.readText()
            assertTrue("stdin did not reach the child: $body", body.contains("host-stdin-line"))
        } finally {
            reply("close $token")
            directory.deleteRecursively()
        }
    }

    @Test fun closeTerminatesTheChildInsteadOfOnlyForgettingIt() {
        assumeTrue("POSIX host has no cmd.exe", windows)
        val directory = tempDirectory()
        /*
         * A child that keeps producing a side effect for far longer than the close. If
         * close only removed the registry entry, the file keeps growing after it; a
         * terminated child stops writing. No pid discovery is needed, so the assertion
         * does not depend on how the platform names or reaps the process.
         */
        val ticks = File(directory, "ticks.txt")
        val started = reply("start " + argv("cmd.exe", "/c",
            "for /l %i in (1,1,120) do @(echo tick >> ticks.txt & ping -n 2 127.0.0.1 > nul)") +
            " cwd=" + text(directory.absolutePath))
        val token = token(started)
        try {
            val first = System.currentTimeMillis() + 15_000
            while ((!ticks.isFile || ticks.length() == 0L) && System.currentTimeMillis() < first) {
                Thread.sleep(100)
            }
            assertTrue("the child produced no side effect at all", ticks.isFile && ticks.length() > 0L)
            assertEquals("OK", reply("close $token"))
            Thread.sleep(1_500)
            val afterClose = ticks.length()
            Thread.sleep(2_500)
            val later = ticks.length()
            assertEquals("close only removed the task; the child is still running", afterClose, later)
        } finally {
            reply("close $token")
            directory.deleteRecursively()
        }
    }

    @Test fun startCarriesWorkingDirectoryAndEnvironment() {
        assumeTrue("POSIX host has no cmd.exe", windows)
        val directory = tempDirectory()
        val environment = ArrayList<String>()
        listOf("SystemRoot", "PATH", "windir").forEach { name ->
            System.getenv(name)?.let { environment += name + "=" + it }
        }
        environment += "MAPLESU_PROBE=option-ok"
        val started = reply("start " +
            argv("cmd.exe", "/c", "echo %MAPLESU_PROBE% > env.txt & cd >> env.txt") +
            " cwd=" + text(directory.absolutePath) +
            " env=" + text(environment.joinToString("\n")))
        val token = token(started)
        try {
            val exit = await(reply("wait $token 15000"))
            assertEquals(0, exit)
            val body = File(directory, "env.txt").readText()
            assertTrue("the environment option was not applied: $body", body.contains("option-ok"))
            assertTrue("the working directory option was not applied: $body",
                body.contains(directory.absolutePath))
        } finally {
            reply("close $token")
            directory.deleteRecursively()
        }
    }

    @Test fun unknownOrImpossibleOptionsAreRefused() {
        assumeTrue("POSIX host has no cmd.exe", windows)
        val unknown = reply("start " + argv("cmd.exe", "/c", "exit 0") + " bogus=1")
        assertTrue(unknown, unknown.startsWith("ERR ") && unknown.contains("BAD_REQUEST"))
        val missing = File(System.getProperty("java.io.tmpdir"), "maplesu-absent-" + System.nanoTime())
        val badCwd = reply("start " + argv("cmd.exe", "/c", "exit 0") + " cwd=" + text(missing.absolutePath))
        assertTrue(badCwd, badCwd.startsWith("ERR ") && badCwd.contains("BAD_CWD"))
    }
}
