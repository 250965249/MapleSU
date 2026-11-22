package dev.maplesu.manager.runtime

import java.io.File
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

class HookSuCommandTest {
    private fun request(directory: String, environment: List<String>) = NativeSuRequest(
        terminals = 0, targetUid = 0, globalMount = false, window = IntArray(4),
        executable = "/system/bin/sh", directory = directory,
        arguments = listOf("/system/bin/sh"), environment = environment,
    )

    @Test fun callerEnvironmentAndDirectoryAreQuotedRatherThanEvaluatedByTheManager() {
        val request = request("/data/user/0/app name/it's", listOf("X=a'\$HOME", "PATH=/system/bin"))
        val script = HookSuCommand.script(request, listOf("/system/bin/sh", "-c", "printf '%s' \"\$X\""))
        assertTrue(script.startsWith("cd "))
        assertTrue(script.contains("exec /system/bin/env -i -- "))
        assertTrue(script.contains("'X=a'\\''\$HOME'"))
        assertFalse(script.contains("suToken"))
    }

    @Test fun onlyTheNativeChildRunsTheFrameworkDomainWrapper() {
        val argv = HookSuCommand.argv(request("/", emptyList()), listOf("/system/bin/id", "-u"))
        assertEquals(listOf("/system/bin/sh", "-c"), argv.take(2))
        assertTrue(argv[2].contains("u:r:kernel:s0"))
        assertTrue(argv[2].contains("runcon u:r:shell:s0"))
        assertTrue(argv[2].contains("/system/bin/id"))
    }

    @Test fun realShellReplayPreservesCwdEnvironmentInputAndCommandExit() {
        val bash = File("C:/Program Files/Git/bin/bash.exe")
        assumeTrue(bash.isFile)
        val directory = Files.createTempDirectory("hook-su-cwd-").toFile()
        try {
            val marker = File(directory, "must-not-exist")
            val value = "quote' \$(touch must-not-exist) \$HOME"
            val request = request(directory.path.replace('\\', '/'), listOf("TEST_VALUE=$value", "PATH=/usr/bin"))
            val command = listOf("/usr/bin/bash", "-c",
                "printf '%s\\n' \"\$TEST_VALUE\"; pwd; read line; printf '%s\\n' \"\$line\"; exit 23")
            val script = HookSuCommand.script(request, command).replace("/system/bin/env", "/usr/bin/env")
            // A script file avoids Windows' command-line quote rewriting; Android execv
            // passes the original bytes directly and has no such host-shell boundary.
            val file = File(directory, "root-command.sh").apply { writeText(script + "\n") }
            val process = ProcessBuilder(bash.path, file.path.replace('\\', '/')).redirectErrorStream(true).start()
            process.outputStream.use { it.write("stream-input\n".toByteArray()) }
            assertTrue(process.waitFor(5, TimeUnit.SECONDS))
            val output = process.inputStream.bufferedReader().readLines()
            assertEquals(output.toString(), 23, process.exitValue())
            assertEquals("script=$script output=$output", value, output[0])
            assertTrue(output[1].endsWith("/" + directory.name))
            assertEquals("stream-input", output[2])
            assertFalse(marker.exists())
        } finally { directory.deleteRecursively() }
    }
}
