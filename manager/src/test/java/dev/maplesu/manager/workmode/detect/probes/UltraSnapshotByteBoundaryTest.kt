package dev.maplesu.manager.workmode.detect.probes

import java.io.File
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Execute the real generated shell with byte-exact control files, including damaged JSON. */
class UltraSnapshotByteBoundaryTest {
    @Test fun embeddedNulMustNotRepairMalformedControlJson() {
        assertNull(readControl("{\"schema\":\u00001}".toByteArray()))
    }

    @Test fun invalidUtf8IsUnknownNotReplacementText() {
        assertNull(readControl(byteArrayOf(123, 34, 120, 34, 58, 34, 0xc3.toByte(), 34, 125)))
    }

    @Test fun longMultilineBase64RetainsExactText() {
        val text = "{\"text\":\"" + "雪MapleSU".repeat(8192) + "\"}\n\n"
        assertEquals(text.dropLast(1), readControl(text.toByteArray()))
    }

    private fun readControl(bytes: ByteArray): String? {
        val root = Files.createTempDirectory("maplesu-byte-boundary").toFile()
        try {
            File(root, "maplesu-workmode/control/modes.json").also {
                requireNotNull(it.parentFile).mkdirs(); it.writeBytes(bytes)
            }
            val path = root.absolutePath.replace('\\', '/')
            var calls = 0
            val opened = UltraRootShellSession.open({ true }, RootShellRunner { command ->
                calls++
                val scriptFile = File(root, "fixture.sh")
                val script = "__fixture_id() { printf '0\\n'; }\n" +
                    command.replace("/system/bin/id -u", "__fixture_id").replace("/data/adb", path)
                scriptFile.writeText(script + "\n")
                val shell = if (System.getProperty("os.name", "")?.startsWith("Windows") == true)
                    listOf("C:/Program Files/Git/bin/bash.exe", "--noprofile", "--norc")
                else listOf("/bin/sh")
                val process = ProcessBuilder(shell + scriptFile.absolutePath.replace('\\', '/')).start()
                val stdout = process.inputStream.bufferedReader(Charsets.UTF_8).readText()
                val stderr = process.errorStream.bufferedReader(Charsets.UTF_8).readText()
                process.waitFor()
                if (stderr.isNotEmpty()) System.err.println("byte probe shell stderr: $stderr")
                RootCommandResult(true, stdout.lines())
            }, { "MAPLESU_BYTE_BOUNDARY" })
            assertEquals(1, calls)
            return opened?.let { session ->
                ShellRootEvidenceSession(session).use { it.readControlFile("modes.json") }
            }
        } finally { root.deleteRecursively() }
    }
}
