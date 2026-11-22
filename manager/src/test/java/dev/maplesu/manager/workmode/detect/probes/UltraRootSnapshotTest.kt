package dev.maplesu.manager.workmode.detect.probes

import dev.maplesu.manager.workmode.control.ControlPaths
import java.io.File
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Runs the real generated shell against files; only UID and fixed Android paths are mapped. */
class UltraRootSnapshotTest {
    @Test fun evidenceReadIsOneSdkRoundTripInOriginalOrder() = withFixture { fixture ->
        fixture.file("maplesu-workmode/control/modes.json", "{\n  \"schema\": 1\n}\n")
        fixture.file("maplesu-workmode/control/installed.json", "")
        fixture.file("maplesu-workmode/control/switch.json", "{}")
        fixture.file("maplesu/authorization/entry", "")
        fixture.directory("maplesu/installer")
        fixture.file("maplesu/published-directory/entry", "")
        fixture.file("ksu/entry", "")
        fixture.file("ksu/.kmi-writable", "")
        fixture.file("magisk/entry", "")
        val session = fixture.open()!!
        assertEquals("{\n  \"schema\": 1\n}", session.readControlFile("modes.json"))
        assertEquals("", session.readControlFile("installed.json"))
        assertEquals("{}", session.readControlFile("switch.json"))
        assertEquals(true, session.hasAnyEntry("/data/adb/maplesu/authorization"))
        assertEquals(false, session.hasAnyEntry("/data/adb/maplesu/installer"))
        assertEquals(true, session.hasAnyEntry("/data/adb/maplesu/published-directory"))
        assertEquals(true, session.hasAnyEntry("/data/adb/ksu"))
        assertEquals(false, session.isExecutable("/data/adb/ksud"))
        assertEquals(true, session.exists("/data/adb/ksu/.kmi-writable"))
        assertEquals(true, session.hasAnyEntry("/data/adb/magisk"))
        assertEquals(1, fixture.calls)
        assertEquals(listOf(
            "id -u", "cat ${ControlPaths.CONTROL}/modes.json",
            "cat ${ControlPaths.CONTROL}/installed.json", "cat ${ControlPaths.CONTROL}/switch.json",
            "test -d /data/adb/maplesu/authorization", "test -L /data/adb/maplesu/authorization",
            "ls -A /data/adb/maplesu/authorization", "test -d /data/adb/maplesu/installer",
            "test -L /data/adb/maplesu/installer", "ls -A /data/adb/maplesu/installer",
            "test -d /data/adb/maplesu/published-directory", "test -L /data/adb/maplesu/published-directory",
            "ls -A /data/adb/maplesu/published-directory", "test -d /data/adb/ksu",
            "test -L /data/adb/ksu", "ls -A /data/adb/ksu", "test -x /data/adb/ksud",
            "test -e /data/adb/ksu/.kmi-writable", "test -d /data/adb/magisk",
            "test -L /data/adb/magisk", "ls -A /data/adb/magisk",
        ), fixture.trace())
        session.close()
    }

    @Test fun missingSymlinkAndWhitespaceDirectoriesRetainShortCircuit() = withFixture { fixture ->
        fixture.directory("maplesu/installer")
        fixture.file("maplesu/installer/entry", "")
        fixture.symlink("maplesu/installer", "maplesu/authorization")
        fixture.file("magisk/\u2003", "")
        fixture.file("ksu/.allowlist/entry", "")
        val session = fixture.open()!!
        assertEquals(false, session.hasAnyEntry("/data/adb/maplesu/authorization"))
        assertEquals(false, session.hasAnyEntry("/data/adb/maplesu/published-directory"))
        assertEquals(false, session.hasAnyEntry("/data/adb/magisk"))
        assertEquals(true, session.hasAnyEntry("/data/adb/ksu/.allowlist"))
        assertFalse(fixture.trace().contains("ls -A /data/adb/maplesu/authorization"))
        assertFalse(fixture.trace().contains("test -L /data/adb/maplesu/published-directory"))
        assertEquals(1, fixture.calls)
    }

    @Test fun perItemFailureIsUnknownAndDoesNotHideOtherResults() = withFixture { fixture ->
        fixture.file("maplesu-workmode/control/modes.json", "{}")
        fixture.file("maplesu-workmode/control/installed.json", "{}")
        fixture.file("maplesu/authorization/entry", "")
        fixture.file("ksu/.allowlist/entry", "")
        fixture.failCat = "${ControlPaths.CONTROL}/modes.json"
        fixture.failLs = "/data/adb/maplesu/authorization"
        val session = fixture.open()!!
        assertNull(session.readControlFile("modes.json"))
        assertEquals("{}", session.readControlFile("installed.json"))
        assertNull(session.hasAnyEntry("/data/adb/maplesu/authorization"))
        assertEquals(false, session.hasAnyEntry("/data/adb/magisk"))
        assertEquals(true, session.hasAnyEntry("/data/adb/ksu/.allowlist"))
        assertEquals(1, fixture.calls)
    }

    @Test fun arbitraryCommandsAndClosedSnapshotAreUnknown() = withFixture { fixture ->
        fixture.file("maplesu-workmode/control/modes.json", "{}")
        val session = fixture.open()!!
        assertNull(session.exists("/unrequested/path"))
        assertEquals("{}", session.readControlFile("modes.json"))
        session.close()
        assertNull(session.readControlFile("modes.json"))
        assertEquals(1, fixture.calls)
    }

    @Test fun magiskListFailureStillReadsAllowlist() = withFixture { fixture ->
        fixture.file("magisk/entry", "")
        fixture.file("ksu/.allowlist/entry", "")
        fixture.failLs = "/data/adb/magisk"
        val session = fixture.open()!!
        assertNull(session.hasAnyEntry("/data/adb/magisk"))
        assertEquals(true, session.hasAnyEntry("/data/adb/ksu/.allowlist"))
        assertTrue(fixture.trace().contains("ls -A /data/adb/ksu/.allowlist"))
        assertEquals(1, fixture.calls)
    }

    @Test fun snapshotIsReusedOnlyInsideItsOwnOpenSession() = withFixture { fixture ->
        fixture.file("maplesu-workmode/control/modes.json", "first")
        val first = fixture.open()!!
        fixture.file("maplesu-workmode/control/modes.json", "second")
        assertEquals("first", first.readControlFile("modes.json"))
        assertEquals("first", first.readControlFile("modes.json"))
        val second = fixture.open()!!
        assertEquals("second", second.readControlFile("modes.json"))
        assertEquals(2, fixture.calls)
    }

    @Test fun realUidAndEncodingFailureRejectTheWholeSnapshot() = withFixture { fixture ->
        fixture.uid = "2000"
        assertNull(fixture.open())
        assertEquals(listOf("id -u"), fixture.trace())
        fixture.uid = "0"
        fixture.failEncoding = true
        assertNull(fixture.open())
    }

    private fun withFixture(block: (UltraSnapshotFixture) -> Unit) {
        UltraSnapshotFixture().use(block)
    }
}

internal class UltraSnapshotFixture : AutoCloseable {
    private val root = Files.createTempDirectory("maplesu snapshot ").toFile()
    private val traceFile = File(root, "trace.txt")
    private val rootPath = root.absolutePath.replace('\\', '/')
    var uid = "0"
    var uidExit = 0
    var selinux = "Enforcing"
    var selinuxExit = 0
    var failCat: String? = null
    var failLs: String? = null
    var failEncoding = false
    var running = true
    var calls = 0
    var lastScript = ""
    var transform: (RootCommandResult) -> RootCommandResult = { it }
    val tag = "MAPLESU_SNAPSHOT_TEST"

    fun file(path: String, contents: String) {
        File(root, path).also { requireNotNull(it.parentFile).mkdirs(); it.writeText(contents) }
    }
    fun directory(path: String) { File(root, path).mkdirs() }
    fun symlink(target: String, link: String) {
        requireNotNull(File(root, link).parentFile).mkdirs()
        execute("ln -s ${quote("$rootPath/$target")} ${quote("$rootPath/$link")}")
    }
    fun trace(): List<String> = if (traceFile.isFile) traceFile.readLines()
        .map { it.replace(rootPath, "/data/adb") } else emptyList()

    fun open(): ShellRootEvidenceSession? = openRaw()?.let(::ShellRootEvidenceSession)
    fun openRaw(): RootShellSession? = UltraRootShellSession.open(
        running = { running }, sdk = RootShellRunner { command ->
            calls++
            lastScript = command
            val script = """
                __fixture_id() { printf 'id -u\n' >> ${quote(traceFile.absolutePath.replace('\\', '/'))}; printf '%s\n' ${quote(uid)}; return $uidExit; }
                __fixture_getenforce() { printf '%s\n' ${quote(selinux)}; return $selinuxExit; }
                cat() { printf 'cat %s\n' "${'$'}1" >> ${quote(traceFile.absolutePath.replace('\\', '/'))}; if [ "${'$'}1" = ${quote(mapPath(failCat ?: ""))} ]; then return 13; fi; command cat "${'$'}@"; }
                ls() { printf 'ls %s %s\n' "${'$'}1" "${'$'}2" >> ${quote(traceFile.absolutePath.replace('\\', '/'))}; if [ "${'$'}2" = ${quote(mapPath(failLs ?: ""))} ]; then return 13; fi; command ls "${'$'}@"; }
                test() { printf 'test %s %s\n' "${'$'}1" "${'$'}2" >> ${quote(traceFile.absolutePath.replace('\\', '/'))}; builtin test "${'$'}@"; }
                ${if (failEncoding) "base64() { return 13; }" else ""}
                ${mapPath(command).replace("/system/bin/id -u", "__fixture_id").replace("/system/bin/getenforce", "__fixture_getenforce")}
            """.trimIndent()
            val result = execute(script)
            transform(RootCommandResult(true, result.lines()))
        }, marker = { tag },
    )

    private fun mapPath(value: String) = value.replace("/data/adb", rootPath)

    private fun execute(script: String): String {
        val shell = if (System.getProperty("os.name", "")?.startsWith("Windows") == true)
            listOf("C:/Program Files/Git/bin/bash.exe", "--noprofile", "--norc", "-s")
        else listOf("/bin/sh", "-s")
        val process = ProcessBuilder(shell).also {
            it.environment()["MSYS"] = "winsymlinks:nativestrict"
            it.environment()["LC_ALL"] = "C.UTF-8"
        }.start()
        process.outputStream.bufferedWriter(Charsets.UTF_8).use { it.write(script); it.write("\n") }
        val output = process.inputStream.bufferedReader(Charsets.UTF_8).readText()
        val errors = process.errorStream.bufferedReader(Charsets.UTF_8).readText()
        val exit = process.waitFor()
        check(errors.isBlank()) { "fixture shell stderr: $errors" }
        // A failed UID gate deliberately returns nonzero; the real SDK still has its own envelope.
        check(exit in 0..255)
        return output
    }

    override fun close() { root.deleteRecursively() }
    private fun quote(value: String) = ShellRootEvidenceSession.quote(value)
}
