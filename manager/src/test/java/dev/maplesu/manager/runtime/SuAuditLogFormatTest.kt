package dev.maplesu.manager.runtime

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * Host regression for the audit line (design §5.2 / §7.3 item 4).
 *
 * <p>The log's whole value is what it must **not** contain: no token, no full argv, no
 * signing material. The positive assertions are the field set the design fixes, so a
 * later edit cannot silently drop `rev` or `gate` and leave the reader guessing.
 */
class SuAuditLogFormatTest {
    @Rule
    @JvmField
    val folder = TemporaryFolder()

    private val token = "0123456789abcdef"

    private fun event(argv: List<String> = listOf("/system/bin/id", "-u")) = SuAuditEvent(
        backend = "hook",
        event = "decision",
        bootId = "0011223344556677",
        attemptId = "a1b2c3d4e5f60718",
        callerUid = 10_123,
        callerPackages = listOf("com.example.su"),
        decision = "allow",
        reason = "ALLOW",
        sessionId = "s7",
        argv0 = SuAuditLog.argv0(argv),
        argvSha256 = SuAuditLog.argvDigest(argv),
        gate = "ARMED",
        exitCode = 0,
        durationMs = 812,
        rev = 42,
        source = "manager",
        ts = 1_000,
    )

    @Test
    fun carriesTheDesignsFields() {
        val line = SuAuditLog.line(event())
        for (field in listOf(
            "\"ts\":\"1000\"", "\"bootId\":\"0011223344556677\"",
            "\"attemptId\":\"a1b2c3d4e5f60718\"", "\"backend\":\"hook\"",
            "\"event\":\"decision\"", "\"callerUid\":\"10123\"",
            "\"callerPackages\":[\"com.example.su\"]", "\"decision\":\"allow\"",
            "\"reason\":\"ALLOW\"", "\"sessionId\":\"s7\"", "\"argv0\":\"/system/bin/id\"",
            "\"gate\":\"ARMED\"", "\"exitCode\":\"0\"", "\"durationMs\":\"812\"",
            "\"rev\":\"42\"", "\"source\":\"manager\"",
        )) {
            assertTrue("missing $field in $line", line.contains(field))
        }
    }

    @Test
    fun neverCarriesATokenOrThePlainArgv() {
        val argv = listOf("/system/bin/sh", "-c", "echo " + token)
        val line = SuAuditLog.line(event(argv))
        assertFalse("token leaked: $line", line.contains(token))
        assertFalse("full argv leaked: $line", line.contains("echo "))
        assertFalse("argument leaked: $line", line.contains("-c"))
        // The fingerprint is a correlation handle, not the command: 16 hex digits.
        val digest = SuAuditLog.argvDigest(argv)
        assertEquals(16, digest.length)
        assertTrue(digest.matches(Regex("^[0-9a-f]{16}$")))
        assertTrue(line.contains("\"argvSha256\":\"$digest\""))
    }

    @Test
    fun digestIsStableAndArgumentSensitive() {
        val first = SuAuditLog.argvDigest(listOf("/system/bin/id", "-u"))
        assertEquals(first, SuAuditLog.argvDigest(listOf("/system/bin/id", "-u")))
        assertFalse(first == SuAuditLog.argvDigest(listOf("/system/bin/id", "-g")))
        // The design's exact formula: sha256(argv.joinToString("\0")), first 16 hex.
        val digest = java.security.MessageDigest.getInstance("SHA-256")
            .digest("/system/bin/id\u0000-u".toByteArray(Charsets.UTF_8))
        assertEquals(
            digest.take(8).joinToString("") { "%02x".format(it.toInt() and 255) },
            first,
        )
    }

    @Test
    fun escapingKeepsTheLineParseable() {
        val line = SuAuditLog.line(
            SuAuditEvent(backend = "hook", event = "stage", detail = "a\"b\\c\nd\te"),
        )
        assertTrue(line.contains("\"detail\":\"a\\\"b\\\\c\\nd\\te\""))
        assertEquals(1, line.lines().size)
    }

    @Test
    fun appendedLinesSurviveARotationBoundary() {
        val file = File(folder.newFolder("audit"), SuAuditLog.FILE)
        repeat(3) { SuAuditLog.write(file, event(), limitBytes = 1024 * 1024) }
        assertEquals(3, file.readLines().filter { it.isNotBlank() }.size)
        // A tiny limit rotates once: the writer must not leave a half line behind.
        repeat(40) { SuAuditLog.write(file, event(), limitBytes = 512) }
        val rotated = File(file.parentFile, SuAuditLog.ROTATED)
        assertTrue("rotation never happened", rotated.isFile || file.length() <= 2048)
        file.readLines().filter { it.isNotBlank() }.forEach { line ->
            assertTrue("truncated line: $line", line.trimStart().startsWith("{"))
            assertTrue("unterminated line: $line", line.trimEnd().endsWith("}"))
        }
    }
}
