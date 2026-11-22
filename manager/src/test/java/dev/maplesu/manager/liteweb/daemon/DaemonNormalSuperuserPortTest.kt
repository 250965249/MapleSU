package dev.maplesu.manager.liteweb.daemon

import dev.maplesu.manager.liteweb.*
import org.junit.Assert.*
import org.junit.Test

class DaemonNormalSuperuserPortTest {
    private val commands = mutableListOf<String>()
    private val granted = mutableSetOf(10123)
    private var malformed = false
    private var logging = true
    private val normal = DaemonNormalSuperuserPort { command ->
        commands += command
        if (command.startsWith("/system/bin/pm")) return@DaemonNormalSuperuserPort DaemonShellResult(0,
            "package:com.example.app uid:10123\npackage:com.example.app uid:110123\npackage:com.example.shared uid:10123\n")
        val operation = command.substringAfter("normal-superuser ")
        val body = when {
            operation == "snapshot" -> """{"ok":true,"uids":[${granted.joinToString(",")}],"loggingEnabled":$logging}"""
            operation.startsWith("set '") -> {
                val uid = operation.split(' ')[2].toInt()
                val allow = operation.endsWith(" true")
                val changed = if (allow) granted.add(uid) else granted.remove(uid)
                """{"ok":true,"allowed":$allow,"changed":$changed}"""
            }
            operation == "log" -> """{"ok":true,"lines":["su granted"]}"""
            operation == "clear-log" -> """{"ok":true,"cleared":true}"""
            operation.startsWith("set-logging ") -> {
                logging = operation.endsWith(" true")
                """{"ok":true,"enabled":$logging}"""
            }
            else -> error(command)
        }
        DaemonShellResult(0, if (malformed) "Success" else "MAPLESU_NORMAL_SU_V1 $body")
    }
    private val backend = object : LiteWebBackend by FakeBackend() {
        override fun superuserPort() = normal
    }
    private val token = "a".repeat(64)
    private val core = LiteWebDaemonCore(LiteWebDaemonConfig(18431, token, workMode = "KSU"),
        handler = LiteWebRequestHandler({ token }, backend))
    private fun get() = core.handle("GET", "/x7k9f/$token/api/superuser", mapOf("Host" to "localhost:18431"), "")
    private fun post(uid: String = "110123", name: String = "com.example.app", allow: Boolean = true) =
        core.handle("POST", "/x7k9f/$token/api/superuser", mapOf("Host" to "localhost:18431", "Content-Type" to "application/json"),
            """{"packageName":"$name","uid":$uid,"allow":$allow,"confirm":true}""")

    @Test fun normalHttpCatalogUsesKernelUidsAndKeepsUsersSeparate() {
        val response = get()
        assertEquals(response.body, 200, response.status)
        assertTrue(response.body.contains("\"backend\":\"ksu\""))
        assertTrue(response.body.contains("\"scope\":\"uid\""))
        val snapshot = (normal.snapshot() as LiteWebSuResult.Ok).value.entriesJson()
        assertTrue(snapshot.contains("\"uid\":110123,\"userId\":1,\"installed\":true,\"allowed\":false"))
        assertTrue(snapshot.contains("\"uid\":10123,\"userId\":0,\"installed\":true,\"allowed\":true"))
    }

    @Test fun grantAndRevokeUseSelectedUidAndReadBackWithoutChangingAnotherUser() {
        assertEquals(200, post().status)
        assertEquals(setOf(10123, 110123), granted)
        assertEquals(200, post(allow = false).status)
        assertEquals(setOf(10123), granted)
        assertTrue(commands.any { it.endsWith("normal-superuser set 'com.example.app' 110123 false") })
    }

    @Test fun invalidOrMismatchedUidNeverReachesKernelMutation() {
        assertEquals(400, post(uid = "-1").status)
        assertEquals(409, post(uid = "99999").status)
        assertEquals(403, post(name = "dev.maplesu.manager", allow = false).status)
        assertTrue(normal.setAllowed("com.example.app", true) is LiteWebSuResult.Failed)
        assertFalse(commands.any { it.contains("normal-superuser set ") })
    }

    @Test fun missingNativeReceiptIsUnknownInsteadOfAnEmptyAuthorizationList() {
        malformed = true
        assertEquals(503, get().status)
        assertFalse(get().body.contains("\"apps\":[]"))
    }

    @Test fun normalLogsAndLoggingUseKsuRatherThanUltra() {
        assertEquals("ksu", (normal.log() as LiteWebSuResult.Ok).value.source)
        assertTrue(normal.setLogging(false) is LiteWebSuResult.Ok)
        assertFalse(logging)
        assertTrue(normal.clearLog() is LiteWebSuResult.Ok)
    }
}
