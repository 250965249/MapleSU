package dev.maplesu.manager.ksu

import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import java.util.concurrent.TimeoutException
import java.util.concurrent.CancellationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.Before
import org.junit.rules.TemporaryFolder

class KsuModuleInstallTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val daemon = "/data/adb/ksud"

    private fun archive(properties: String = "id=fixture\n"): File = tmp.newFile("module.zip").also { file ->
        ZipOutputStream(file.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("module.prop"))
            zip.write(properties.toByteArray())
            zip.closeEntry()
        }
    }

    @Before
    fun clearLog() {
        KsuLog.clear()
    }

    private fun backend(
        runner: KsuShellRunner,
        exists: Boolean = true,
        global: KsuShellRunner? = null,
    ) = KsuCommandBackend(
        daemonPathProvider = { daemon },
        runner = runner,
        globalMountRunner = global,
        probe = object : KsuPathProbe {
            override fun exists(path: String): Boolean = exists
            override fun canExecute(path: String): Boolean = exists
        },
    )

    @Test
    fun archivePathWithSpacesRemainsOneArgument() {
        val archive = tmp.newFile("my module.zip")
        val calls = mutableListOf<List<String>>()
        val ops = KsuModuleOps(backend(KsuShellRunner { command, _ ->
            calls += command
            KsuShellResult(0, emptyList(), emptyList())
        }))

        assertEquals(0, ops.installResult(archive).code)
        assertInstallInvocation(calls.single(), archive)
    }

    @Test
    fun archivePathWithShellCharactersRemainsOneArgument() {
        val archive = tmp.newFile("module 'quoted'; dollar\$.zip")
        val calls = mutableListOf<List<String>>()
        val ops = KsuModuleOps(backend(KsuShellRunner { command, _ ->
            calls += command
            KsuShellResult(0, emptyList(), emptyList())
        }))

        ops.installResult(archive)
        assertInstallInvocation(calls.single(), archive)
    }

    @Test
    fun failureReceiptPreservesExitCodeAndAllOutputLines() {
        val receipt = KsuShellResult(7, listOf("installing", "", "last"), listOf("failure", ""))
        val ops = KsuModuleOps(backend(KsuShellRunner { _, _ -> receipt }))

        assertSame(receipt, ops.installResult(tmp.newFile("module.zip")))
    }

    @Test
    fun successfulReceiptPreservesOutputAndWarnings() {
        val receipt = KsuShellResult(0, listOf("", "installed", ""), listOf("warning", ""))
        val ops = KsuModuleOps(backend(KsuShellRunner { _, _ -> receipt }))

        assertSame(receipt, ops.installResult(tmp.newFile("module.zip")))
    }

    @Test
    fun installationStreamsOutputBeforeCompletionWithoutReplayingIt() {
        val events = mutableListOf<String>()
        val receipt = KsuShellResult(7, listOf("installing", ""), listOf("warning"))
        val runner = object : KsuShellRunner {
            override fun run(command: List<String>, timeoutMs: Long): KsuShellResult =
                error("installation must use streaming")

            override fun runStreaming(
                command: List<String>, timeoutMs: Long,
                onStdout: (String) -> Unit, onStderr: (String) -> Unit,
            ): KsuShellResult {
                onStdout("installing")
                onStdout("")
                onStderr("warning")
                events += "completed"
                return receipt
            }
        }
        val result = KsuModuleOps(backend(runner)).installResult(tmp.newFile("streaming.zip"),
            { events += "out:$it" }, { events += "err:$it" })

        assertSame(receipt, result)
        assertEquals(listOf("out:installing", "out:", "err:warning", "completed"), events)
    }

    @Test
    fun booleanCompatibilityExecutesOnceForEachCall() {
        var calls = 0
        var exitCode = 0
        val ops = KsuModuleOps(backend(KsuShellRunner { _, _ ->
            calls++
            KsuShellResult(exitCode, emptyList(), emptyList())
        }))
        val archive = tmp.newFile("module.zip")

        assertTrue(ops.install(archive))
        assertEquals(1, calls)
        exitCode = 7
        assertFalse(ops.install(archive))
        assertEquals(2, calls)
    }

    @Test
    fun missingArchiveFailsBeforeCommandStarts() {
        var calls = 0
        val ops = KsuModuleOps(backend(KsuShellRunner { _, _ ->
            calls++
            KsuShellResult(0, emptyList(), emptyList())
        }))
        val archive = File(tmp.root, "missing.zip")

        val result = ops.installResult(archive)
        assertEquals(-1, result.code)
        assertEquals(listOf("MODULE_INSTALL_ARCHIVE_NOT_FILE:${archive.absolutePath}"), result.err)
        assertEquals(0, calls)
    }

    @Test
    fun directoryFailsBeforeCommandStarts() {
        var calls = 0
        val ops = KsuModuleOps(backend(KsuShellRunner { _, _ ->
            calls++
            KsuShellResult(0, emptyList(), emptyList())
        }))
        val archive = tmp.newFolder("module.zip")

        assertEquals(-1, ops.installResult(archive).code)
        assertEquals(0, calls)
    }

    @Test
    fun missingDaemonExplainsPrelaunchFailure() {
        var calls = 0
        val ops = KsuModuleOps(backend(KsuShellRunner { _, _ ->
            calls++
            KsuShellResult(0, emptyList(), emptyList())
        }, exists = false))

        val result = ops.installResult(tmp.newFile("module.zip"))
        assertEquals(-1, result.code)
        assertEquals(listOf("KSUD_UNAVAILABLE:$daemon"), result.err)
        assertEquals(0, calls)
    }

    @Test
    fun commandStartExceptionIsAnExplicitPrelaunchFailure() {
        val ops = KsuModuleOps(backend(KsuShellRunner { _, _ ->
            throw IllegalStateException("shell start failed")
        }))

        val result = ops.installResult(tmp.newFile("module.zip"))
        assertEquals(-1, result.code)
        assertEquals(listOf("MODULE_INSTALL_START_FAILED:IllegalStateException:shell start failed"), result.err)
    }

    @Test
    fun executionTimeoutAndInterruptionDoNotClaimTheInstallerNeverStarted() {
        for ((failure, expected) in listOf(
            TimeoutException("fixture deadline") to "MODULE_INSTALL_TIMEOUT",
            InterruptedException("fixture cancelled") to "MODULE_INSTALL_INTERRUPTED",
            CancellationException("fixture cancelled") to "MODULE_INSTALL_CANCELLED",
            IllegalStateException("fixture disconnected") to "MODULE_INSTALL_EXECUTION_FAILED",
        )) {
            var calls = 0
            val out = mutableListOf<String>()
            val err = mutableListOf<String>()
            val runner = object : KsuShellRunner {
                override fun run(command: List<String>, timeoutMs: Long): KsuShellResult = error("use streaming")
                override fun runStreaming(
                    command: List<String>, timeoutMs: Long,
                    onStdout: (String) -> Unit, onStderr: (String) -> Unit,
                ): KsuShellResult {
                    calls++
                    onStdout("partial")
                    onStdout("")
                    onStderr("warning")
                    throw IllegalStateException("outer", failure)
                }
            }
            try {
                val result = KsuModuleOps(backend(runner)).installResult(tmp.newFile(expected + ".zip"), out::add, err::add)
                assertEquals(-1, result.code)
                assertEquals(listOf("partial", ""), result.out)
                assertEquals(result.out, out)
                assertEquals(listOf("warning"), result.err.dropLast(1))
                assertEquals(result.err, err)
                assertTrue(result.err.last().startsWith("$expected:"))
                assertEquals(1, result.err.count { it.startsWith("$expected:") })
                assertEquals(1, calls)
                assertEquals(failure is InterruptedException, Thread.currentThread().isInterrupted)
            } finally {
                Thread.interrupted()
            }
        }
    }

    @Test
    fun installationRetainsTimeoutAndCurrentRunner() {
        var timeout: Long? = null
        var globalCalls = 0
        val ops = KsuModuleOps(
            backend(
                runner = KsuShellRunner { _, timeoutMs ->
                    timeout = timeoutMs
                    KsuShellResult(0, emptyList(), emptyList())
                },
                global = KsuShellRunner { _, _ ->
                    globalCalls++
                    KsuShellResult(99, emptyList(), emptyList())
                },
            ),
            moduleInstallTimeoutMs = 123_456L,
        )

        assertEquals(0, ops.installResult(tmp.newFile("module.zip")).code)
        assertEquals(123_456L, timeout)
        assertEquals(0, globalCalls)
    }

    @Test
    fun normalInstallNeedsRebootWhenLiveUpdateMarkerExists() {
        val calls = mutableListOf<List<String>>()
        val ops = KsuModuleOps(backend(KsuShellRunner { command, _ ->
            calls += command
            KsuShellResult(1, emptyList(), emptyList())
        }))

        assertTrue(ops.needsReboot(archive()))
        assertEquals(
            listOf(listOf("/system/bin/sh", "-c",
                "[ -d '/data/adb/modules/fixture' ] && [ ! -e '/data/adb/modules/fixture/update' ]")),
            calls,
        )
    }

    @Test
    fun hotInstallDoesNotNeedRebootWhenLiveModuleHasNoUpdateMarker() {
        val ops = KsuModuleOps(backend(KsuShellRunner { _, _ ->
            KsuShellResult(0, emptyList(), emptyList())
        }))

        assertFalse(ops.needsReboot(archive()))
    }

    @Test
    fun unreadableInstallStateConservativelyNeedsReboot() {
        val ops = KsuModuleOps(backend(KsuShellRunner { _, _ ->
            throw IllegalStateException("root channel unavailable")
        }))

        assertTrue(ops.needsReboot(archive()))
    }

    @Test
    fun malformedModuleIdNeedsRebootWithoutStartingCommand() {
        var calls = 0
        val ops = KsuModuleOps(backend(KsuShellRunner { _, _ ->
            calls++
            KsuShellResult(0, emptyList(), emptyList())
        }))

        assertTrue(ops.needsReboot(archive("id=bad id;touch /tmp/fixture\n")))
        assertEquals(0, calls)
    }

    @Test
    fun commandLogPreservesExecutedArgvTimeoutAndActualCode() {
        val archive = tmp.newFile("module 'quoted' with spaces.zip")
        val calls = mutableListOf<List<String>>()
        val ops = KsuModuleOps(
            backend(KsuShellRunner { command, _ ->
                calls += command
                KsuShellResult(7, listOf("installing"), listOf("script failed"))
            }),
            moduleInstallTimeoutMs = 12_345L,
        )

        assertEquals(7, ops.installResult(archive).code)

        val logs = KsuLog.snapshot()
        val commandLog = logs.single { it.startsWith("ksu.module-install-command: ") }
        val argv = Json.parseToJsonElement(
            commandLog.substringAfter("argv=").substringBefore(" timeoutMs="),
        ) as JsonArray
        assertInstallInvocation(calls.single(), archive)
        assertEquals(calls.single().drop(2), argv.map { (it as JsonPrimitive).content })
        assertEquals("12345", commandLog.substringAfter(" timeoutMs="))
        assertEquals("ksu.module-install-result: code=7", logs.single { it.startsWith("ksu.module-install-result: ") })
        assertEquals(1, calls.size)
    }

    private fun assertInstallInvocation(command: List<String>, archive: File) {
        assertEquals("/system/bin/env", command[0])
        assertTrue(Regex("KSUD_MODULE_LIVE_EVENT=[0-9a-f]{32}").matches(command[1]))
        assertEquals(listOf(daemon, "module", "install", archive.absolutePath), command.drop(2))
    }
}
