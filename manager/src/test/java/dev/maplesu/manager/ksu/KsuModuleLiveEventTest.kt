package dev.maplesu.manager.ksu

import dev.maplesu.manager.modules.webui.ModuleWebUiSessions
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.concurrent.thread

/** The actual command consumer receives swap facts, independently of exit/reboot status. */
class KsuModuleLiveEventTest {
    @get:Rule val tmp = TemporaryFolder()
    private val daemon = "/data/adb/ksud"

    private fun archive(id: String, properties: String = "id=$id\n"): File = tmp.newFile("$id.zip").also { file ->
        ZipOutputStream(file.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("module.prop"))
            zip.write(properties.toByteArray(Charsets.UTF_8))
            zip.closeEntry()
        }
    }

    private fun backend(runner: KsuShellRunner) = KsuCommandBackend(
        daemonPathProvider = { daemon }, runner = runner,
        probe = object : KsuPathProbe {
            override fun exists(path: String) = true
            override fun canExecute(path: String) = true
        },
    )

    private fun event(command: List<String>, id: String): String {
        assertEquals(6, command.size)
        assertEquals("/system/bin/env", command[0])
        assertTrue(command[1].matches(Regex("KSUD_MODULE_LIVE_EVENT=[0-9a-f]{32}")))
        assertEquals(listOf(daemon, "module", "install"), command.subList(2, 5))
        assertTrue(File(command[5]).isFile)
        return "__MAPLESU_MODULE_LIVE_V1__${command[1].substringAfter('=')}:$id"
    }

    private fun streaming(block: (List<String>, (String) -> Unit, (String) -> Unit) -> KsuShellResult) =
        object : KsuShellRunner {
            override fun run(command: List<String>, timeoutMs: Long): KsuShellResult =
                error("Use one streaming install")
            override fun runStreaming(command: List<String>, timeoutMs: Long,
                                      onStdout: (String) -> Unit, onStderr: (String) -> Unit) =
                block(command, onStdout, onStderr)
        }

    @Test fun aHotSwapRetiresOnlyTheMatchingPageBeforeTheInstallerReturns() {
        val id = "live_event_target"
        val other = "live_event_other"
        var retired = 0
        var otherRetired = 0
        val revision = ModuleWebUiSessions.revision(id)
        val out = mutableListOf<String>()
        val err = mutableListOf<String>()
        ModuleWebUiSessions.subscribe(id, revision) { retired++ }!!.use {
            ModuleWebUiSessions.subscribe(other, ModuleWebUiSessions.revision(other)) { otherRetired++ }!!.use {
                val runner = streaming { command, stdout, stderr ->
                    stdout("installing")
                    val marker = event(command, id)
                    stderr(marker)
                    assertEquals("Retirement is synchronous with the swap fact", 1, retired)
                    assertEquals(0, otherRetired)
                    stderr("warning")
                    KsuShellResult(0, listOf("installing"), listOf(marker, "warning"))
                }
                val result = KsuModuleOps(backend(runner)).installResult(archive(id), out::add, err::add)
                assertEquals(0, result.code)
                assertEquals(listOf("installing"), out)
                assertEquals(listOf("warning"), err)
                assertEquals(err, result.err)
                assertEquals(revision + 1, ModuleWebUiSessions.revision(id))
            }
        }
    }

    @Test fun aSwapFactStillRetiresThePageWhenTheFinalCommandFails() {
        val id = "live_event_nonzero"
        var retired = 0
        ModuleWebUiSessions.subscribe(id, ModuleWebUiSessions.revision(id)) { retired++ }!!.use {
            val runner = streaming { command, _, stderr ->
                val marker = event(command, id)
                stderr(marker)
                stderr("FIRST_ERROR")
                KsuShellResult(7, emptyList(), listOf(marker, "FIRST_ERROR"))
            }
            val result = KsuModuleOps(backend(runner)).installResult(archive(id))
            assertEquals(7, result.code)
            assertEquals(listOf("FIRST_ERROR"), result.err)
            assertEquals(1, retired)
        }
    }

    @Test fun aRegularPendingInstallDoesNotRetirePagesFromSuccessTextOrExitCode() {
        val id = "live_event_pending"
        var retired = 0
        val receipt = KsuShellResult(0, listOf("- Module installed successfully!", "", "- Reboot to apply the module"), emptyList())
        ModuleWebUiSessions.subscribe(id, ModuleWebUiSessions.revision(id)) { retired++ }!!.use {
            val runner = streaming { command, stdout, _ ->
                event(command, id)
                receipt.out.forEach(stdout)
                receipt
            }
            val result = KsuModuleOps(backend(runner)).installResult(archive(id))
            assertSame(receipt, result)
            assertEquals(0, retired)
        }
    }

    @Test fun wrongNonceInvalidIdsAndStdoutMarkersRemainBusinessOutput() {
        val id = "live_event_rejected"
        val revision = ModuleWebUiSessions.revision(id)
        var retired = 0
        var otherRetired = 0
        val other = "${id}_other"
        val stdout = mutableListOf<String>()
        val stderr = mutableListOf<String>()
        ModuleWebUiSessions.subscribe(id, revision) { retired++ }!!.use {
          ModuleWebUiSessions.subscribe(other, ModuleWebUiSessions.revision(other)) { otherRetired++ }!!.use {
            val runner = streaming { command, out, err ->
                val valid = event(command, id)
                val prefix = valid.substringBeforeLast(':') + ":"
                val nonce = command[1].substringAfter('=')
                val wrongNonce = (if (nonce[0] == 'f') "0" else "f") + nonce.substring(1)
                val invalid = listOf(
                    "__MAPLESU_MODULE_LIVE_V1__$wrongNonce:$id",
                    prefix + "bad id", prefix + "../escape", prefix + "", prefix + "x",
                    "prefix " + valid, prefix + other,
                )
                out(valid)
                invalid.forEach(err)
                KsuShellResult(0, listOf(valid), invalid)
            }
            val result = KsuModuleOps(backend(runner)).installResult(archive(id), stdout::add, stderr::add)
            assertEquals(result.out, stdout)
            assertEquals(result.err, stderr)
            assertEquals(7, stderr.size)
            assertEquals(0, retired)
            assertEquals(0, otherRetired)
            assertEquals(revision, ModuleWebUiSessions.revision(id))
          }
        }
    }

    @Test fun streamedAndFinalReceiptEventsAreDeduplicatedAgainstAReplacementPage() {
        val id = "live_event_duplicate"
        val revision = ModuleWebUiSessions.revision(id)
        var originalRetired = 0
        var replacementRetired = 0
        var replacement: AutoCloseable? = null
        ModuleWebUiSessions.subscribe(id, revision) { originalRetired++ }!!.use {
            try {
                val runner = streaming { command, _, stderr ->
                    val marker = event(command, id)
                    stderr(marker)
                    replacement = ModuleWebUiSessions.subscribe(id, ModuleWebUiSessions.revision(id)) { replacementRetired++ }
                    assertNotNull(replacement)
                    stderr(marker)
                    KsuShellResult(0, emptyList(), listOf(marker, marker))
                }
                val result = KsuModuleOps(backend(runner)).installResult(archive(id))
                assertTrue(result.err.isEmpty())
                assertEquals(1, originalRetired)
                assertEquals(0, replacementRetired)
                assertEquals(revision + 1, ModuleWebUiSessions.revision(id))
            } finally { replacement?.close() }
        }
    }

    @Test fun aReceiptOnlyFactIsConsumedAndDoesNotAlterTheOriginalExitOrBusinessLines() {
        val id = "live_event_receipt"
        var retired = 0
        ModuleWebUiSessions.subscribe(id, ModuleWebUiSessions.revision(id)) { retired++ }!!.use {
            val runner = streaming { command, _, _ ->
                KsuShellResult(9, listOf("", "raw out"), listOf("before", event(command, id), "", "after"))
            }
            val result = KsuModuleOps(backend(runner)).installResult(archive(id))
            assertEquals(9, result.code)
            assertEquals(listOf("", "raw out"), result.out)
            assertEquals(listOf("before", "", "after"), result.err)
            assertEquals(1, retired)
        }
    }

    @Test fun aDisconnectPreservesPriorBusinessStreamsAndRetirementWithoutReplay() {
        val id = "live_event_disconnect"
        var calls = 0
        var retired = 0
        val out = mutableListOf<String>()
        val err = mutableListOf<String>()
        ModuleWebUiSessions.subscribe(id, ModuleWebUiSessions.revision(id)) { retired++ }!!.use {
            val runner = streaming { command, stdout, stderr ->
                calls++
                stdout("partial"); stdout("")
                stderr(event(command, id))
                stderr("FIRST_ERROR")
                throw IllegalStateException("fixture disconnected")
            }
            val result = KsuModuleOps(backend(runner)).installResult(archive(id), out::add, err::add)
            assertEquals(-1, result.code)
            assertEquals(listOf("partial", ""), result.out)
            assertEquals(out, result.out)
            assertEquals("FIRST_ERROR", result.err.first())
            assertTrue(result.err.last().startsWith("MODULE_INSTALL_EXECUTION_FAILED:"))
            assertEquals(err, result.err)
            assertEquals(1, calls)
            assertEquals(1, retired)
        }
    }

    @Test fun concurrentDuplicateFactsRetireTheCurrentPageOnlyOnce() {
        val id = "live_event_concurrent"
        val revision = ModuleWebUiSessions.revision(id)
        var retired = 0
        ModuleWebUiSessions.subscribe(id, revision) { retired++ }!!.use {
            val runner = streaming { command, _, stderr ->
                val marker = event(command, id)
                val start = CountDownLatch(1)
                val failure = AtomicReference<Throwable?>()
                val workers = (1..8).map {
                    thread {
                        try {
                            start.await()
                            repeat(16) { stderr(marker) }
                        } catch (error: Throwable) { failure.compareAndSet(null, error) }
                    }
                }
                start.countDown()
                workers.forEach { it.join(5_000) }
                assertFalse("Concurrent delivery completed", workers.any { it.isAlive })
                assertNull(failure.get())
                KsuShellResult(0, emptyList(), listOf(marker))
            }
            val result = KsuModuleOps(backend(runner)).installResult(archive(id))
            assertTrue(result.err.isEmpty())
            assertEquals(1, retired)
            assertEquals(revision + 1, ModuleWebUiSessions.revision(id))
        }
    }

    @Test fun propertiesSyntaxBindsTheSameFinalModuleIdAsTheInstaller() {
        val formats = listOf("id=earlier\nid=%ID%\n", "id: %ID%\n", "\\u0069d=%ID%\n")
        formats.forEachIndexed { index, format ->
            val id = "live_event_properties_$index"
            var retired = 0
            ModuleWebUiSessions.subscribe(id, ModuleWebUiSessions.revision(id)) { retired++ }!!.use {
                val runner = streaming { command, _, stderr ->
                    val marker = event(command, id)
                    stderr(marker)
                    KsuShellResult(0, emptyList(), listOf(marker))
                }
                val result = KsuModuleOps(backend(runner)).installResult(archive(id, format.replace("%ID%", id)))
                assertEquals("Properties syntax: $format", 1, retired)
                assertTrue(result.err.isEmpty())
            }
        }
    }
}
