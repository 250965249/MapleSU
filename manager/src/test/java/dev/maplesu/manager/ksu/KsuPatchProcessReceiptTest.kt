package dev.maplesu.manager.ksu

import java.io.File
import kotlin.system.exitProcess
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class KsuPatchProcessReceiptTest {
    @get:Rule val temp = TemporaryFolder()

    private fun fixtureCommand(vararg args: String) = listOf(
        File(System.getProperty("java.home"), "bin/java").absolutePath,
        "-cp", System.getProperty("java.class.path"), KsuPatchProcessFixture::class.java.name,
    ) + args

    private fun runner() = KsuFileCommandRunner()

    @Test fun preservesRealExitCodeAndSeparateLargeStreams() {
        val result = runner().run(fixtureCommand("output"), 15_000)
        assertEquals(37, result.code)
        assertEquals(2_000, result.out.size)
        assertEquals(2_000, result.err.size)
        assertEquals("out-0", result.out.first())
        assertEquals("out-1999", result.out.last())
        assertEquals("err-0", result.err.first())
        assertEquals("err-1999", result.err.last())
    }

    @Test fun aTimedOutProcessTerminatesWithADiagnostic() {
        val result = runner().run(fixtureCommand("sleep"), 1_000)
        assertEquals(124, result.code)
        assertTrue(result.errText.contains("timed out"))
        val pid = result.out.single().removePrefix("pid=").toLong()
        assertFalse(ProcessHandle.of(pid).map { it.isAlive }.orElse(false))
    }

    @Test fun timeoutStopsTheActualPatchWorker() {
        val candidate = File(temp.newFolder("candidate dir"), "output & 'quoted'.img")
        val start = System.nanoTime()
        val result = runner().run(fixtureCommand("write", candidate.absolutePath), 2_000)
        val elapsedMs = (System.nanoTime() - start) / 1_000_000
        assertEquals(124, result.code)
        val worker = ProcessHandle.of(result.out.single().removePrefix("pid=").toLong()).orElse(null)
        try {
            assertFalse("the patch worker survived its timeout", worker?.isAlive ?: false)
            assertTrue("timeout waited for normal worker completion: ${elapsedMs}ms", elapsedMs < 10_000)
            val size = candidate.length()
            assertTrue(size > 0)
            Thread.sleep(200)
            assertEquals("candidate changed after the runner returned", size, candidate.length())
        } finally {
            worker?.destroyForcibly()
            worker?.onExit()?.get()
        }
    }

    @Test fun argvRemainsCompatibleWithStringOnlyTransports() {
        var line = ""
        var timeout = 0L
        val transport = KsuRootCommandRunner { command, timeoutMs ->
            line = command
            timeout = timeoutMs
            KsuShellResult(0, emptyList(), emptyList())
        }
        val argv = listOf("/app dir/ksud", "boot-patch", "a 'quoted' input.img")
        assertEquals(0, transport.run(argv, 123).code)
        assertEquals(KsuInstallProducer.shellJoin(argv), line)
        assertEquals(123L, timeout)
    }

    @Test fun producerReportsTheActualInvocationAndProcessFailure() {
        val source = KsuImageFixtures.write(temp.newFolder("source dir"), "init_boot.img", KsuImageFixtures.stockImage())
        val daemon = KsuImageFixtures.write(temp.newFolder("lib dir"), "libksud_ksu.so", byteArrayOf(1))
        val receipts = mutableListOf<KsuPatchCommandReceipt>()
        val out = mutableListOf<String>()
        val err = mutableListOf<String>()
        var invocation: List<String>? = null
        val transport = object : KsuRootCommandRunner {
            override fun run(commandLine: String, timeoutMs: Long): KsuShellResult =
                error("the producer must pass argv to the file transport")

            override fun run(argv: List<String>, timeoutMs: Long): KsuShellResult {
                invocation = argv.toList()
                return runner().run(fixtureCommand("output"), timeoutMs)
            }
        }
        val producer = KsuInstallProducer(daemon.absolutePath, transport, temp.newFolder("work"),
            KsuCandidateCommitPort { _, _ -> error("file production must not commit") })
        val result = producer.produceCandidate(source, KsuBootPatchOptions(kmi = "android15-6.6"),
            out::add, err::add, onCommand = receipts::add)
        assertTrue(result is KsuProduceResult.Rejected)
        result as KsuProduceResult.Rejected
        assertEquals("PRODUCE_KSud_FAILED", result.code)
        assertEquals(37, result.exitCode)
        val receipt = receipts.single()
        assertEquals(invocation, receipt.argv)
        assertEquals(37, receipt.result.code)
        assertEquals(daemon.absolutePath, receipt.argv.first())
        assertEquals(source.absolutePath, receipt.argv[receipt.argv.indexOf("-b") + 1])
        assertEquals("android15-6.6", receipt.argv[receipt.argv.indexOf("--kmi") + 1])
        assertEquals(receipt.result.out, out.takeLast(2_000))
        assertEquals(receipt.result.err, err)
    }
}

object KsuPatchProcessFixture {
    @JvmStatic fun main(args: Array<String>) {
        if (args.first() == "sleep" || args.first() == "write") {
            println("pid=${ProcessHandle.current().pid()}")
            System.out.flush()
            if (args.first() == "write") {
                val candidate = File(args[1])
                repeat(600) {
                    candidate.appendText("written\n")
                    Thread.sleep(50)
                }
                return
            }
            Thread.sleep(30_000)
        }
        repeat(2_000) {
            println("out-$it")
            System.err.println("err-$it")
        }
        exitProcess(37)
    }
}
