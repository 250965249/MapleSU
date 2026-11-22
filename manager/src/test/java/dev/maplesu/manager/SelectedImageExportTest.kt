package dev.maplesu.manager

import dev.maplesu.manager.ksu.KsuBootPatchOptions
import dev.maplesu.manager.ksu.KsuCandidateCommitPort
import dev.maplesu.manager.ksu.KsuCommitResult
import dev.maplesu.manager.ksu.KsuImageFixtures
import dev.maplesu.manager.ksu.KsuInstallProducer
import dev.maplesu.manager.ksu.KsuProduceResult
import java.io.File
import java.nio.file.Files
import org.junit.Assert.*
import org.junit.Test

class SelectedImageExportTest {
    private fun source() = Files.createTempDirectory("selected-image-").resolve("source.img").toFile()

    @Test fun copiesBuildsAndPublishesInOrderWithoutChangingTheInput() {
        val source = source()
        val input = byteArrayOf(0x41, 0x4e, 0x44, 0x52, 0x4f, 0x49, 0x44)
        val events = mutableListOf<String>()
        val published = exportSelectedImage(source,
            copySource = { events += "copy"; it.writeBytes(input) },
            build = { events += "build"; assertArrayEquals(input, it.readBytes()); it.readBytes() + 0x7f.toByte() },
            publish = { events += "publish"; assertArrayEquals(input + 0x7f.toByte(), it); "/storage/emulated/0/Download/maplesu-patched (1).img" },
        )
        assertEquals(listOf("copy", "build", "publish"), events)
        assertEquals("/storage/emulated/0/Download/maplesu-patched (1).img", published)
        assertFalse(source.exists())
        requireNotNull(source.parentFile).delete()
    }

    @Test fun failedCopyDoesNotBuildOrPublishAndDeletesThePartialCopy() {
        val source = source()
        val expected = IllegalStateException("DOCUMENT_READ_FAILED")
        try {
            exportSelectedImage(source,
                copySource = { it.writeText("partial"); throw expected },
                build = { fail("build after a failed copy"); it },
                publish = { fail("publish after a failed copy"); "" },
            )
            fail("Expected copy failure")
        } catch (actual: IllegalStateException) { assertSame(expected, actual) }
        assertFalse(source.exists())
        requireNotNull(source.parentFile).delete()
    }

    @Test fun failedPatchDoesNotPublishAndDeletesTheSourceCopy() {
        val source = source()
        val expected = IllegalStateException("SITE_MISMATCH")
        try {
            exportSelectedImage(source,
                copySource = { it.writeText("input") },
                build = { throw expected },
                publish = { _: File -> fail("publish after a failed patch"); "" },
            )
            fail("Expected patch failure")
        } catch (actual: IllegalStateException) { assertSame(expected, actual) }
        assertFalse(source.exists())
        requireNotNull(source.parentFile).delete()
    }

    @Test fun failedPublishDoesNotReportAPathAndDeletesTheSourceCopy() {
        val source = source()
        val expected = IllegalStateException("CANDIDATE_EXPORT_WRITE_FAILED")
        try {
            exportSelectedImage(source,
                copySource = { it.writeText("input") },
                build = { it.readText() + "patched" },
                publish = { assertEquals("inputpatched", it); throw expected },
            )
            fail("Expected publication failure")
        } catch (actual: IllegalStateException) { assertSame(expected, actual) }
        assertFalse(source.exists())
        requireNotNull(source.parentFile).delete()
    }

    @Test fun normalSelectedImageRunsTheRealProducerWithZeroTransactionSubmissions() {
        val directory = Files.createTempDirectory("selected-normal-").toFile()
        try {
            val original = File(directory, "selected-init_boot.img").apply {
                writeBytes(KsuImageFixtures.stockImage())
            }
            val before = original.readBytes()
            val source = File(directory, "copied-source.img")
            val daemon = File(directory, "libksud_ksu.so").apply { writeText("ksud") }
            val runner = KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage(withMaplesuId = true))
            var transactionSubmissions = 0
            val producer = KsuInstallProducer(
                daemonPath = daemon.path,
                runner = runner,
                workRoot = File(directory, "candidate-work"),
                commit = KsuCandidateCommitPort { _, _ ->
                    transactionSubmissions++
                    KsuCommitResult.Accepted
                },
                kmiCatalog = { listOf("android15-6.6") },
            )
            val path = exportSelectedImage(source,
                copySource = { original.copyTo(it) },
                build = { selected ->
                    val result = producer.produceCandidate(selected,
                        KsuBootPatchOptions(kmi = "android15-6.6", partition = "init_boot"))
                    assertTrue(result.toString(), result is KsuProduceResult.Produced)
                    (result as KsuProduceResult.Produced).candidate
                },
                publish = { candidate ->
                    val output = File(directory, "Download/maplesu-patched.img")
                    output.parentFile?.mkdirs()
                    candidate.candidate.copyTo(output)
                    assertEquals(candidate.sha256, KsuInstallProducer.sha256(output))
                    output.absolutePath
                },
            )
            assertEquals(0, transactionSubmissions)
            assertTrue(File(path).isFile)
            assertFalse(source.exists())
            assertArrayEquals(before, original.readBytes())
            assertEquals(1, runner.commands.size)
            val tokens = KsuImageFixtures.splitCommandLine(runner.commands.single())
            assertFalse(tokens.any { it in setOf("-f", "--flash", "--restore", "--backup") })
        } finally { directory.deleteRecursively() }
    }

}
