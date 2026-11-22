package dev.maplesu.manager.ultrakernel

import dev.maplesu.image.UltraInitBootProducer
import java.io.File
import java.io.IOException
import java.io.InterruptedIOException
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Uses the same container byte fixtures; no module/shim executes and no runtime support is asserted. */
class UltraInitBootReceiptTest {
    @get:Rule val temporary = TemporaryFolder()
    private val credential = UltraKernelCredential.of("A".repeat(48))

    @Test fun completeReceiptIsPublishedOnlyAfterCandidateReadback() {
        val (source, artifact) = fixture()
        val before = source.readBytes()
        val targetBefore = artifact.targetBoot.readBytes()
        val work = temporary.newFolder("complete")
        val built = UltraKernelBuilder(work).generateInitBoot(source, artifact, credential)
        val receipt = File(work, built.image.nameWithoutExtension + ".json")
        assertTrue(receipt.isFile)
        assertTrue(receipt.readText().contains("\"runtimeVerified\":false"))
        assertTrue(receipt.readText().contains(built.bootSha256))
        assertTrue(work.listFiles().orEmpty().none { it.name.endsWith(".pending") })
        assertArrayEquals(before, source.readBytes())
        assertArrayEquals(targetBefore, artifact.targetBoot.readBytes())
    }

    @Test fun partialWriteAndCloseFailureRemoveCandidateAndPartialReceipt() {
        for (reason in listOf("partial-write", "close-failure")) {
            val (source, artifact) = fixture()
            val before = source.readBytes()
            val work = temporary.newFolder(reason)
            val primary = IOException(reason)
            val builder = UltraKernelBuilder(work) { file, bytes ->
                file.outputStream().use { stream ->
                    stream.write(bytes, 0, if (reason == "partial-write") 9 else bytes.size)
                }
                throw primary
            }
            val failure = runCatching { builder.generateInitBoot(source, artifact, credential) }.exceptionOrNull()
            assertSame(primary, failure)
            assertTrue(work.listFiles().orEmpty().isEmpty())
            assertArrayEquals(before, source.readBytes())
        }
    }

    @Test fun cleanupFailureIsSuppressedOnTheOriginalReceiptError() {
        val (source, artifact) = fixture()
        val work = temporary.newFolder("cleanup")
        val primary = IOException("receipt-close")
        val builder = UltraKernelBuilder(work) { file, bytes ->
            file.writeBytes(bytes.copyOf(9))
            val output = work.listFiles()!!.single { it.extension == "img" }
            check(output.delete() && output.mkdir())
            File(output, "busy").writeText("force nonempty-directory cleanup failure")
            throw primary
        }
        val failure = runCatching { builder.generateInitBoot(source, artifact, credential) }.exceptionOrNull()
        assertSame(primary, failure)
        assertTrue(primary.suppressed.isNotEmpty())
        assertTrue(work.listFiles().orEmpty().none { it.extension == "json" || it.name.endsWith(".pending") })
    }

    @Test fun cancellationAfterReceiptWriteDoesNotReturnAnInstallableCandidate() {
        val (source, artifact) = fixture()
        val sourceBefore = source.readBytes()
        val targetBefore = artifact.targetBoot.readBytes()
        val work = temporary.newFolder("cancel-receipt")
        val builder = UltraKernelBuilder(work) { file, bytes ->
            file.outputStream().use { stream -> stream.write(bytes); stream.fd.sync() }
            Thread.currentThread().interrupt()
        }
        val failure = try {
            runCatching { builder.generateInitBoot(source, artifact, credential) }.exceptionOrNull().also {
                assertTrue(Thread.currentThread().isInterrupted)
            }
        } finally { Thread.interrupted() }
        assertTrue(failure is InterruptedIOException)
        assertEquals("ULTRA_KERNEL_INIT_BOOT_CANCELLED", failure?.message)
        assertTrue(work.listFiles().orEmpty().isEmpty())
        assertArrayEquals(sourceBefore, source.readBytes())
        assertArrayEquals(targetBefore, artifact.targetBoot.readBytes())
    }

    private fun fixture(): Pair<File, UltraInitBootProducer.Artifact> {
        // Reuse the container owner's exact helpers instead of maintaining a second synthetic parser.
        val fixture = Class.forName("dev.maplesu.image.UltraInitBootProducerTest")
        fun bytes(name: String, vararg args: Any): ByteArray {
            val types = args.map { if (it is Boolean) java.lang.Boolean.TYPE else it.javaClass }.toTypedArray()
            val method = fixture.getDeclaredMethod(name, *types).apply { isAccessible = true }
            return method.invoke(null, *args) as ByteArray
        }
        val target = temporary.newFile().also { it.writeBytes(bytes("image", bytes("kernel"), ByteArray(0))) }
        val source = temporary.newFile().also { it.writeBytes(bytes("image", ByteArray(0), bytes("stock", false, false))) }
        val secret = credential.copySecret()
        val credentialHash = try { UltraKernelSpec.sha256(secret) } finally { secret.fill(0) }
        val constructor = UltraInitBootProducer.Artifact::class.java.getDeclaredConstructor(
            File::class.java, String::class.java, String::class.java, String::class.java,
            String::class.java, ByteArray::class.java, ByteArray::class.java).apply { isAccessible = true }
        val artifact = constructor.newInstance(target, UltraKernelSpec.sha256(target), "6.6.1-fixture",
            UltraKernelSpec.sha256(bytes("kernel")), credentialHash, bytes("handoff"), "opaque module fixture".toByteArray())
        return source to artifact
    }
}
