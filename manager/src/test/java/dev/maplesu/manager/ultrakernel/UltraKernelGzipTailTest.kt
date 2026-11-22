package dev.maplesu.manager.ultrakernel

import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.BootImageRoundTrip
import dev.maplesu.image.KernelCompression
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Real builder regression: decoded kernel equality alone misses an appended DTB. */
class UltraKernelGzipTailTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun generatedGzipKernelKeepsOriginalComponentTail() {
        generatedKernel("GZIP", true)
    }

    @Test fun generatedLz4FrameKernelKeepsOriginalComponentTail() {
        generatedKernel("LZ4_FRAME", true)
    }

    @Test fun generatedXzKernelKeepsOriginalComponentTail() {
        generatedKernel("XZ", true)
    }

    @Test fun generatedZstdKernelKeepsOriginalComponentTail() {
        generatedKernel("ZSTD", true)
    }

    @Test fun externalXzFiltersAndBlocksKeepGenerationAndRecoveryBehavior() {
        for (name in listOf("arm64-0.xz", "arm64-4096.xz", "arm64-4294967292.xz",
            "arm64-blocks.xz", "delta.xz", "arm64-delta.xz", "four-filters.xz", "arm64-crc64.xz",
            "arm64-sha256.xz", "plain-blocks.xz")) {
            generatedKernel("XZ", true, name)
        }
    }

    @Test fun concatenatedXzKeepsGenerationAndRecoveryBehavior() {
        generatedKernel("XZ", true, "concat.xz")
    }

    @Test fun concatenatedLz4KeepsGenerationAndRecoveryBehavior() {
        generatedKernel("LZ4_FRAME", true, "concat.lz4")
    }

    @Test fun compressedZstdKeepsGenerationAndRecoveryBehavior() {
        for (name in listOf("kernel-1.zst", "kernel-3.zst", "kernel-19.zst",
            "kernel-unknown.zst", "kernel-window27.zst", "kernel-concat.zst")) {
            generatedKernel("ZSTD", true, name, "zstd-compressed", "kernel.raw")
        }
    }

    @Test fun untailedGzipRawAndLz4KeepGenerationAndRecoveryBehavior() {
        for (format in listOf("GZIP", "RAW_ARM64", "LZ4_LEGACY", "LZ4_FRAME", "XZ", "ZSTD")) generatedKernel(format, false)
    }

    private fun fixture(name: String, directory: String = "kernel-streams"): ByteArray = requireNotNull(javaClass.getResourceAsStream("/$directory/$name")) {
        "MISSING_FIXTURE:$name"
    }.use { it.readBytes() }

    private fun generatedKernel(format: String, withTail: Boolean, external: String? = null,
        fixtureDirectory: String = "kernel-streams", rawFixture: String = "arm64.raw") {
        val tail = if (!withTail) byteArrayOf() else ByteArray(64).apply {
            ByteBuffer.wrap(this).order(ByteOrder.BIG_ENDIAN).putInt(0xd00dfeed.toInt()).putInt(size)
            for (index in 40 until size) this[index] = index.toByte()
        }
        val raw = if (external != null) fixture(rawFixture, fixtureDirectory) else ByteArray(8192).apply {
            "ARMd".toByteArray().copyInto(this, 56)
            "Linux version 6.6.89-tail-fixture (test)".toByteArray().copyInto(this, 128)
        }
        val compressed = (if (external != null) fixture(external, fixtureDirectory) else KernelCompression.encode(raw, format)) + tail
        val bytes = ByteArray(4096 + ((compressed.size + 4095) / 4096) * 4096)
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).apply {
            put("ANDROID!".toByteArray()); putInt(8, compressed.size); putInt(20, 1584); putInt(40, 4)
        }
        compressed.copyInto(bytes, 4096)
        val directory = temporary.newFolder("$format-$withTail-${external ?: "canonical"}")
        val base = File(directory, "base.img").apply { writeBytes(bytes) }
        val credential = UltraKernelCredential.of("Aa1".repeat(16))
        val plan = UltraKernelPlan.fromRecords("6.6.89-tail-fixture",
            listOf(UltraKernelPlan.PatchRecord("fixture", 1024, ByteArray(48), "Aa1".repeat(16).toByteArray()),
                UltraKernelPlan.PatchRecord("path", 2048, ByteArray(UltraKernelCredential.INIT_PATH_FIELD),
                    credential.initPathField(UltraKernelCredential.INIT_PATH_FIELD))),
            credential, baseKernelSha256 = UltraKernelSpec.sha256(raw))
            .let { it.withDerived(it.apply(raw).derived) }
        val text = plan.specText(plan.credential)
        val asset = UltraKernelGeneratedAsset.of(plan, base.length(), 0, text)
        val candidate = UltraKernelBuilder(File(directory, "builder")).generate(base, asset, UltraKernelSpec.parse(text))
        val report = BootImageInspector.inspect(candidate.image)
        val component = ByteArray(report.kernelSize.toInt())
        RandomAccessFile(candidate.image, "r").use { input ->
            input.seek(report.kernelOffset); input.readFully(component)
        }
        assertEquals(format, report.compression)
        assertArrayEquals("kernel bytes must still equal the applied spec", plan.apply(raw).kernel,
            KernelCompression.decode(component, report.compression, KernelCompression.MAX_KERNEL_BYTES))
        assertArrayEquals("appended DTB belongs to the kernel component and must survive rebuilding", tail,
            component.copyOfRange(component.size - tail.size, component.size))
        assertArrayEquals("the input image remains unchanged", bytes, base.readBytes())
        BootImageRoundTrip.verify(candidate.image, File(directory, "roundtrip").apply { mkdirs() })
        val recovered = UltraKernelOriginalRecovery(UltraKernelMemoryAssets(emptyMap())).recover(candidate.image,
            requireNotNull(candidate.image.parentFile), emptyList(), File(directory, "recovery"), generatedOnly = external != null)
        org.junit.Assert.assertNotNull("recovery must use the same component-tail rule as generation", recovered)
        assertArrayEquals("restoring a generated image restores the complete kernel", raw,
            UltraKernelPlan.readKernel(recovered!!.image))
        val recoveredReport = BootImageInspector.inspect(recovered.image)
        val recoveredComponent = ByteArray(recoveredReport.kernelSize.toInt())
        RandomAccessFile(recovered.image, "r").use { input ->
            input.seek(recoveredReport.kernelOffset); input.readFully(recoveredComponent)
        }
        assertArrayEquals("recovery retains appended data", tail,
            recoveredComponent.copyOfRange(recoveredComponent.size - tail.size, recoveredComponent.size))
        if (external == null) assertArrayEquals("canonical component restores byte-for-byte", bytes,
            recovered.image.readBytes())
        else {
            val exact = UltraKernelOriginalRecovery(UltraKernelMemoryAssets(emptyMap())).recover(candidate.image,
                requireNotNull(candidate.image.parentFile), listOf(base), File(directory, "backup-recovery"))
            org.junit.Assert.assertNotNull("original backup must restore the exact compressed container", exact)
            assertArrayEquals(bytes, exact!!.image.readBytes())
            println("EXTERNAL_STREAM_GENERATION_RECOVERY $external passed")
        }
    }
}
