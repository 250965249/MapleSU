package dev.maplesu.manager.ultrakernel

import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.KernelCompression
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** The patch asset describes the kernel; the input image owns its container layout. */
class UltraKernelContainerTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test
    fun aFooterlessPartitionDumpCanProduceACompactCandidate() {
        val source = image("partition.img", size = 64 * 1024)
        val candidate = build(source)
        assertTrue(candidate.image.length() < source.length())
        assertEquals(12 * 1024L, candidate.image.length())
        assertEquals(1, candidate.differingBytes)
    }

    @Test
    fun theReferenceDevicesPartitionSizeDoesNotConstrainAnotherContainer() {
        val source = image("factory.img", size = 12 * 1024)
        val candidate = build(source)
        assertEquals(source.length(), candidate.image.length())
        assertEquals(release, candidate.kernelRelease)
    }

    @Test
    fun aBootRamdiskIsPreservedInsteadOfComparedWithTheReferenceDevice() {
        val ramdisk = byteArrayOf(4, 8, 15, 16, 23, 42)
        val source = image("with-ramdisk.img", size = 16 * 1024, ramdisk = ramdisk)
        val candidate = build(source)
        val report = BootImageInspector.inspect(candidate.image)
        assertEquals(ramdisk.size.toLong(), report.ramdiskSize)
        val bytes = candidate.image.readBytes()
        assertArrayEquals(ramdisk, bytes.copyOfRange(report.ramdiskOffset.toInt(),
            report.ramdiskOffset.toInt() + ramdisk.size))
    }

    @Test
    fun theSameReleaseBannerDoesNotAuthorizeAnotherPinnedBase() {
        val source = image("same-release.img", size = 12 * 1024)
        val bytes = source.readBytes().apply { this[4096 + 2048] = 55 }
        source.writeBytes(bytes)

        val failure = assertThrows(IllegalStateException::class.java) { build(source) }
        assertTrue(failure.message.orEmpty().startsWith("ULTRA_KERNEL_TEMPLATE_BASE_MISMATCH"))
    }

    @Test
    fun theReferenceBaseStillRequiresItsPinnedOutputDigest() {
        val source = image("pinned.img", size = 12 * 1024)
        val error = assertThrows(IllegalStateException::class.java) {
            build(source, expectedKernel = "0".repeat(64))
        }
        assertTrue(error.message!!.startsWith("ULTRA_KERNEL_RESULT_DIGEST_MISMATCH"))
    }

    @Test
    fun aTemplateWithoutABasePinStillRequiresItsOutputDigestAcrossReleases() {
        val source = image("unpinned-base.img", size = 12 * 1024)
        val error = assertThrows(IllegalStateException::class.java) {
            build(source, expectedKernel = "0".repeat(64),
                assetRelease = "6.6.88-android15-container-fixture", pinBase = false)
        }
        assertTrue(error.message!!.startsWith("ULTRA_KERNEL_RESULT_DIGEST_MISMATCH"))
    }

    @Test
    fun aTemplateWithoutABasePinKeepsItsOutputPinAcrossReleases() {
        val source = image("output-pinned.img", size = 12 * 1024)
        val candidate = build(source, assetRelease = "6.6.88-android15-container-fixture", pinBase = false)
        assertTrue(candidate.expectedPinned)
    }

    @Test
    fun aDifferentBaseStillRequiresEveryOriginalPatchByte() {
        val source = image("wrong-site.img", size = 12 * 1024)
        source.writeBytes(source.readBytes().apply { this[4096 + 1024] = 2 })
        val error = assertThrows(IllegalStateException::class.java) { build(source) }
        assertTrue(error.message!!.startsWith("ULTRA_KERNEL_TEMPLATE_BASE_MISMATCH"))
    }

    @Test
    fun allAospBootHeadersKeepTheirLayoutAndRamdiskAcrossKernelFormats() {
        for (version in 0..4) {
            for (format in listOf("RAW_ARM64", "GZIP", "LZ4_LEGACY", "LZ4_FRAME", "XZ", "ZSTD")) {
                for (page in if (version < 3) listOf(2048, 4096, 8192, 16384) else listOf(4096)) {
                    val component = KernelCompression.encode(kernel, format)
                    val ramdisk = byteArrayOf(4, 8, 15, 16, 23, 42)
                    val ramdiskOffset = (page + component.size + page - 1) / page * page
                    val source = File(temporary.root, "v$version-$format-$page.img")
                    val bytes = ByteArray((ramdiskOffset + ramdisk.size + page - 1) / page * page)
                    ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).apply {
                        put("ANDROID!".toByteArray())
                        putInt(8, component.size)
                        putInt(40, version)
                        if (version < 3) {
                            putInt(16, ramdisk.size)
                            putInt(36, page)
                            if (version > 0) putInt(1644, if (version == 1) 1648 else 1660)
                        } else {
                            putInt(12, ramdisk.size)
                            putInt(20, if (version == 3) 1580 else 1584)
                        }
                    }
                    component.copyInto(bytes, page)
                    ramdisk.copyInto(bytes, ramdiskOffset)
                    source.writeBytes(bytes)
                    val candidate = build(source)
                    val report = BootImageInspector.inspect(candidate.image)
                    assertEquals("$version/$format/$page", version, report.headerVersion)
                    assertEquals(page.toLong(), report.pageSize)
                    assertEquals(format, report.compression)
                    assertArrayEquals(kernel.apply { this[1024] = 1 }, UltraKernelPlan.readKernel(candidate.image))
                    val output = candidate.image.readBytes()
                    assertArrayEquals(ramdisk, output.copyOfRange(report.ramdiskOffset.toInt(),
                        report.ramdiskOffset.toInt() + ramdisk.size))
                    assertArrayEquals(bytes, source.readBytes())
                }
            }
        }
    }

    private val release = "6.6.89-android15-8-container-fixture"
    private val kernel: ByteArray get() = ByteArray(8192).apply {
        "ARMd".toByteArray().copyInto(this, 56)
        "Linux version $release (fixture)".toByteArray().copyInto(this, 128)
    }

    private fun image(name: String, size: Int, ramdisk: ByteArray = ByteArray(0)): File {
        val bytes = ByteArray(size)
        val header = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        header.put("ANDROID!".toByteArray())
        header.putInt(8, kernel.size)
        header.putInt(12, ramdisk.size)
        header.putInt(20, 1584)
        header.putInt(40, 4)
        kernel.copyInto(bytes, 4096)
        ramdisk.copyInto(bytes, 12 * 1024)
        return File(temporary.root, name).apply { writeBytes(bytes) }
    }

    private fun build(source: File, expectedKernel: String? = null, assetRelease: String = release,
        pinBase: Boolean = true): UltraKernelBuilder.Candidate {
        val spec = UltraKernelSpec.parse("#kernel=$release\n1024|00|01")
        val patched = kernel.apply { this[1024] = 1 }
        val asset = UltraKernelReleaseAsset(
            id = "fixture", label = "fixture", summary = "", specAsset = "fixture.spec",
            specSha256 = "0".repeat(64), patches = 1, kernelRelease = assetRelease,
            baseKernelSha256 = if (pinBase) UltraKernelSpec.sha256(kernel) else "",
            expectedKernelSha256 = expectedKernel ?: UltraKernelSpec.sha256(patched),
            knownBaseImageSha256 = "", knownBaseImageBootSha256 = "",
            imageSizeBytes = 100_663_296, ramdiskSize = 0,
            source = "sample", verification = "experimental",
        )
        return UltraKernelBuilder(File(temporary.root, "work")).generate(source, asset, spec)
    }
}
