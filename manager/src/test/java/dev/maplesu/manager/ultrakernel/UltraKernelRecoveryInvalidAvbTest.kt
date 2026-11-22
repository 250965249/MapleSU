package dev.maplesu.manager.ultrakernel

import dev.maplesu.image.BootImageRebuilder
import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.AvbFooter
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class UltraKernelRecoveryInvalidAvbTest {
    @get:Rule val temporary = TemporaryFolder()
    private val recovery = UltraKernelOriginalRecovery(UltraKernelMemoryAssets(emptyMap()))

    @Test fun recoverableInvalidFooterDoesNotStopGeneratedRecoveryProbes() {
        for (kind in 0..2) {
            val input = image(kind)
            val before = input.readBytes()
            val receipts = temporary.newFolder("receipts-$kind")
            val output = File(temporary.root, "unused-output-$kind")
            assertNull(recovery.generatedKernel(input, receipts))
            assertNull(recovery.recover(input, receipts, emptyList(), output,
                generatedOnly = true))
            assertArrayEquals(before, input.readBytes())
            assertFalse(output.exists())
            assertTrue(receipts.listFiles().orEmpty().isEmpty())
        }
    }

    @Test fun strictReaderStillReportsTheInvalidFooter() {
        assertThrows(BootImageRebuilder.ValidationException::class.java) {
            BootImageRebuilder.readRecoveryRecord(image(0))
        }
    }

    @Test fun unknownNonzeroTailIsNotTreatedAsAnEmptyRecoveryRecord() {
        val input = image(1, unknownTail = true)
        val before = input.readBytes()
        assertThrows(BootImageRebuilder.ValidationException::class.java) {
            recovery.generatedKernel(input, temporary.newFolder())
        }
        assertArrayEquals(before, input.readBytes())
    }

    @Test fun invalidComponentBoundsAreStillPropagated() {
        val input = image(0)
        val bytes = input.readBytes()
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(8, bytes.size * 2)
        input.writeBytes(bytes)
        val error = assertThrows(BootImageInspector.InvalidImageException::class.java) {
            recovery.generatedKernel(input, temporary.newFolder())
        }
        assertEquals("COMPONENT_OUT_OF_BOUNDS", error.code)
        assertArrayEquals(bytes, input.readBytes())
    }

    @Test fun validFooterlessInputHasNoRecoveryAndIsUnchanged() {
        val input = image(-1)
        val before = input.readBytes()
        assertNull(recovery.generatedKernel(input, temporary.newFolder()))
        assertArrayEquals(before, input.readBytes())
    }

    @Test fun builderProducesAReadbackVerifiedCandidateAfterTheRecoveryProbe() {
        for (kind in 0..2) {
            val input = image(kind)
            val before = input.readBytes()
            val kernel = before.copyOfRange(4096, 12288)
            val text = "#kernel=5.10.237\n1024|00|01"
            val spec = UltraKernelSpec.parse(text)
            val expected = spec.apply(kernel).kernel
            val asset = UltraKernelReleaseAsset(
                id = "invalid-avb-$kind", label = "fixture", summary = "fixture",
                specAsset = "fixture.spec", specSha256 = UltraKernelSpec.sha256(text.toByteArray()),
                patches = 1, kernelRelease = "5.10.237", baseKernelSha256 = UltraKernelSpec.sha256(kernel),
                expectedKernelSha256 = UltraKernelSpec.sha256(expected), knownBaseImageSha256 = "",
                knownBaseImageBootSha256 = "", imageSizeBytes = 0, ramdiskSize = 0,
                source = "model", verification = "experimental")
            assertNull(recovery.generatedKernel(input, temporary.newFolder()))
            val candidate = UltraKernelBuilder(temporary.newFolder()).generate(input, asset, spec)
            assertEquals(UltraKernelSpec.sha256(expected), candidate.kernelSha256)
            assertArrayEquals(expected, UltraKernelPlan.readKernel(candidate.image))
            assertFalse(AvbFooter.parse(candidate.image).present)
            assertArrayEquals(before, input.readBytes())
        }
    }

    private fun image(kind: Int, unknownTail: Boolean = false): File {
        val bytes = ByteArray(32768)
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).apply {
            put("ANDROID!".toByteArray())
            putInt(8, 8192)
            putInt(20, 1584)
            putInt(40, 4)
        }
        "ARMd".toByteArray().copyInto(bytes, 4096 + 56)
        "Linux version 5.10.237 (fixture)".toByteArray().copyInto(bytes, 4096 + 128)
        if (unknownTail) bytes[12288 + 32] = 1
        if (kind >= 0) {
            val footer = bytes.size - 64
            "AVBf".toByteArray().copyInto(bytes, footer)
            ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN).apply {
                putInt(footer + 4, 1)
                putLong(footer + 12, if (kind == 0) 8192 else 12288)
                putLong(footer + 20, if (kind == 0) 8192 else if (kind == 1) 16384 else 65536)
                putLong(footer + 28, 1664)
            }
        }
        return temporary.newFile().apply { writeBytes(bytes) }
    }
}
