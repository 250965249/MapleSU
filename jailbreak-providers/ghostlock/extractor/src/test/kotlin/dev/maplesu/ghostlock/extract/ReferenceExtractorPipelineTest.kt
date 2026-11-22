package dev.maplesu.ghostlock.extract

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ReferenceExtractorPipelineTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun localImagesReachTheReferenceWithoutLosingAuxiliaryInputs() {
        val input = ExtractInput.BootImageFile(temporary.newFile("boot.img"),
            temporary.newFile("xbl_config.img"), temporary.newFile("uefi.img"),
            temporary.newFile("vendor_boot.img"))
        var received: ExtractInput.BootImageFile? = null
        val outcome = GhostlockExtractionPipeline.parse(input, temporary.newFolder(),
            imageExtractor = KernelImageExtractor { images, _, _ ->
                received = images
                "release = \"6.1.1-test\"\nroute { select_stack { pselect_waiter_shift = -1 } }\n"
            })
        assertEquals(input, received)
        val profile = (outcome as ExtractionOutcome.Generated).profiles.single()
        assertFalse("incomplete native output must stay non-runnable", profile.complete)
        assertEquals("local_image", profile.provenance.kind)
        assertEquals("select_stack", profile.route)
    }

    @Test fun originalExtractorFailureRetainsItsFailureClass() {
        val outcome = GhostlockExtractionPipeline.parse(
            ExtractInput.BootImageFile(temporary.newFile()), temporary.newFolder(),
            imageExtractor = KernelImageExtractor { _, _, _ ->
                throw ExtractionException(FailureKind.ALREADY_FIXED, "remove_waiter is fixed")
            })
        assertEquals(FailureKind.ALREADY_FIXED, (outcome as ExtractionOutcome.Failure).kind)
    }

    @Test fun otaAuxiliaryPartitionsReachTheSameEngineAndAreCleanedAfterSuccessAndFailure() {
        for (zip in listOf(false, true)) for (fail in listOf(false, true)) {
            val source = linkedMapOf("boot" to byteArrayOf(1), "xbl_config" to byteArrayOf(2),
                "uefi" to byteArrayOf(3), "vendor_boot" to byteArrayOf(4))
            val payload = SyntheticKernel.payloadImages(source)
            val archive = temporary.newFile().apply {
                writeBytes(if (zip) SyntheticKernel.otaZip(payload) else payload)
            }
            val work = temporary.newFolder()
            var called = false
            val outcome = GhostlockExtractionPipeline.parse(ExtractInput.LocalArchive(archive), work,
                imageExtractor = KernelImageExtractor { images, _, _ ->
                    called = true
                    assertEquals(1, images.boot.readBytes().first().toInt())
                    assertEquals(2, images.xblConfig!!.readBytes().first().toInt())
                    assertEquals(3, images.uefi!!.readBytes().first().toInt())
                    assertEquals(4, images.vendorBoot!!.readBytes().first().toInt())
                    if (fail) throw ExtractionException(FailureKind.KALLSYMS, "fixture failure")
                    "release = \"6.1.1-test\"\n"
                })
            assertTrue(called)
            assertEquals(if (fail) ExtractionOutcome.Failure::class else ExtractionOutcome.Generated::class,
                outcome::class)
            assertTrue("temporary auxiliary partitions leaked", work.listFiles().isNullOrEmpty())
        }
    }
}
