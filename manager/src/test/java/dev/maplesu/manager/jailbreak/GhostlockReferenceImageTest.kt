package dev.maplesu.manager.jailbreak

import com.ghostlock.app.data.HoconSupport
import com.ghostlock.app.data.asValueMap
import dev.maplesu.ghostlock.extract.*
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.*
import org.junit.Assume.assumeNotNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class GhostlockReferenceImageTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun realImageUsesTheDerivedLoggerSlotAndRejectsInfeasibleSelectGeometry() {
        val binary = System.getenv("MAPLESU_GHOSTLOCK_TEST_EXTRACTOR")
        val image = System.getenv("MAPLESU_GHOSTLOCK_TEST_IMAGE_61")
        assumeNotNull(binary, image)
        val outcome = GhostlockExtractionPipeline.parse(ExtractInput.BootImageFile(File(image!!)),
            temporary.newFolder(), imageExtractor = GhostlockNativeExtractor(File(binary!!)))
        assertTrue(outcome.toString(), outcome is ExtractionOutcome.Generated)
        val profile = (outcome as ExtractionOutcome.Generated).profiles.single()
        assertEquals("6.1.25-android14-11-o-gf12b379cb280", profile.release)
        assertEquals("tcp_zerocopy", profile.route)
        val offsets = HoconSupport.parseValue(profile.document).asValueMap()!!["offset"].asValueMap()!!
        assertEquals(0x1f12ae8L, (offsets["slide_loggers_0_1"] as Number).toLong())
        assertTrue(profile.validation.invalidFields.toString(), profile.complete)
        GhostlockProfileCodec.toWire(profile.document, profile.release)
        assertEquals("b67359641c8663e5184abba73ecdf2c456dce3e7", profile.provenance.referenceCommit)
    }

    @Test fun referenceParserFailureNeverBecomesAnEmptySuccessfulProfile() {
        val binary = System.getenv("MAPLESU_GHOSTLOCK_TEST_EXTRACTOR")
        assumeNotNull(binary)
        val malformed = temporary.newFile().apply { writeText("invalid boot image") }
        val outcome = GhostlockExtractionPipeline.parse(ExtractInput.BootImageFile(malformed),
            temporary.newFolder(), imageExtractor = GhostlockNativeExtractor(File(binary!!)))
        assertTrue(outcome is ExtractionOutcome.Failure)
        assertEquals(FailureKind.GENERIC, (outcome as ExtractionOutcome.Failure).kind)
        assertTrue(outcome.message.contains("exit=2"))
    }

    @Test fun vendorBootActuallySuppliesThePhysicalLoadAndProvenDramBase() {
        val binary = System.getenv("MAPLESU_GHOSTLOCK_TEST_EXTRACTOR")
        val image = System.getenv("MAPLESU_GHOSTLOCK_TEST_IMAGE_61")
        assumeNotNull(binary, image)
        val vendor = temporary.newFile("vendor_boot.img").apply {
            writeBytes(ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
                .put("VNDRBOOT".toByteArray()).putInt(3).putInt(4096).putInt(0x40080000).array())
        }
        val outcome = GhostlockExtractionPipeline.parse(
            ExtractInput.BootImageFile(File(image!!), vendorBoot = vendor), temporary.newFolder(),
            imageExtractor = GhostlockNativeExtractor(File(binary!!)))
        val profile = (outcome as ExtractionOutcome.Generated).profiles.single()
        val parsed = HoconSupport.parseValue(profile.document).asValueMap()!!
        assertEquals(0x40080000L, (parsed["kernel_phys_load"] as Number).toLong())
        assertEquals(0x40000000L, (parsed["kernel_phys_offset"] as Number).toLong())
        assertTrue(profile.validation.invalidFields.toString(), profile.complete)
    }
}
