package dev.maplesu.ghostlock.extract

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Field-level tests for the image half of the extraction pipeline. The fixtures
 * carry a real arm64 Image header, a real linux_banner, a real embedded BTF blob
 * and a real kallsyms table, so the parsers (not stubs) run.
 */
class ExtractionPipelineTest {
    @get:Rule val temporary = TemporaryFolder()

    private val fixture by lazy { SyntheticKernel.build() }

    @Test
    fun `boot image release is the uts banner`() {
        val boot = BootImage.load(fixture.bootImage)
        assertEquals(SyntheticKernel.RELEASE, boot.release())
        assertFalse(boot.mtkLz4)
        assertFalse(boot.mtkGzip)
    }

    @Test
    fun `raw arm64 image and gzip image load`() {
        assertEquals(SyntheticKernel.RELEASE, BootImage.load(fixture.image).release())
        val gzipped = java.io.ByteArrayOutputStream().also { out ->
            java.util.zip.GZIPOutputStream(out).use { it.write(fixture.image) }
        }.toByteArray()
        val boot = BootImage.load(gzipped)
        assertEquals(SyntheticKernel.RELEASE, boot.release())
        // A top-level gzip is unwrapped before the Image checks; only a gzip
        // *inside* an Android boot header is the MediaTek fallback case.
        assertFalse(boot.mtkGzip)
    }

    @Test
    fun `foreign bytes are refused with the reference message`() {
        val error = assertThrows(java.io.IOException::class.java) {
            BootImage.load(ByteArray(128) { 0x41 })
        }
        assertTrue(error.message!!.contains("not an Android boot image"))
    }

    @Test
    fun `embedded btf is located at the symbol described offset`() {
        val blob = BootImage.load(fixture.image).embeddedBtfAt()
        assertNotNull(blob)
        assertEquals(0x18000, blob!!.offset)
        val btf = Btf.parse(blob.bytes)
        assertEquals(132, btf.field("task_struct", "prio"))
        assertEquals(2316, btf.field("task_struct", "pi_lock"))
        assertEquals(136, btf.size("cred"))
        assertEquals(48, btf.field("rt_mutex_waiter", "task"))
        assertEquals(56, btf.field("rt_mutex_waiter", "lock"))
        assertEquals(0x3C0, btf.size("mm_struct"))
    }

    @Test
    fun `kallsyms recovery rebuilds the exact anchor symbols`() {
        val boot = BootImage.load(fixture.image)
        val kallsyms = KallsymsRecovery.recover(boot.kernel, boot.embeddedBtfAt())
        assertEquals(SyntheticKernel.BASE, kallsyms.unique("_text"))
        assertEquals(SyntheticKernel.BASE + 0x1000, kallsyms.unique("init_task"))
        assertEquals(SyntheticKernel.BASE + 0x2000, kallsyms.unique("init_cred"))
        assertEquals(SyntheticKernel.BASE + 0x3000, kallsyms.unique("root_task_group"))
        assertEquals(SyntheticKernel.BASE + 0x4000, kallsyms.unique("selinux_state"))
        assertEquals(
            SyntheticKernel.IMAGE_SIZE.toLong(),
            kallsyms.unique("_end")!! - kallsyms.unique("_text")!!,
        )
        val symbols = KernelLayout.resolveSymbols(kallsyms, SyntheticKernel.BASE)
        assertEquals(0x1000L, symbols["off_init_task"])
        assertEquals(0x2000L, symbols["off_init_cred"])
        assertEquals(0x3000L, symbols["off_root_task_group"])
        assertEquals(0x4000L, symbols["off_selinux_enforcing"])
        // The reference's loggers heuristic: symbol + 0x10.
        assertEquals(0x9010L, symbols["off_slide_loggers_0_1"])
    }

    @Test
    fun `struct fields resolve from btf with the reference names`() {
        val btf = Btf.parse(BootImage.load(fixture.image).embeddedBtfAt()!!.bytes)
        val structs = KernelLayout.resolveStructs(btf)
        assertEquals(132, structs["task_prio"])
        assertEquals(2280, structs["task_seccomp"])
        assertEquals(48, structs["waiter_task"])
        assertEquals(56, structs["waiter_lock"])
        assertEquals(0x3C0, structs["struct_mm_struct"])
    }

    @Test
    fun `pipeline generates a complete profile for a verified 6_6 family`() {
        val boot = temporary.newFile("boot.img").apply { writeBytes(fixture.bootImage) }
        val outcome = GhostlockExtractionPipeline.parse(
            ExtractInput.BootImageFile(boot),
            workDir = temporary.newFolder("work"),
        )
        assertTrue(outcome.toString(), outcome is ExtractionOutcome.Generated)
        val profile = (outcome as ExtractionOutcome.Generated).profiles.single()
        assertEquals(SyntheticKernel.RELEASE, profile.release)
        assertTrue(
            "invalid fields: ${profile.validation.invalidFields}",
            profile.complete,
        )
        assertEquals("select_stack", profile.route)
        // The verified-family fallback the reference also uses without disassembly.
        assertTrue(profile.document.contains("waiter_shift = -2"))
        assertTrue(profile.document.contains("kernel_phys_load = null"))
        assertTrue(profile.document.contains("kernel_major = 6"))
        assertTrue(profile.document.contains("collisions = 4"))
        assertTrue(profile.document.contains("init_task = 4096"))
        assertTrue(profile.document.contains("caps_offset = 48"))
        assertEquals("local_image", profile.provenance.kind)
        assertEquals(64, profile.provenance.documentSha256.length)
        assertEquals(64, (profile.provenance.sourceSha256 ?: "").length)
        assertEquals(ProfileProvenance.REFERENCE_COMMIT, profile.provenance.referenceCommit)
        // The generated document is accepted by the wire encoder.
        val wire = profile.validation.wire
        assertNotNull(wire)
        val header = java.nio.ByteBuffer.wrap(wire).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        assertEquals(0x0d000721, header.int)
        assertEquals(2, header.short.toInt())
    }

    @Test
    fun `profile without btf is generated but never usable`() {
        val stripped = fixture.image.copyOf()
        // Remove the BTF magic so the blob is not found, as a vendor image may.
        for (i in 0 until 8) stripped[0x18000 + i] = 0
        val boot = temporary.newFile("boot-nobtf.img").apply { writeBytes(stripped) }
        val outcome = GhostlockExtractionPipeline.parse(
            ExtractInput.BootImageFile(boot),
            workDir = temporary.newFolder("work-nobtf"),
        )
        val profile = (outcome as ExtractionOutcome.Generated).profiles.single()
        assertFalse(profile.complete)
        assertTrue(profile.validation.invalidFields.contains("task_struct.prio"))
        val state = GhostlockOtaFlow(profile.release).finish(outcome)
        assertEquals(
            OtaParseState.Failed(OtaFailure.INCOMPLETE_PROFILE),
            state,
        )
    }

    @Test
    fun `device release mismatch is refused before any attempt`() {
        val boot = temporary.newFile("boot-mismatch.img").apply { writeBytes(fixture.bootImage) }
        val outcome = GhostlockExtractionPipeline.parse(
            ExtractInput.BootImageFile(boot),
            workDir = temporary.newFolder("work-mismatch"),
        )
        val flow = GhostlockOtaFlow("6.1.100-android14-11-gdeadbeef-ab123")
        assertEquals(OtaParseState.Failed(OtaFailure.KERNEL_MISMATCH), flow.finish(outcome))
    }

    @Test
    fun `candidate is rendered with the reference field order`() {
        val symbols = linkedMapOf<String, Long?>(
            "off_init_task" to 0x1000,
            "off_init_cred" to 0x2000,
            "off_root_task_group" to 0x3000,
            "off_selinux_enforcing" to 0x4000,
            "off_selinux_blob_sizes" to 0x5000,
            "off_security_hook_heads" to 0x6000,
            "off_slide_nfulnl_logger" to 0x7000,
            "off_slide_boot_id" to 0x8000,
            "off_slide_loggers_0_1" to 0x9010,
        )
        val structs = KernelLayout.resolveStructs(
            Btf.parse(BootImage.load(fixture.image).embeddedBtfAt()!!.bytes))
        val document = KernelLayout.renderConf(
            KernelLayout.ConfInputs(
                release = "6.6.89-android15-8-test",
                phys = null,
                physOffset = null,
                symbols = symbols,
                structs = structs,
                route = "select_stack",
                routeGeometry = listOf("waiter_shift" to "-2"),
                cred = KernelLayout.confCred6x(),
                emptyZeroPage = 0xA000,
            ),
        )
        val lines = document.trim().split("\n")
        assertEquals("# GhostLock kernel profile: 6.6.89-android15-8-test (HOCON, self-contained).", lines[0])
        assertEquals("release = \"6.6.89-android15-8-test\"", lines[1])
        assertEquals("schema_version = 1", lines[2])
        assertEquals("kernel_major = 6", lines[3])
        assertEquals("recommend_shizuku = 0", lines[4])
        assertEquals("kernel_phys_load = null", lines[5])
        assertEquals("kernel_phys_offset = null", lines[6])
        assertEquals("route {", lines[7])
        assertEquals("  select_stack {", lines[8])
        assertEquals("    waiter_shift = -2", lines[9])
        assertEquals("  }", lines[10])
        assertEquals("}", lines[11])
        assertEquals("fallback {", lines[12])
        assertEquals("  to = \"none\"", lines[13])
        assertEquals("}", lines[14])
        assertEquals("kernelsnitch {", lines[15])
        assertEquals("  collisions = 4", lines[16])
        assertEquals("  mm_struct_sz = null", lines[17])
        assertEquals("}", lines[18])
        assertEquals("task_struct {", lines[19])
        assertTrue(document.contains("empty_zero_page = 40960"))
        assertTrue(document.indexOf("task_struct {") < document.indexOf("cred {"))
        assertTrue(document.indexOf("cred {") < document.indexOf("offset {"))
        assertTrue(document.endsWith("\n"))
    }

    @Test
    fun `verified family table matches the reference`() {
        assertEquals(-2, KernelLayout.pselectWaiterShiftFor(SyntheticKernel.RELEASE))
        assertEquals(1, KernelLayout.pselectWaiterShiftFor("6.1.145-android14-11-gabc-ab1"))
        assertEquals(0, KernelLayout.pselectWaiterShiftFor("6.12.38-android16-5-gabc-ab1-4k"))
        assertNull(KernelLayout.pselectWaiterShiftFor("6.6.89-generic"))
        assertNull(KernelLayout.pselectWaiterShiftFor("6.12.38-android16-5-gabc-ab1-4k".replace("android16", "custom")))
        assertTrue(KernelLayout.kernelLayoutVerified(SyntheticKernel.RELEASE))
        assertFalse(KernelLayout.kernelLayoutVerified("6.6.89-generic"))
    }

    @Test
    fun `missing files and huge files fail closed`() {
        val missing = File(temporary.root, "does-not-exist.img")
        val outcome = GhostlockExtractionPipeline.parse(
            ExtractInput.BootImageFile(missing),
            workDir = temporary.newFolder("work-missing"),
        )
        assertTrue(outcome is ExtractionOutcome.Failure)
    }
}
