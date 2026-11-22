package dev.maplesu.manager.ultrakernel

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Cross-release proof on the real boot samples (read-only, never flashed).
 *
 * One test per supported release, asserting what the generator *actually* does there. The point of
 * the whole code-body work is that these four lines are all `16/16` instead of `16/16`, `3/18`,
 * `STRUCT_OFFSET_NOT_FOUND`, `SITE_SYMBOL_MISSING`.
 *
 * `refOrig` is recorded rather than asserted-away: it is the count of sites that still carry the
 * *reference* build's pristine bytes, and it is expected to be low on every non-6.6.89 kernel. Seeing
 * it low while `sites` is 16/16 is exactly the shape this work was supposed to produce - the code is
 * the kernel's own now, not 6.6.89's bytes moved to a new address.
 *
 * The samples are large workspace artefacts, not test resources, so each test is skipped when its
 * boot image is absent; the pure-JVM tests do not depend on them.
 */
class UltraKernelCrossReleaseTest {

    private val credential = UltraKernelPlanFixtures.freshCredential()
    private val generator = UltraKernelSpecGenerator()

    @Test
    fun `6_6_89 retains k22 code with corrected SDK metadata`() {
        val plan = generate("6.6.89", "OnePlusAce6_6.6", UltraKernelPlanFixtures.activeCredential()) ?: return
        val evidence = requireNotNull(plan.evidence)
        assertEquals("every site must be generated", "16/16", evidence.summary)
        assertEquals("16/16", evidence.summary)
        assertTrue("no optional record may be skipped here", evidence.skippedRoles.isEmpty())
        assertEquals(16, plan.records.size)
        // The packaged records plus independently derived dynamic-SCS entry/frame corrections.
        val shipped = UltraKernelPlanFixtures.shippedRecords()
        plan.records.forEachIndexed { index, record ->
            val exec = record.role == "do_execveat_common+0x0"
            assertEquals("offset ${record.role}", shipped[index].offset, record.offset)
            if (exec) assertEquals(0xD101C3FF.toInt(), UltraKernelA64.le32Bits(record.original, 0))
            else assertTrue("original ${record.role}", shipped[index].original.contentEquals(record.original))
            assertTrue("replacement ${record.role}",
                UltraKernelPlanFixtures.correctedReplacement(index).contentEquals(record.replacement))
            if (record.cave != null) assertTrue("original function must be preserved", record.shiftedFrom != null)
        }
        assertEquals(UltraKernelPlanFixtures.CORRECTED_K22_KERNEL_SHA256, plan.derived?.patchedKernelSha256)
        assertEquals(874, plan.derived?.changedBytes)
    }

    @Test
    fun `6_1_25 now renders all eighteen sites`() {
        val plan = generate("6.1.25", "OnePlus12_6.1") ?: return
        val evidence = requireNotNull(plan.evidence)
        assertEquals("the recipe's sites are the kernel's own, not the reference build's", "16/16", evidence.summary)
        assertEquals(16, plan.records.size)
        // The kernel is not the reference build: most pristine bytes differ, and that is fine now.
        assertTrue(
            "6.1.25 must not look like the reference build (was ${evidence.referenceOrigMatch})",
            evidence.referenceOrigMatch != "16/16",
        )
        assertTrue("a full kernel digest must be derived", (plan.derived?.patchedKernelSha256 ?: "").length == 64)
    }

    @Test
    fun `6_12_23 renders all eighteen sites at the actual function boundaries`() {
        val plan = generate("6.12.23", "OnePlus15_6.12") ?: return
        val evidence = requireNotNull(plan.evidence)
        assertEquals("17/17", evidence.summary)
        assertEquals(17, plan.records.size)
        // This fixture also has an odd symbol count (125417). The correctly paired die
        // spans 776 bytes; the old padding bug paired it with its shorter successor.
        val gate = plan.records.first { it.role == "die+0x0" }
        assertEquals(UltraKernelBodies.EXECVE_GATE_BYTES, gate.replacement.size)
        assertEquals("original die entry", 0x2D16CL, gate.shiftedFrom)
        assertTrue("the original die remains callable", gate.offset != gate.shiftedFrom)
        assertTrue(plan.records.filter { it.cave == "die" }.all {
            it.offset + it.length <= gate.offset + UltraKernelBodies.EXECVE_GATE_BYTES + 16 + 12
        })
    }

    @Test
    fun `5_10 generates without the CFI record it does not have`() {
        val plan = generate("5.10", "OnePlus10_Pro_5.10") ?: return
        val evidence = requireNotNull(plan.evidence)
        assertEquals("report_cfi_failure is absent on 5.10, so the CFI stub is skipped", listOf("report_cfi_failure+0x0"), evidence.skippedRoles)
        assertEquals("every record this kernel can host is generated", "15/15", evidence.summary)
        assertEquals(15, plan.records.size)
        assertTrue(plan.records.none { it.role == "report_cfi_failure+0x0" })
    }

    /**
     * 5.15 has no CFI either, so it takes the same path as 5.10: 17 records, CFI stanza skipped.
     *
     * Unlike 6.12/6.18 it still exports `module_alloc`/`module_memfree` under their original names,
     * so no alias is needed - the alias table only applies where the rename actually happened.
     */
    @Test
    fun `5_15 generates without the CFI record it does not have`() {
        val plan = generate("5.15", "OnePlus11_5.15") ?: return
        val evidence = requireNotNull(plan.evidence)
        assertEquals(listOf("report_cfi_failure+0x0"), evidence.skippedRoles)
        assertEquals("every record this kernel can host is generated", "15/15", evidence.summary)
        assertEquals(15, plan.records.size)
        assertTrue(plan.records.none { it.role == "report_cfi_failure+0x0" })
        // Its own build, not the reference one - and the `execve-gate` cave still fits.
        assertTrue(
            "5.15 must not look like the reference build (was ${evidence.referenceOrigMatch})",
            evidence.referenceOrigMatch != "16/16",
        )
        assertEquals(UltraKernelBodies.EXECVE_GATE_BYTES, plan.records.first { it.role == "die+0x0" }.replacement.size)
    }

    /**
     * 6.18.21 is the newest release in the sample set and needs no new mechanism, which is the
     * interesting part: its `execmem_alloc` needs the same two-argument adapter as 6.12,
     * while `execmem_free` keeps the one-argument contract. Both accessor shapes are still
     * `mrs sp_el0` + an immediate load - only the displacements moved.
     *
     * The execve hook separately verifies the PACIASP instruction it displaces; BTI on other
     * kernel APIs does not change that entry contract.
     */
    @Test
    fun `6_18_21 renders all eighteen sites`() {
        val plan = generate("6.18.21", "OnePlus16_6.18") ?: return
        val evidence = requireNotNull(plan.evidence)
        assertEquals("17/17", evidence.summary)
        assertEquals(17, plan.records.size)
        assertTrue(
            "6.18.21 must not look like the reference build (was ${evidence.referenceOrigMatch})",
            evidence.referenceOrigMatch != "16/16",
        )
        assertTrue("at least one collapsed cave must move", plan.records.any { it.shiftedFrom != null })
    }

    private fun generate(label: String, directory: String, credential: UltraKernelCredential = this.credential): UltraKernelPlan? {
        val boot = File("../MapleSU_Reference/Boots/$directory/boot.img")
        assumeTrue("$label boot sample not available", boot.isFile)
        val plan = generator.generate(boot, credential)
        assertNotNull("$label must produce a plan", plan)
        assertEquals(UltraKernelPlan.Origin.GENERATED, plan.origin)
        assertEquals(UltraKernelPlan.SupportLevel.EXPERIMENTAL, plan.supportLevel)
        return plan
    }
}
