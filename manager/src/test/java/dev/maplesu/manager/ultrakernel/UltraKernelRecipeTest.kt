package dev.maplesu.manager.ultrakernel

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The recipe + renderer contract, checked against the shipped k22 spec as an oracle.
 *
 * Current k22 assets are experimental Panic repair candidates. These tests verify
 * deterministic generation, preserved function bodies and the shipped record layout.
 * Device boot acceptance remains a separate check.
 */
class UltraKernelRecipeTest {

    private val recipe = UltraKernelPlanFixtures.recipe()

    @Test fun `metadata relocations render without their historical tracepoint host`() {
        val raw = UltraKernelPlanFixtures.syntheticKernel()
        val host = "__traceiter_kvm_userspace_exit"
        val symbols = FakeSymbols(UltraKernelPlanFixtures.K22_SYMBOL_BASE - host, raw.size)
        val result = recipe.renderDetailed(symbols, raw, UltraKernelPlanFixtures.freshCredential())
        val metadata = result.records.single { it.cave == host }
        val placement = result.placements.getValue(host)
        assertEquals(placement.base + metadata.record.delta, metadata.site)
        assertEquals(null, metadata.shiftedFrom)
        assertEquals(metadata.site, UltraKernelA64.le32Bits(metadata.replacement, 0))
        assertEquals(emptyList<String>(), recipe.residue(symbols, result.records))
    }

    @Test fun `request v2 is installed only with both exact nofault symbols`() {
        val raw = UltraKernelPlanFixtures.syntheticKernel()
        val functions = mapOf("copy_from_user_nofault" to 0x800000,
            "copy_to_user_nofault" to 0x800040)
        for (available in listOf(emptyMap(), functions.filterKeys { it.startsWith("copy_from") },
            functions.filterKeys { it.startsWith("copy_to") }, functions)) {
            val result = recipe.renderDetailed(FakeSymbols(UltraKernelPlanFixtures.K22_SYMBOL_BASE + available,
                raw.size), raw, UltraKernelPlanFixtures.freshCredential())
            val added = result.records.filter { it.record.code == "request-v2" }
            assertEquals(if (available.size == 2) 1 else 0, added.size)
            assertEquals(272, result.records.single { it.record.code == "execve-gate" }.replacement.size)
            if (added.isNotEmpty()) {
                val body = added.single()
                val gate = result.records.single { it.record.code == "execve-gate" }
                assertEquals(gate.site + UltraKernelRequestV2.CAVE_OFFSET, body.site)
                assertEquals(UltraKernelRequestV2.BYTES, body.replacement.size)
                assertEquals("die", body.cave)
                assertEquals(emptyList<String>(), recipe.residue(
                    FakeSymbols(UltraKernelPlanFixtures.K22_SYMBOL_BASE + available, raw.size), result.records))
            }
        }
    }

    @Test fun `request v2 never selects ordinary copy aliases`() {
        val raw = UltraKernelPlanFixtures.syntheticKernel()
        val aliases = mapOf("copy_from_user" to 0x800000, "copy_to_user" to 0x800040,
            "__arch_copy_from_user" to 0x800080, "__arch_copy_to_user" to 0x8000c0)
        val result = recipe.renderDetailed(FakeSymbols(UltraKernelPlanFixtures.K22_SYMBOL_BASE + aliases,
            raw.size), raw, UltraKernelPlanFixtures.freshCredential())
        assertTrue(result.records.none { it.record.code == "request-v2" })
    }

    @Test fun `a record without layout consumers never requires unrelated target fields`() {
        val raw = ByteArray(64)
        val record = UltraKernelRecipe.Record("fixture+0x0", "fixture", 0, 4,
            byteArrayOf(1, 2, 3, 4), emptyList(), null)
        val result = UltraKernelRecipe("fixture", "fixture", UltraKernelCredential.LENGTH, "", listOf(record))
            .renderDetailed(FakeSymbols(mapOf("fixture" to 0), raw.size), raw,
                UltraKernelPlanFixtures.freshCredential())
        assertTrue(result.layout.fields.isEmpty())
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), result.records.single().replacement)
    }

    @Test fun `rendered layout carries the exact evidence consumed by the generated bodies`() {
        val raw = UltraKernelPlanFixtures.syntheticKernel()
        val result = recipe.renderDetailed(UltraKernelPlanFixtures.symbols(raw.size), raw,
            UltraKernelPlanFixtures.freshCredential())
        assertEquals(UltraKernelLayoutField(0x820, 8, null, "accessor"), result.layout.fields["task_struct.cred"])
        assertEquals(UltraKernelLayoutField(0x830, 16, null, "accessor"), result.layout.fields["task_struct.comm"])
        assertEquals(UltraKernelLayoutField(16, 4, null, "accessor"), result.layout.fields["cred.suid"])
    }

    @Test
    fun `the embedded recipe is the reviewed one`() {
        assertEquals(UltraKernelRecipe.SCHEMA, 1)
        assertEquals(16, recipe.records.size)
        assertEquals(UltraKernelPlanFixtures.K22_RELEASE, recipe.referenceRelease)
        assertEquals(
            listOf(
                "die+0x0", "die+0xD4", "arm64_notify_die+0x0", "free_initmem+0x0",
                "report_cfi_failure+0x0", "free_reserved_area+0x0", "do_execveat_common+0x0",
                "avc_denied+0x28", "__drm_puts_coredump+0x0", "__drm_printfn_coredump+0x0",
                "drm_dev_printk+0x0",
                "__dev_printk+0x0", "panic+0x0", "__traceiter_kvm_userspace_exit+0x70",
                "drm_dev_printk+0x5C", "drm_dev_printk+0x34",
            ),
            recipe.records.map { it.role },
        )
        assertEquals(9, recipe.records.count { it.constructed })
        assertEquals(
            "the embedded constant must not drift from its source JSON",
            dev.maplesu.manager.ultrakernel.K22_RECIPE_SHA256,
            UltraKernelRecipe.sha256Of(K22_RECIPE_JSON.toByteArray(Charsets.UTF_8)),
        )
    }

    @Test
    fun `the renderer relocates every movable group and preserves its original function`() {
        val kernel = UltraKernelPlanFixtures.syntheticKernel()
        val rendered = UltraKernelPlanFixtures.rendered()
        val patched = UltraKernelPlanFixtures.k22Plan().apply(kernel).kernel
        assertEquals(16, rendered.size)
        for (cave in rendered.mapNotNull { it.cave }.distinct()) {
            val base = UltraKernelPlanFixtures.K22_SYMBOL_BASE.getValue(cave)
            val end = requireNotNull(UltraKernelPlanFixtures.symbols().nextOffset(base))
            assertArrayEquals(cave, kernel.copyOfRange(base, end), patched.copyOfRange(base, end))
            assertTrue(rendered.filter { it.cave == cave }.all { it.shiftedFrom == base })
        }
        rendered.forEach { item ->
            assertArrayEquals("orig ${item.role}", kernel.copyOfRange(item.site, item.site + item.original.size), item.original)
        }
    }

    @Test
    fun `no address is left frozen on the reference layout`() {
        assertEquals(
            emptyList<String>(),
            recipe.residue(UltraKernelPlanFixtures.symbols(), UltraKernelPlanFixtures.rendered()),
        )
    }

    @Test
    fun `the site evidence counts all eighteen reference sites`() {
        val match = recipe.generatedCoverage(UltraKernelPlanFixtures.rendered())
        assertEquals(16, match.matching)
        assertEquals(16, match.total)
        assertTrue(match.differingRoles.isEmpty())
    }

    @Test
    fun `the credential slot is declared by the recipe, not guessed`() {
        val kernel = UltraKernelPlanFixtures.syntheticKernel()
        val rendered = UltraKernelPlanFixtures.rendered()
        val index = recipe.credentialRecordIndex()
        assertEquals(12, index)
        assertEquals("panic+0x0", rendered[index].role)
        assertArrayEquals(
            UltraKernelPlanFixtures.credential().copySecret(),
            rendered[index].replacement.copyOfRange(0, UltraKernelCredential.LENGTH),
        )
        assertEquals(listOf(3, 13), recipe.initPathRecordIndices())
        assertTrue(
            "the init path must follow the credential",
            String(rendered[13].replacement, Charsets.US_ASCII)
                .contains(UltraKernelPlanFixtures.credential().key16),
        )
        assertEquals(kernel.size, UltraKernelPlanFixtures.symbols(kernel.size).imageSize)
    }

    @Test
    fun `a missing site symbol is refused with a stable code`() {
        val withoutDie = UltraKernelPlanFixtures.K22_SYMBOL_BASE.filterKeys { it != "die" }
        val kernel = UltraKernelPlanFixtures.syntheticKernel()
        try {
            recipe.render(FakeSymbols(withoutDie, kernel.size), kernel, UltraKernelPlanFixtures.credential())
            fail("a recipe whose anchor symbol is gone must not render")
        } catch (expected: UltraKernelGenerateException) {
            assertEquals(UltraKernelGenerateCodes.SITE_SYMBOL_MISSING, expected.code)
            assertTrue(expected.detail.contains("die"))
        }
    }

    @Test
    fun `a missing relocation target is refused with a stable code`() {
        val withoutModuleAlloc = UltraKernelPlanFixtures.K22_SYMBOL_BASE.filterKeys { it != "module_alloc" }
        val kernel = UltraKernelPlanFixtures.syntheticKernel()
        try {
            recipe.render(FakeSymbols(withoutModuleAlloc, kernel.size), kernel, UltraKernelPlanFixtures.credential())
            fail("a recipe whose relocation target is gone must not render")
        } catch (expected: UltraKernelGenerateException) {
            assertEquals(UltraKernelGenerateCodes.TARGET_SYMBOL_MISSING, expected.code)
            assertEquals("module_alloc", expected.detail)
        }
    }

    @Test
    fun `kallsyms refuses an image it cannot walk, with one stable code`() {
        try {
            UltraKernelKallsymsTable.decode(ByteArray(4096))
            fail("a buffer that is not an arm64 Image must not decode")
        } catch (expected: UltraKernelGenerateException) {
            assertEquals(UltraKernelGenerateCodes.KALLSYMS, expected.code)
        }
        val armMagic = ByteArray(4096)
        "ARMd".toByteArray(Charsets.US_ASCII).copyInto(armMagic, 56)
        try {
            UltraKernelKallsymsTable.decode(armMagic)
            fail("an arm64 header with no kallsyms must not decode")
        } catch (expected: UltraKernelGenerateException) {
            assertEquals(UltraKernelGenerateCodes.KALLSYMS, expected.code)
        }
    }

    @Test
    fun `branch encoding keeps b and bl apart`() {
        val here = 0x1000L
        val target = 0x2000L
        val branch = UltraKernelA64.encodeB(here, target)
        val call = UltraKernelA64.encodeBl(here, target)
        assertEquals(0x14000000, branch and 0xFC000000.toInt())
        assertEquals(0x94000000.toInt(), call and 0xFC000000.toInt())
        assertTrue(UltraKernelA64.isBl(call))
        assertTrue(!UltraKernelA64.isBl(branch))
        // A bl masked with 0x7C000000 (bit 31 dropped) equals a plain b - the defect that once
        // encoded every `bl` as a `b`. The two must differ.
        assertTrue(branch != call)
    }

    @Test
    fun `executor uses the native page size in the actual Image flags`() {
        for ((flag, stride) in listOf(1 to 1, 2 to 4, 3 to 16)) {
            val kernel = UltraKernelPlanFixtures.syntheticKernel()
            UltraKernelA64.writeLe32(kernel, 24, (flag shl 1).toLong())
            val executor = recipe.render(UltraKernelPlanFixtures.symbols(kernel.size), kernel,
                UltraKernelPlanFixtures.credential()).single { it.role == "__drm_printfn_coredump+0x0" }
            assertEquals(188, executor.replacement.size)
            assertEquals(UltraKernelA64.addImm(12, 12, stride), UltraKernelA64.le32Bits(executor.replacement, 160))
        }
        val unknown = UltraKernelPlanFixtures.syntheticKernel()
        UltraKernelA64.writeLe32(unknown, 24, 0)
        val error = org.junit.Assert.assertThrows(UltraKernelGenerateException::class.java) {
            recipe.render(UltraKernelPlanFixtures.symbols(unknown.size), unknown, UltraKernelPlanFixtures.credential())
        }
        assertEquals("IMAGE_PAGE_SIZE", error.detail)
    }

    @Test
    fun `imm64 emission honours the declared word count`() {
        assertEquals(1, UltraKernelA64.encodeImm64(13, 0x1).size)
        assertEquals(2, UltraKernelA64.encodeImm64(13, 0x1_0001).size)
        assertEquals(4, UltraKernelA64.encodeImm64(13, 0x1_0001_0001_0001L).size)
        assertEquals(
            "a negative displacement is signalled by its high 16 bit groups (0x0000 groups are dropped)",
            3,
            UltraKernelA64.encodeImm64(13, -0x1_0000_0000L).size,
        )
        assertEquals(0x10000000, UltraKernelA64.encodeAdr(0x1000, 0x1000, 0))
        assertEquals(0x1000L, UltraKernelA64.decodeAdr(0x10000000, 0x1000))
    }
}
