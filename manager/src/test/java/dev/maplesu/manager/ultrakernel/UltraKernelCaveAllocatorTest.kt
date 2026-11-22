package dev.maplesu.manager.ultrakernel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class UltraKernelCaveAllocatorTest {
    @Test
    fun `a movable metadata slot does not require its historical host function`() {
        val kernel = ByteArray(1024)
        val symbols = Symbols(mapOf("_stext" to 32, "next_function" to 400, "_etext" to 768))
        val allocation = UltraKernelCaveAllocator.allocate(
            recipe(212, space = "slot", expected = "0".repeat(64)), symbols, kernel)
        val placement = allocation.placements.getValue("die")
        assertTrue(placement.base in 32..556)
        assertTrue(placement.shifted)
        assertEquals(null, placement.shiftedFrom)
        assertEquals(placement.base, allocation.symbols.offsetOf("die"))
        assertTrue(kernel.all { it == 0.toByte() })
    }

    @Test
    fun `a missing fixed hook is still required when a movable host is absent`() {
        val recipe = UltraKernelRecipe.parse("""{
            "schema":1,"id":"missing-hook","records":[
              {"role":"data","site":{"symbol":"absent_host","delta":0},
               "length":16,"space":"slot","slotExpectedSha256":"${"0".repeat(64)}","cave":"absent_host"},
              {"role":"hook","site":{"symbol":"absent_hook","delta":0},"length":4}
            ]
        }""")
        val failure = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelCaveAllocator.allocate(recipe, symbols(), ByteArray(1024))
        }
        assertEquals(UltraKernelGenerateCodes.SITE_SYMBOL_MISSING, failure.code)
        assertEquals("hook:absent_hook", failure.detail)
    }

    @Test
    fun `an absent movable host still requires valid padding`() {
        val failure = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelCaveAllocator.allocate(recipe(212, space = "slot", expected = "0".repeat(64)),
                Symbols(mapOf("_stext" to 32, "_etext" to 768)), ByteArray(1024) { 1 })
        }
        assertEquals(UltraKernelGenerateCodes.CAVE_UNAVAILABLE, failure.code)
    }

    @Test
    fun `functions retain their code even when their capacity is sufficient`() {
        val kernel = ByteArray(1024)
        val values = mapOf("_text" to 0, "_stext" to 32, "die" to 64,
            "next_function" to 400, "_etext" to 768)
        val placement = UltraKernelCaveAllocator.allocate(recipe(212), Symbols(values), kernel)
            .placements.getValue("die")
        assertTrue("existing functions are still CFI/BTI call targets", placement.shifted)
        assertTrue(placement.base >= 400)
    }

    @Test
    fun `nop alternative replacement instructions are live source bytes not padding`() {
        val kernel = ByteArray(1024) { 1 }
        for (offset in 64 until 192 step 4) {
            UltraKernelA64.writeLe32(kernel, offset, UltraKernelA64.NOP.toLong())
        }
        UltraKernelA64.writeLe32(kernel, 800, (400 - 800).toLong())
        UltraKernelA64.writeLe32(kernel, 804, (64 - 804).toLong())
        kernel[810] = 128.toByte()
        kernel[811] = 128.toByte()
        val symbols = Symbols(mapOf("_text" to 0, "_stext" to 32,
            "die" to 256, "next_function" to 300, "_etext" to 768,
            "__alt_instructions" to 800, "__alt_instructions_end" to 812))
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelCaveAllocator.allocate(recipe(64), symbols, kernel)
        }
        assertEquals(UltraKernelGenerateCodes.CAVE_UNAVAILABLE, error.code)
    }

    @Test
    fun `padding before stext is an image header not a runtime cave`() {
        val kernel = ByteArray(1024)
        val symbols = Symbols(mapOf(
            "_text" to 0, "_stext" to 512, "die" to 64,
            "next_function" to 160, "_etext" to 1024,
        ))
        val placement = UltraKernelCaveAllocator.allocate(recipe(212), symbols, kernel)
            .placements.getValue("die")
        assertTrue("the runtime cave must be in executable text", placement.base >= 512)
    }

    @Test
    fun `a collapsed symbol is moved into zero and nop padding as one group`() {
        val kernel = ByteArray(1024)
        for (offset in 640 until 1024 step 4) {
            UltraKernelA64.writeLe32(kernel, offset, UltraKernelA64.NOP.toLong())
        }
        val symbols = Symbols(
            mapOf(
                "_text" to 0,
                "die" to 64,
                "next_function" to 160,
                "_etext" to 1024,
            ),
        )
        val allocation = UltraKernelCaveAllocator.allocate(recipe(span = 212), symbols, kernel)
        val placement = allocation.placements.getValue("die")
        assertTrue(placement.shifted)
        assertNotEquals(64, placement.base)
        assertTrue(placement.base >= 276)
        assertTrue(placement.span.contains(placement.base, placement.base + 212))
        assertEquals(placement.base, allocation.siteByRole.getValue("die+0x0"))
        assertTrue((placement.base until placement.base + 212 step 4).all { offset ->
            val word = UltraKernelA64.le32Bits(kernel, offset)
            word == 0 || word == UltraKernelA64.NOP
        })
    }

    @Test
    fun `no padding produces the stable unavailable code`() {
        val kernel = ByteArray(1024) { 1 }
        val failure = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelCaveAllocator.allocate(recipe(span = 212), symbols(), kernel)
        }
        assertEquals(UltraKernelGenerateCodes.CAVE_UNAVAILABLE, failure.code)
        assertTrue(failure.detail.contains("die:need=212"))
    }

    @Test
    fun `records sharing a cave keep their relative layout after the move`() {
        val kernel = ByteArray(1024)
        for (offset in 640 until 1024 step 4) {
            UltraKernelA64.writeLe32(kernel, offset, UltraKernelA64.NOP.toLong())
        }
        val recipe = UltraKernelRecipe.parse("""{
            "schema":1,"id":"group","records":[
              {"role":"die+0x0","site":{"symbol":"die","delta":0},"length":212,
               "space":"symbol","cave":"die"},
              {"role":"die+0xD4","site":{"symbol":"die","delta":212},"length":16,
               "space":"symbol","cave":"die"}
            ]
        }""")
        val allocation = UltraKernelCaveAllocator.allocate(recipe, symbols(), kernel)
        val first = allocation.siteByRole.getValue("die+0x0")
        val tail = allocation.siteByRole.getValue("die+0xD4")
        assertEquals(212, tail - first)
        assertEquals(first, allocation.placements.getValue("die").base)
        assertTrue(allocation.placements.getValue("die").shifted)
    }

    @Test
    fun `padding overlapping the original record is never reused`() {
        val kernel = ByteArray(276)
        val failure = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelCaveAllocator.allocate(recipe(span = 212), symbols(etext = 276), kernel)
        }
        assertEquals(UltraKernelGenerateCodes.CAVE_UNAVAILABLE, failure.code)
    }

    @Test
    fun `a padding run containing a non zero non nop byte is rejected`() {
        val kernel = ByteArray(1024) { 1 }
        kernel.fill(0, 300, 500)
        kernel.fill(0, 700, 900)
        val failure = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelCaveAllocator.allocate(recipe(span = 212), symbols(), kernel)
        }
        assertEquals(UltraKernelGenerateCodes.CAVE_UNAVAILABLE, failure.code)
    }

    @Test
    fun `aarch64 branch range includes minus 128 mib and rejects the first out of range target`() {
        assertTrue(UltraKernelCaveAllocator.withinBranchRange(0, 128L * 1024 * 1024 - 4))
        assertTrue(UltraKernelCaveAllocator.withinBranchRange(128L * 1024 * 1024, 0))
        assertFalse(UltraKernelCaveAllocator.withinBranchRange(0, 128L * 1024 * 1024))
        assertFalse(UltraKernelCaveAllocator.withinBranchRange(0, 128L * 1024 * 1024 + 4))
    }

    @Test
    fun `a matching digest does not make an exception function unused`() {
        val kernel = ByteArray(512)
        val original = kernel.copyOfRange(64, 276)
        val expected = UltraKernelRecipe.sha256Of(original)
        val allocation = UltraKernelCaveAllocator.allocate(
            recipe(span = 212, space = "slot", expected = expected), symbols(), kernel,
        )
        val placement = allocation.placements.getValue("die")
        assertTrue(placement.shifted)
        assertNotEquals(64, placement.base)
    }

    @Test
    fun `an alternate digest still preserves the original exception function`() {
        val kernel = ByteArray(512)
        val accepted = UltraKernelRecipe.sha256Of(kernel.copyOfRange(64, 276))
        val allocation = UltraKernelCaveAllocator.allocate(
            recipe(
                span = 212,
                space = "slot",
                expected = "0".repeat(64),
                accepted = listOf(accepted),
            ),
            symbols(),
            kernel,
        )
        assertTrue(allocation.placements.getValue("die").shifted)
    }

    @Test
    fun `a cave with a static key patch site moves even when the function is large enough`() {
        val kernel = ByteArray(1024)
        UltraKernelA64.writeLe32(kernel, 800, (100 - 800).toLong())
        UltraKernelA64.writeLe32(kernel, 804, (300 - 804).toLong())
        val symbols = Symbols(mapOf("_text" to 0, "_stext" to 32,
            "die" to 64, "next_function" to 400, "_etext" to 768,
            "__start___jump_table" to 800, "__stop___jump_table" to 816))
        val placement = UltraKernelCaveAllocator.allocate(recipe(212), symbols, kernel)
            .placements.getValue("die")
        assertTrue("jump_label_init would overwrite shellcode", placement.shifted)
    }

    @Test
    fun `alternative instruction slots are excluded from both fixed and padding caves`() {
        val kernel = ByteArray(1024)
        UltraKernelA64.writeLe32(kernel, 800, (100 - 800).toLong())
        kernel[810] = 4
        val symbols = Symbols(mapOf("_text" to 0, "_stext" to 32,
            "die" to 64, "next_function" to 400, "_etext" to 768,
            "__alt_instructions" to 800, "__alt_instructions_end" to 812))
        val placement = UltraKernelCaveAllocator.allocate(recipe(212), symbols, kernel)
            .placements.getValue("die")
        assertTrue(placement.shifted)
        assertFalse(placement.span.contains(100, 104))
    }

    @Test
    fun `a fixed hook overlapping runtime patching is rejected`() {
        val kernel = ByteArray(1024)
        UltraKernelA64.writeLe32(kernel, 800, (64 - 800).toLong())
        val symbols = Symbols(mapOf("_text" to 0, "die" to 64, "next" to 400,
            "_etext" to 768, "__start___jump_table" to 800, "__stop___jump_table" to 816))
        val hook = UltraKernelRecipe.parse("""{
            "schema":1,"id":"fixed","records":[{
              "role":"hook","site":{"symbol":"die","delta":0},"length":4
            }]
        }""")
        val failure = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelCaveAllocator.allocate(hook, symbols, kernel)
        }
        assertTrue(failure.detail.startsWith("RUNTIME_PATCH_CONFLICT:"))
    }

    @Test
    fun `an encoded identity places metadata at its original locator`() {
        val allocation = UltraKernelCaveAllocator.allocate(identityRecipe(), identitySymbols(),
            ByteArray(1024), metadataDisplacement = 200)
        val call = allocation.siteByRole.getValue("executor") + UltraKernelBodies.EXECUTOR_CALL_OFFSET
        assertEquals(200, allocation.siteByRole.getValue("free_initmem+0x0") + 4 - call)
    }

    @Test
    fun `identity metadata placement rejects another allocated cave`() {
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelCaveAllocator.allocate(identityRecipe(), identitySymbols(), ByteArray(1024),
                metadataDisplacement = -32)
        }
        assertEquals(UltraKernelGenerateCodes.CAVE_UNAVAILABLE, error.code)
    }

    @Test
    fun `identity metadata placement rejects a live dynamic patch slot`() {
        val kernel = ByteArray(1024)
        UltraKernelA64.writeLe32(kernel, 900, (724 - 900).toLong())
        val symbols = identitySymbols(mapOf("__start___jump_table" to 900,
            "__stop___jump_table" to 916))
        val error = assertThrows(UltraKernelGenerateException::class.java) {
            UltraKernelCaveAllocator.allocate(identityRecipe(), symbols, kernel,
                metadataDisplacement = 200)
        }
        assertEquals(UltraKernelGenerateCodes.CAVE_UNAVAILABLE, error.code)
        assertEquals(0, UltraKernelA64.le32Bits(kernel, 724))
    }

    private fun identityRecipe() = UltraKernelRecipe.parse("""{
        "schema":1,"id":"identity","records":[
          {"role":"free_initmem+0x0","site":{"symbol":"free_initmem","delta":0},
           "length":58,"cave":"free_initmem"},
          {"role":"executor","site":{"symbol":"executor","delta":0},
           "length":188,"code":"printfn-bracket","cave":"executor"}
        ]
    }""")

    private fun identitySymbols(extra: Map<String, Int> = emptyMap()) = Symbols(mapOf(
        "_stext" to 32, "free_initmem" to 64, "executor" to 128, "next" to 400,
        "_etext" to 880,
    ) + extra)

    private fun recipe(
        span: Int,
        space: String = "symbol",
        expected: String? = null,
        accepted: List<String> = emptyList(),
    ): UltraKernelRecipe {
        val expectation = expected?.let { ",\"slotExpectedSha256\":\"$it\"" }.orEmpty()
        val alternatives = if (accepted.isEmpty()) "" else
            ",\"slotAcceptedSha256\":[" + accepted.joinToString(",") { "\"$it\"" } + "]"
        return UltraKernelRecipe.parse("""{
            "schema":1,"id":"allocator","records":[{
                "role":"die+0x0","site":{"symbol":"die","delta":0},
                "length":$span,"space":"$space","cave":"die"$expectation$alternatives
            }]
        }""")
    }

    private fun symbols(etext: Int = 1024) = Symbols(
        mapOf(
            "_text" to 0,
            "die" to 64,
            "next_function" to 160,
            "_etext" to etext,
        ),
    )

    private class Symbols(private val values: Map<String, Int>) : UltraKernelSymbols {
        override val imageSize: Int = 1024
        override fun offsetOf(name: String): Int? = values[name]
        override fun isSymbolStart(value: Int): Boolean = values.containsValue(value)
        override fun nextOffset(offset: Int): Int? = values.values.filter { it > offset }.minOrNull()
        override fun nameAt(offset: Int): String? = values.entries.firstOrNull { it.value == offset }?.key
        override fun hasSymbolIn(start: Int, end: Int): Boolean =
            values.values.any { it in start until end }
        override fun nameBefore(offset: Int): String? =
            values.entries.filter { it.value < offset }.maxByOrNull { it.value }?.key
        override val summary: String = "test"
    }
}
