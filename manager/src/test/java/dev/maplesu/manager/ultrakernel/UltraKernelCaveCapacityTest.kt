package dev.maplesu.manager.ultrakernel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class UltraKernelCaveCapacityTest {
    private val credential = UltraKernelCredential.of("A".repeat(48))
    private val fields = mapOf(UltraKernelStructOffsets.CRED to 0x820)

    @Test
    fun `a 212 byte body cannot consume a 96 byte symbol`() {
        val kernel = ByteArray(512)
        val symbols = FakeSymbols(mapOf("die" to 64, "next_function" to 160), kernel.size)
        val failure = assertThrows(UltraKernelGenerateException::class.java) {
            recipe().render(symbols, kernel, credential, fields)
        }
        assertEquals("ULTRA_KERNEL_GENERATE_CAVE_TOO_SMALL", failure.code)
        assertTrue(failure.detail.contains("die+0x0:need=212:room=96"))
    }

    @Test
    fun `capacity includes the delta rather than only the record length`() {
        val kernel = ByteArray(512)
        val symbols = FakeSymbols(mapOf("die" to 64, "next_function" to 280), kernel.size)
        val failure = assertThrows(UltraKernelGenerateException::class.java) {
            recipe(delta = 212, length = 16).render(symbols, kernel, credential, fields)
        }
        assertEquals("ULTRA_KERNEL_GENERATE_CAVE_TOO_SMALL", failure.code)
        assertTrue(failure.detail.contains("need=228:room=216"))
    }

    @Test
    fun `a fixed slot declaration cannot bless arbitrary original code`() {
        val kernel = ByteArray(512) { 1 }
        val symbols = FakeSymbols(mapOf("die" to 64, "next_function" to 160), kernel.size)
        val failure = assertThrows(UltraKernelGenerateException::class.java) {
            recipe(space = "slot", expected = "0".repeat(64)).render(symbols, kernel, credential, fields)
        }
        assertEquals("ULTRA_KERNEL_GENERATE_CAVE_TOO_SMALL", failure.code)
    }

    @Test
    fun `an exact declared slot stays at its original address`() {
        val kernel = ByteArray(512)
        val symbols = FakeSymbols(mapOf("die" to 64, "next_function" to 160), kernel.size)
        val expected = UltraKernelRecipe.sha256Of(kernel.copyOfRange(64, 276))
        val rendered = recipe(space = "slot", expected = expected).render(symbols, kernel, credential, fields)
        assertEquals(64, rendered.single().site)
        assertEquals(212, rendered.single().replacement.size)
    }

    private fun recipe(delta: Int = 0, length: Int = 212,
                       space: String = "symbol", expected: String? = null): UltraKernelRecipe {
        val expectation = expected?.let { ",\"slotExpectedSha256\":\"$it\"" }.orEmpty()
        return UltraKernelRecipe.parse("""{
            "schema":1,"id":"capacity","records":[{
                "role":"die+0x0","site":{"symbol":"die","delta":$delta},
                "length":$length,"space":"$space"$expectation,
                "relocs":[{"at":0,"kind":"u16_struct","name":"task_struct.cred"}]
            }]
        }""")
    }
}
