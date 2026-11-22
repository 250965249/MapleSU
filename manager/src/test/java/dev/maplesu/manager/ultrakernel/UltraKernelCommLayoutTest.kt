package dev.maplesu.manager.ultrakernel

import org.junit.Assert.*
import org.junit.Test

class UltraKernelCommLayoutTest {
    @Test fun `moving comm leaves cred loads in place`() {
        val symbols = UltraKernelSymbolResolver(UltraKernelPlanFixtures.symbols())
        val body = UltraKernelBodies.generate("printk-flush", 0x8FCF7C, symbols,
            UltraKernelFields(cred = 0x820, comm = 0x870, credEuid = 24)).bytes
        val loads = (body.indices step 4).map { UltraKernelA64.le32Bits(body, it) }
            .filter { it and 0xFFC003FF.toInt() == 0xF940016C.toInt() }
            .map { ((it ushr 10) and 0xFFF) * 8 }
        assertEquals(listOf(0x820, 0x870), loads)
    }

    @Test fun `recipe uses the independently observed process name offset`() {
        val raw = UltraKernelPlanFixtures.syntheticKernel()
        UltraKernelA64.writeLe32(raw, 0x300, UltraKernelA64.addImm(1, 2, 0x870).toLong())
        val plan = UltraKernelPlanFixtures.recipe().render(UltraKernelPlanFixtures.symbols(raw.size),
            raw, UltraKernelPlanFixtures.freshCredential())
        val body = plan.single { it.record.code == "dev-printk" }.replacement
        // Independent decode of LDRB W12, [X16, #comm] immediately after its leading RET.
        val word = UltraKernelA64.le32Bits(body, 4)
        assertEquals(0x3940020C, word and 0xFFC003FF.toInt())
        assertEquals(0x870, (word ushr 10) and 0xFFF)
    }
}
