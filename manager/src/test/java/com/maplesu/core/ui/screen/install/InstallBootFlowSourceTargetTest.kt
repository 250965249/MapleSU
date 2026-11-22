package com.maplesu.core.ui.screen.install

import com.maplesu.core.ui.util.UltraKernelFacts
import com.maplesu.core.ui.util.UltraKernelGeneration
import com.maplesu.core.ui.util.UltraKernelVariantInfo
import java.io.File
import org.junit.After
import org.junit.Assert.*
import org.junit.Test

class InstallBootFlowSourceTargetTest {
    @After fun restorePort() { InstallBootFlow.generation = UltraKernelGeneration.port }

    @Test fun aBrokenRecommendationDoesNotBlockTheTargetRenderer() {
        var calls = 0
        val boot = File("selected-target.img")
        InstallBootFlow.generation = object : UltraKernelGenerationPort {
            override fun plan(image: File?, release: String): UltraKernelGenerationPort.GenerationPlan {
                assertSame(boot, image)
                assertEquals("6.6.89-target", release)
                calls++
                return UltraKernelGenerationPort.GenerationPlan.Available("a".repeat(64), 16)
            }
        }
        val facts = UltraKernelFacts("6.6.89-target",
            variants = listOf(UltraKernelVariantInfo("k21", "legacy", "", 15, true, false)),
            rejected = listOf("k22:ULTRA_KERNEL_SPEC_DIGEST_MISMATCH"), defaultId = "k22")
        val profile = InstallBootFlow.fromFacts("boot.img", "6.12-other", facts, boot)
        assertTrue("historical default must not block target generation: ${profile.stableCode}", profile.selectable)
        assertEquals(InstallBootFlow.GENERATED_VARIANT_ID, profile.target?.id)
        assertEquals(1, calls)
    }

    @Test fun anAvailableRecommendationDoesNotBypassTheTargetRenderer() {
        var calls = 0
        InstallBootFlow.generation = object : UltraKernelGenerationPort {
            override fun plan(boot: File?, release: String): UltraKernelGenerationPort.GenerationPlan {
                calls++
                return UltraKernelGenerationPort.GenerationPlan.Unavailable("ULTRA_KERNEL_TARGET_LAYOUT", "target field missing")
            }
        }
        val facts = UltraKernelFacts("6.6.89-target",
            variants = listOf(UltraKernelVariantInfo("k22", "legacy", "", 16, true, true)), defaultId = "k22")
        val profile = InstallBootFlow.fromFacts("boot.img", "", facts)
        assertEquals("ULTRA_KERNEL_TARGET_LAYOUT", profile.stableCode)
        assertFalse(profile.selectable)
        assertEquals(1, calls)
    }
}
