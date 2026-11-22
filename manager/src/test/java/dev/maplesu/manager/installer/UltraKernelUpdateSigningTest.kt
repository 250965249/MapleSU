package dev.maplesu.manager.installer

import dev.maplesu.image.LenovoAvbSigner
import org.junit.Assert.*
import org.junit.Test

class UltraKernelUpdateSigningTest {
    @Test fun withoutAnInstalledReceiptTheInstallPageFingerprintDefaultIsPreserved() {
        assertTrue(kernelUpdateSigningOptions("LENOVO/device/build", null).enabled)
        assertTrue(kernelUpdateSigningOptions("lenovo/device", null).enabled)
        assertFalse(kernelUpdateSigningOptions("OnePlus/device", null).enabled)
        assertFalse(kernelUpdateSigningOptions(null, null).enabled)
    }

    @Test fun aMatchingInstalledReceiptPreservesAllPreviousSigningChoices() {
        val aosp = kernelUpdateSigningOptions("custom/device", "AOSP")
        assertTrue(aosp.enabled)
        assertEquals(LenovoAvbSigner.Mode.AOSP, aosp.mode("boot"))
        assertEquals(listOf("recovery", "vbmeta_system", "vbmeta"), aosp.requiredImages("boot"))
        val chained = kernelUpdateSigningOptions("custom/device", "CHAINED")
        assertTrue(chained.enabled)
        assertEquals(LenovoAvbSigner.Mode.CHAINED, chained.mode("boot"))
        assertFalse(kernelUpdateSigningOptions("LENOVO/device", "").enabled)
    }

    @Test fun anInvalidInstalledBootModeFailsBeforeAnyUnsignedFallback() {
        assertThrows(IllegalStateException::class.java) { kernelUpdateSigningOptions("LENOVO/device", "NON_CHAINED") }
        assertThrows(IllegalStateException::class.java) { kernelUpdateSigningOptions("custom/device", "invalid") }
    }

    @Test fun switchSigningChoicesRequireTheCurrentSlotAndCompletePartitionDigest() {
        val current = current()
        for (mode in listOf("", "CHAINED", "AOSP")) {
            val matched = matchingSwitchSigningMode("boot", "_a", "a".repeat(64), mode, current)
            assertEquals(mode, matched)
            assertEquals(mode.isNotEmpty(), switchSigningOptions("LENOVO/device", matched).enabled)
        }
        for ((partition, slot, sha) in listOf(Triple("boot", "_b", "a".repeat(64)),
            Triple("boot", "_a", "b".repeat(64)), Triple("init_boot", "_a", "a".repeat(64)),
            Triple("boot", "_a", ""))) {
            assertNull(matchingSwitchSigningMode(partition, slot, sha, "AOSP", current))
        }
        assertFalse(switchSigningOptions("other/device", null).enabled)
        assertTrue(switchSigningOptions("LENOVO/device", null).enabled)
    }

    @Test fun switchSigningKeepsEnablementWhileTheResolvedTargetChoosesItsMode() {
        val installed = matchingSwitchSigningMode("init_boot", "_a", "c".repeat(64), "NON_CHAINED", current())
        val options = switchSigningOptions("custom/device", installed)
        assertTrue(options.enabled)
        assertEquals(LenovoAvbSigner.Mode.NON_CHAINED, options.mode("init_boot"))
        assertEquals(LenovoAvbSigner.Mode.CHAINED, options.mode("boot"))
        assertEquals(LenovoAvbSigner.Mode.NON_CHAINED, switchSigningOptions("custom/device", "AOSP").mode("init_boot"))
        assertThrows(IllegalStateException::class.java) {
            matchingSwitchSigningMode("boot", "_a", "a".repeat(64), "NON_CHAINED", current())
        }
        assertThrows(IllegalStateException::class.java) {
            matchingSwitchSigningMode("init_boot", "_a", "c".repeat(64), "AOSP", current())
        }
    }

    private fun current() = InstallerSnapshot("6.1.1-android14", "fixture", "_a", "Enforcing",
        listOf("boot" to "a", "init_boot" to "c").associate { (name, digest) ->
            name to BootPartitionSnapshot(name, "/dev/block/by-name/${name}_a", "/dev/block/$name", 4096, digest.repeat(64))
        })
}
