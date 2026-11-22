package dev.maplesu.manager.installer

import dev.maplesu.image.LenovoAvbSigner
import org.junit.Assert.*
import org.junit.Test

class LenovoSigningOptionsTest {
    @Test fun fingerprintIsOnlyAnOptionalCaseInsensitivePrefixHint() {
        assertTrue(lenovoFingerprint("LENOVO/device/build"))
        assertTrue(lenovoFingerprint("lenovo/device"))
        assertFalse(lenovoFingerprint(null))
        assertFalse(lenovoFingerprint("other/LENOVO"))
    }
    @Test fun fileModeRequiresOnlyTheImagesForTheSelectedSigningFlow() {
        val legacy = LenovoSigningOptions(enabled = true)
        assertEquals(LenovoAvbSigner.Mode.CHAINED, legacy.mode("boot"))
        assertEquals(LenovoAvbSigner.Mode.NON_CHAINED, legacy.mode("init_boot"))
        assertTrue(legacy.fileInputsReady("boot"))
        assertFalse(legacy.fileInputsReady("init_boot"))
        assertEquals(listOf("vbmeta"), legacy.requiredImages("init_boot"))
        val aosp = legacy.copy(aosp = true)
        assertEquals(LenovoAvbSigner.Mode.AOSP, aosp.mode("boot"))
        assertEquals(LenovoAvbSigner.Mode.NON_CHAINED, aosp.mode("init_boot"))
        assertEquals(listOf("recovery", "vbmeta_system", "vbmeta"), aosp.requiredImages("boot"))
        assertFalse(aosp.fileInputsReady("boot"))
        assertEquals(listOf("vbmeta"), aosp.requiredImages("init_boot"))
        assertTrue(LenovoSigningOptions().fileInputsReady("init_boot"))
    }
}
