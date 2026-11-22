package dev.maplesu.manager.installer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VivoSingleImageTest {
    @Test fun normalFilePatchDoesNotRequireVendorBoot() {
        assertTrue(VivoCompatibilityInputs().ready(needsInitBoot = false))
    }

    @Test fun ultraKernelPatchWithNoRamdiskDoesNotRequireAnotherImage() {
        assertTrue(VivoCompatibilityInputs().ready(needsInitBoot = true))
    }

    @Test fun bootstrapFailureKeepsItsDiagnosticCode() {
        assertEquals("VR_BOOTSTRAP_RAMDISK_REQUIRED", installerFailureDiagnostic(
            IllegalStateException("VR_BOOTSTRAP_RAMDISK_REQUIRED:private details")))
    }
}
