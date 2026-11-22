package com.maplesu.core.ui.util

import dev.maplesu.manager.ultrakernel.withChosenVariant
import dev.maplesu.manager.ultrakernel.UltraKernelSelection
import dev.maplesu.manager.ultrakernel.UltraKernelVariant
import org.junit.Assert.*
import org.junit.Test

class UltraKernelVariantChoiceTest {
    private fun asset(id: String, default: Boolean = false) = UltraKernelVariant(
        id = id,
        label = id,
        summary = "",
        status = "ready",
        reason = "",
        debugOnly = false,
        debugReason = "",
        default = default,
        specAsset = "ultra-kernels/$id.spec",
        specSha256 = "a".repeat(64),
        patches = 18,
        kernelRelease = "6.6.89-android15-8",
        baseKernelSha256 = "b".repeat(64),
        expectedKernelSha256 = "c".repeat(64),
        knownBaseImageSha256 = "d".repeat(64),
        knownBaseImageBootSha256 = "e".repeat(64),
        imageSizeBytes = 4096,
        ramdiskSize = 0,
    )

    private fun selection() = UltraKernelSelection(
        usable = listOf(asset("k22", default = true), asset("k21")),
        rejected = listOf("k20:ULTRA_KERNEL_SPEC_DIGEST_MISMATCH"),
        defaultId = "k22",
    )

    @Test fun explicitlyChoosingTheDefaultNeverKeepsAFallback() {
        val selected = requireNotNull(withChosenVariant(selection(), "k22") {})
        assertEquals(listOf("k22"), selected.usable.map { it.id })
        assertEquals("k22", selected.defaultId)
        assertFalse(selected.fellBack)
    }

    @Test fun explicitlyChoosingTheSecondaryNeverKeepsTheDefault() {
        val notices = mutableListOf<String>()
        val selected = requireNotNull(withChosenVariant(selection(), "k21", notices::add))
        assertEquals(listOf("k21"), selected.usable.map { it.id })
        assertEquals("k21", selected.defaultId)
        assertFalse(selected.fellBack)
        assertTrue(notices.single().contains("k21"))
    }

    @Test fun unknownExplicitIdFailsInsteadOfChoosingAnotherAsset() {
        val failure = assertThrows(IllegalStateException::class.java) {
            withChosenVariant(selection(), "k99") { fail("unknown id must not announce a choice") }
        }
        assertEquals("ULTRA_KERNEL_VARIANT_UNAVAILABLE:k99", failure.message)
    }

    @Test fun blankExplicitIdIsNotTheLegacyNullChoice() {
        val failure = assertThrows(IllegalStateException::class.java) {
            withChosenVariant(selection(), "") {}
        }
        assertEquals("ULTRA_KERNEL_VARIANT_UNAVAILABLE:", failure.message)
    }

    @Test fun noExplicitChoicePreservesTheExactLegacyCatalogAndWarnings() {
        val legacy = selection()
        assertSame(legacy, withChosenVariant(legacy, null) { fail("legacy order is unchanged") })
        assertEquals(listOf("k22", "k21"), legacy.usable.map { it.id })
    }

    @Test fun explicitChoiceKeepsPreviouslyRejectedAssetEvidence() {
        val original = selection()
        val selected = requireNotNull(withChosenVariant(original, "k21") {})
        assertEquals(original.rejected, selected.rejected)
        assertSame(original.usable[1], selected.primary)
        assertEquals(listOf("k22", "k21"), original.usable.map { it.id })
    }

    @Test fun missingCatalogCannotTurnAnExplicitChoiceIntoGeneration() {
        val failure = assertThrows(IllegalStateException::class.java) {
            withChosenVariant(null, "k22") {}
        }
        assertEquals("ULTRA_KERNEL_VARIANT_UNAVAILABLE:k22", failure.message)
    }

    @Test fun noCatalogAndNoExplicitChoicePreservesLegacyGeneration() {
        assertNull(withChosenVariant(null, null) { fail("legacy generation is unchanged") })
    }

    @Test fun rejectedExplicitAssetDoesNotSilentlyChooseTheRemainingAsset() {
        val selected = selection().copy(
            usable = listOf(asset("k21")),
            rejected = listOf("k22:ULTRA_KERNEL_SPEC_DIGEST_MISMATCH"),
        )
        val failure = assertThrows(IllegalStateException::class.java) {
            withChosenVariant(selected, "k22") {}
        }
        assertEquals("ULTRA_KERNEL_VARIANT_UNAVAILABLE:k22", failure.message)
        assertSame(selected, withChosenVariant(selected, null) {})
    }
}
