package dev.maplesu.manager.ultrakernel

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Product policy for the delivery catalogue: k22 ("MapleSU 内核（推荐）") is the default, k21
 * ("兼容内核（回退）") is used only when k22 fails an offline validation, and if both fail the
 * caller must receive no usable variant (fail-closed) with the exact reasons.
 */
class UltraKernelSelectionTest {

    private val release = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k"

    private fun variant(
        id: String,
        default: Boolean,
        status: String = "ready",
        kernelRelease: String = release,
    ) = UltraKernelVariant(
        id = id,
        label = if (default) "MapleSU 内核（推荐）" else "兼容内核（回退）",
        summary = "",
        status = status,
        reason = "",
        debugOnly = false,
        debugReason = "",
        default = default,
        specAsset = "ultra-kernels/$id-ultra-6.6.89.spec",
        specSha256 = "a".repeat(64),
        patches = if (id == "k22") 18 else 17,
        kernelRelease = kernelRelease,
        baseKernelSha256 = "b".repeat(64),
        expectedKernelSha256 = if (id == "k22") "c".repeat(64) else "d".repeat(64),
        knownBaseImageSha256 = "e".repeat(64),
        knownBaseImageBootSha256 = "f".repeat(64),
        imageSizeBytes = 100_663_296,
        ramdiskSize = 0,
    )

    @Test
    fun defaultVariantComesFirstAndOthersFollow() {
        val ordered = orderForRelease(
            listOf(variant("k21", default = false), variant("k22", default = true)), release)
        assertEquals(listOf("k22", "k21"), ordered.map { it.id })
    }

    @Test
    fun unknownReleaseHasNoCandidates() {
        assertTrue(orderForRelease(listOf(variant("k22", default = true)), "6.1.0-other").isEmpty())
    }

    @Test
    fun k22ValidationFailureFallsBackToK21() {
        val ordered = orderForRelease(
            listOf(variant("k21", default = false), variant("k22", default = true)), release)
        val selection = selectUsable(ordered) { current ->
            if (current.id == "k22") "ULTRA_KERNEL_SPEC_DIGEST_MISMATCH:k22" else null
        }
        assertEquals("k21", selection.primary.id)
        assertTrue(selection.fellBack)
        assertEquals(1, selection.rejected.size)
        assertTrue(selection.rejected.single().startsWith("k22:"))
    }

    @Test
    fun rejectingOnlyTheFallbackIsNotAFallback() {
        val ordered = orderForRelease(
            listOf(variant("k21", default = false), variant("k22", default = true)), release)
        val selection = selectUsable(ordered) { current ->
            if (current.id == "k21") "ULTRA_KERNEL_SPEC_DIGEST_MISMATCH:k21" else null
        }
        assertEquals("k22", selection.primary.id)
        assertFalse(selection.fellBack)
    }

    @Test
    fun bothRejectedLeavesNoUsableVariant() {
        val ordered = orderForRelease(
            listOf(variant("k21", default = false), variant("k22", default = true)), release)
        val selection = selectUsable(ordered) { "ULTRA_KERNEL_SPEC_DIGEST_MISMATCH:${it.id}" }
        assertTrue(selection.usable.isEmpty())
        assertEquals(2, selection.rejected.size)
    }

    @Test
    fun manifestMarksK22AsTheDefaultDeliveryVariant() {
        val text = File("src/main/assets/ultra-kernels/manifest.json").readText()
        val k22 = text.substringAfter("\"id\": \"k22\"").substringBefore("\"id\": \"k21\"")
        assertTrue(k22.contains("\"status\": \"ready\""))
        assertTrue(k22.contains("\"debugOnly\": false"))
        assertTrue(k22.contains("\"default\": true"))
        assertTrue(k22.contains("MapleSU 内核（推荐）"))
        val k21 = text.substringAfter("\"id\": \"k21\"")
        assertTrue(k21.contains("\"default\": false"))
        assertTrue(k21.contains("兼容内核（回退）"))
        assertFalse(text.contains("\"id\": \"k23\""))
        assertFalse(text.contains("MapleSU"))
        assertFalse(text.contains("Ultra 内核"))
    }
}
