package dev.maplesu.manager.ultrakernel

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Host-side proof that the *shipped* parser/applier reproduces the pinned Ultra kernels.
 *
 * The reference tool (`UltraBootSpec`) was used to derive the spec; this test drives the same
 * app asset through [UltraKernelSpec], so the Kotlin implementation the device runs is the one
 * being checked. The 36 MB pristine kernel is not in the repository: point
 * `-Dultrakernel.base=/path/to/pristine-kernel.bin` at it (the test is skipped otherwise).
 */
class UltraKernelSpecTest {

    private val assetDir = File("src/main/assets/ultra-kernels")

    private val candidates = listOf(
        System.getProperty("ultrakernel.base") ?: "",
        System.getenv("ULTRAKERNEL_BASE") ?: "",
        // Default location of the pristine kernel extracted from the repacked stock boot.
        "../work/61/spec/srcboot-kernel.bin",
    )

    private fun baseKernel(): ByteArray? {
        for (path in candidates) {
            if (path.isEmpty()) continue
            val file = File(path)
            if (file.isFile) return file.readBytes()
        }
        return null
    }

    @Test
    fun appliedPatchDetectionUsesTheFinalOverlappingRecordOrder() {
        val base = ByteArray(512)
        "Linux version 6.6.89-fixture (test)".toByteArray().copyInto(base)
        val spec = UltraKernelSpec.parse("#kernel=6.6.89-fixture\n64|00000000|01020304\n66|0000|0908")
        assertFalse(spec.isApplied(base))
        val patched = spec.apply(base).kernel
        assertTrue(spec.isApplied(patched))
        assertFalse(spec.isApplied(patched.copyOf(67)))
        patched[66] = 3
        assertFalse(spec.isApplied(patched))
    }

    @Test
    fun k22SpecReproducesPinnedKernel() {
        val base = baseKernel()
        assumeTrue("pristine kernel not provided", base != null)
        val spec = UltraKernelSpec.read(File(assetDir, "k22-ultra-6.6.89.spec"), base!!)
        assertEquals(16, spec.patches.size)
        assertEquals("6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k", spec.kernelRelease)
        assertEquals("346d51ea1f63413ffa5d99c5c426806291af3573f0a1d66a7621c388e835880e",
            UltraKernelSpec.sha256(base))
        assertTrue(spec.mismatched(base).isEmpty())
        val result = spec.apply(base)
        assertEquals("3a601ef90eab78594ece64767de5cb1176e4ec471729372af08b02c6b04477ab",
            UltraKernelSpec.sha256(result.kernel))
        assertEquals(0, result.outsideSites)
        assertEquals(874, result.differingBytes)
    }

    @Test
    fun k21SpecReproducesPinnedKernel() {
        val base = baseKernel()
        assumeTrue("pristine kernel not provided", base != null)
        val spec = UltraKernelSpec.read(File(assetDir, "k21-ultra-6.6.89.spec"), base!!)
        assertEquals(15, spec.patches.size)
        val result = spec.apply(base)
        assertEquals("6e6a2faa4d6fe0faef98d4cfe5d050a70155e25d1ba4a8127d07b9b534d63602",
            UltraKernelSpec.sha256(result.kernel))
        assertEquals(0, result.outsideSites)
    }

    /** A kernel that is already patched must be refused, not half-patched. */
    @Test
    fun alreadyPatchedKernelIsRejected() {
        val base = baseKernel()
        assumeTrue("pristine kernel not provided", base != null)
        val spec = UltraKernelSpec.read(File(assetDir, "k22-ultra-6.6.89.spec"), base!!)
        val patched = spec.apply(base).kernel
        val reopened = UltraKernelSpec.read(File(assetDir, "k22-ultra-6.6.89.spec"), patched)
        val failed = runCatching { reopened.apply(patched) }.exceptionOrNull()
        assertTrue("expected refusal, got $failed",
            failed is IllegalStateException && failed.message.orEmpty().startsWith("ULTRA_KERNEL_PATCH_ORIGINAL_MISMATCH"))
    }

    @Test
    fun everyPackagedExecutorPublishesInstructionsAcrossCpusBeforeCalling() {
        val release = File(assetDir, "releases/${UltraKernelReleaseFixtures.RELEASE}")
        for (directory in listOf(assetDir, release)) {
            for (name in listOf("k21-ultra-6.6.89.spec", "k22-ultra-6.6.89.spec")) {
                val spec = UltraKernelSpec.read(File(directory, name))
                val publications = spec.patches.flatMap { patch ->
                    val code = patch.replacement
                    (12 until code.size - 3 step 4)
                        .filter { UltraKernelA64.le32Bits(code, it) == UltraKernelA64.blr(10) }
                        .map { offset -> (offset - 12 until offset step 4).map { UltraKernelA64.le32Bits(code, it) } }
                }
                assertEquals("$directory/$name", listOf(listOf(
                    UltraKernelA64.icIalluis(), UltraKernelA64.DSB_ISH, UltraKernelA64.ISB,
                )), publications)
            }
        }
    }

    @Test
    fun specDigestIsPinned() {
        val bytes = File(assetDir, "k22-ultra-6.6.89.spec").readBytes()
        assertEquals("e87e4388917804ad72ce5a41377eaa78e0f29e26a906f9cd9e496100ed7ce1a1",
            UltraKernelSpec.sha256(bytes))
        val k21 = File(assetDir, "k21-ultra-6.6.89.spec").readBytes()
        assertEquals("fef44a1373daf01268b6096a0dbc4b5ee0f96ab3950466c9ac1d43a8b78236cb",
            UltraKernelSpec.sha256(k21))
    }
}
