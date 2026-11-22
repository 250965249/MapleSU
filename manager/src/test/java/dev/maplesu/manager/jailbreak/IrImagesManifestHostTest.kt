package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Host regression for the in-kernel route's admission decisions.
 *
 * <p>These run on the JVM, so they assert the decision surface the executor depends
 * on rather than the Android JSON parsing (which has no host implementation):
 *
 * 1. An unadapted kernel must produce `MAPLESU_IR_UNSUPPORTED:<release>` — the exact
 *    string the manual makes a delivery condition — and never a fallback that would
 *    let a provider run with offsets nobody verified.
 * 2. A packaged module without a spec for this release must read as unsupported, not
 *    as "supported with zero specs".
 */
class IrImagesManifestHostTest {

    private val release = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k"
    private val other = "6.6.102-android15-8-g3c2b6d317bae-abogki467167594-lotus-4k"

    private val module = IrImages.Module(
        asset = "maplesu/ir/maplesu_ir.ko",
        sha256 = DIGEST,
        bytes = 13768,
    )

    private fun inventory(vararg specs: IrImages.Spec) =
        IrImages.Inventory(module, specs.associateBy { it.release })

    private fun spec(release: String) = IrImages.Spec(
        release = release,
        asset = "maplesu/ir/$release.ir.spec",
        sha256 = DIGEST,
        bytes = 1031,
        imageSha256 = DIGEST,
        blocks = 3,
    )

    @Test
    fun `a packaged release resolves to its spec`() {
        val inventory = inventory(spec(release))
        assertTrue(inventory.isUsable)
        val found = inventory.specFor(release)
        assertEquals(1031L, found!!.bytes)
        assertEquals(3, found.blocks)
    }

    @Test
    fun `an unadapted release has no spec and the failure names it`() {
        val inventory = inventory(spec(release))
        assertNull(inventory.specFor(other))
        // The manual's C10 code, carrying the release the device actually runs.
        assertEquals("MAPLESU_IR_UNSUPPORTED:$other", IrImages.unsupported(other))
        assertFalse(IrImages.unsupported(other).endsWith(":"))
    }

    @Test
    fun `a module without specs is not usable`() {
        val inventory = inventory()
        assertTrue(inventory.module != null)
        assertFalse(inventory.isUsable)
        assertNull(inventory.specFor(release))
    }

    @Test
    fun `an empty inventory is not usable`() {
        val inventory = IrImages.Inventory(null, emptyMap())
        assertFalse(inventory.isUsable)
        assertTrue(inventory.specs.isEmpty())
        assertNull(inventory.specFor(release))
    }

    /**
     * L3 ABI v1: only a packaged `l3Module` can arm the su gate, and the stage-2 slot
     * must never fall back to the step-3 hook module (that copy lives in the IR/canary
     * slot). These two assertions are the App-side half of that rule; the staging
     * decision itself needs an Android `Context` and is exercised by the dry-run of the
     * staging path and on the device.
     */
    @Test
    fun `an inventory is armed for su only when it packages the l3 module`() {
        val l3 = IrImages.Module(asset = "maplesu/l3/maplesu_l3.ko", sha256 = DIGEST,
            bytes = 16384)
        assertFalse(IrImages.Inventory(module, mapOf(release to spec(release))).hasL3)
        assertTrue(IrImages.Inventory(module, mapOf(release to spec(release)),
            l3Module = l3).hasL3)
        // The absent marker is a value no digest can equal, so it can never be
        // recorded as one.
        assertEquals("", IrImages.L3_ABSENT)
    }

    private companion object {
        const val DIGEST = "346d51ea1f63413ffa5d99c5c426806291af3573f0a1d66a7621c388e835880e"
    }
}
