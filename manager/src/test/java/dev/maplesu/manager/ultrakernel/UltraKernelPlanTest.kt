package dev.maplesu.manager.ultrakernel

import java.io.File
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The credential-slot contract: a Ultra plan must be re-bindable to the user's key, and a plan that
 * baked a key in without declaring it must be refused.
 *
 * Everything here runs on a synthetic kernel plus the *shipped* k22 spec, so no 36 MB image and no
 * device are needed. The point is the two properties that make "generate a spec for any kernel"
 * safe to ship at all:
 *
 *  - re-binding writes exactly the credential slot and the init-path slots, and nothing else;
 *  - the expected digests are *derived* from the records that were actually applied.
 */
class UltraKernelPlanTest {

    private val k22Release = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k"
    private val k22Credential = UltraKernelCredential.of("8eORURvE0cAkp3mlIzCuUsEJrr4OfbjKfT6RvkjeIP6aKm6r")
    private val otherCredential = UltraKernelCredential.of("u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLzdocJ2isAj")
    private val syntheticRelease = "9.9.9-maplesu-test"

    private fun spec(): UltraKernelSpec =
        UltraKernelSpec.read(File("src/main/assets/ultra-kernels/k22-ultra-6.6.89.spec"))

    /** A kernel-shaped buffer: the release string the applier reads, and two record windows. */
    private fun kernel(): ByteArray {
        val bytes = ByteArray(8192)
        "Linux version $syntheticRelease\n".toByteArray(Charsets.US_ASCII).copyInto(bytes, 0x200)
        k22Credential.copySecret().copyInto(bytes, 0x400)
        (k22Credential.initPath + "\u0000").toByteArray(Charsets.US_ASCII).copyInto(bytes, 0x500)
        return bytes
    }

    private fun pathField(credential: UltraKernelCredential, width: Int = 58): ByteArray =
        ByteArray(width).also { blob ->
            (credential.initPath + "\u0000").toByteArray(Charsets.US_ASCII).copyInto(blob, 0)
        }

    private fun plan(): UltraKernelPlan {
        val source = kernel()
        val records = listOf(
            UltraKernelPlan.PatchRecord(
                "panic+0x0", 0x400L,
                source.copyOfRange(0x400, 0x400 + UltraKernelCredential.LENGTH),
                source.copyOfRange(0x400, 0x400 + UltraKernelCredential.LENGTH),
            ),
            UltraKernelPlan.PatchRecord(
                "free_initmem+0x0", 0x500L,
                source.copyOfRange(0x500, 0x500 + 58),
                pathField(k22Credential),
            ),
        )
        return UltraKernelPlan.fromRecords(syntheticRelease, records, k22Credential)
    }

    @Test
    fun `rebind writes only the credential and init path bytes`() {
        val original = plan()
        val rebound = original.rebind(otherCredential)
        assertEquals(original.records.size, rebound.records.size)
        original.records.forEachIndexed { index, before ->
            val after = rebound.records[index]
            assertEquals(before.offset, after.offset)
            assertEquals("record length must not change", before.length, after.length)
            assertArrayEquals("orig must never change", before.original, after.original)
        }
        assertArrayEquals(
            otherCredential.copySecret(),
            rebound.records[0].replacement.copyOfRange(0, UltraKernelCredential.LENGTH),
        )
        val expectedPath = (otherCredential.initPath + "\u0000").toByteArray(Charsets.US_ASCII)
        assertArrayEquals(
            expectedPath,
            rebound.records[1].replacement.copyOfRange(0, expectedPath.size),
        )
        assertEquals(
            "no new bytes may appear past the path",
            0,
            rebound.records[1].replacement.copyOfRange(expectedPath.size, 58).count { it != 0.toByte() },
        )
    }

    @Test
    fun `rebinding to the same key changes nothing and to another key changes only slots`() {
        val source = kernel()
        val identity = plan().rebind(k22Credential).apply(source).derived
        assertEquals("re-binding the key a plan was built for is a no-op", 0, identity.changedBytes)

        val rebound = plan().rebind(otherCredential)
        val changed = rebound.apply(source).derived
        assertTrue("a new key must change the result", changed.changedBytes > 0)
        assertEquals(0, changed.outsideSites)

        val allowed = mutableSetOf<Int>()
        for (index in 0 until UltraKernelCredential.LENGTH) allowed += 0x400 + index
        val pathSize = (otherCredential.initPath + "\u0000").toByteArray(Charsets.US_ASCII).size
        for (index in 0 until pathSize) allowed += 0x500 + index
        val patched = rebound.apply(source)
        val stray = patched.kernel.indices.filter { index ->
            patched.kernel[index] != source[index] && index !in allowed
        }
        assertTrue("bytes changed outside the slots: $stray", stray.isEmpty())
    }

    @Test
    fun `apply fails closed when a record original is absent`() {
        val source = kernel()
        source[0x405] = (source[0x405] + 1).toByte()
        try {
            plan().apply(source)
            fail("a mutated pristine window must be rejected")
        } catch (expected: IllegalStateException) {
            assertTrue(
                "unexpected code: ${expected.message}",
                expected.message.orEmpty().startsWith("ULTRA_KERNEL_PLAN_PATCH_ORIGINAL_MISMATCH"),
            )
        }
    }

    @Test
    fun `the shipped k22 spec is refused when its key is not declared`() {
        try {
            UltraKernelPlan.fromSpec(spec())
            fail("a spec that bakes a 48 character secret in must not pass as slot-free")
        } catch (expected: IllegalStateException) {
            assertEquals("ULTRA_KERNEL_PLAN_SLOT_UNDECLARED", expected.message)
        }
    }

    @Test
    fun `the shipped k22 spec re-binds through exactly three records`() {
        val plan = UltraKernelPlan.fromSpec(spec(), credential = UltraKernelCredential.of(spec().key))
        assertTrue(plan.rebindable)
        assertEquals(16, plan.records.size)

        val rebound = plan.rebind(otherCredential)
        val changed = plan.records.indices.filter { index ->
            !plan.records[index].replacement.contentEquals(rebound.records[index].replacement)
        }
        assertEquals(listOf(3, 12, 13), changed)
        plan.records.forEachIndexed { index, before ->
            val after = rebound.records[index]
            assertEquals("site ${before.role} must not move", before.offset, after.offset)
            assertArrayEquals("orig ${before.role}", before.original, after.original)
        }
        assertArrayEquals(otherCredential.copySecret(), rebound.records[12].replacement)
        assertTrue(
            "the init path must follow the key",
            String(rebound.records[13].replacement, Charsets.US_ASCII)
                .contains(otherCredential.key16),
        )
        assertFalse(
            "the old key must be gone",
            String(rebound.records[12].replacement, Charsets.US_ASCII).contains(k22Credential.key16),
        )
    }

    @Test
    fun `a plan never claims the k22 oracle on another release`() {
        val applied = UltraKernelPlan.planFor(kernel(), k22Credential, plan())
        val derived = applied.derived
        assertTrue("planFor must derive digests", derived != null)
        if (derived == null) return
        assertEquals(0, derived.outsideSites)

        assertTrue(
            "a 9.9.9 plan must not match the 6.6.89 oracle",
            applied.verifyAgainst(UltraKernelPlan.K22_ORACLE, "").isNotEmpty(),
        )
        val matching = UltraKernelPlan.Oracle(
            syntheticRelease, 2, derived.changedBytes, derived.patchedKernelSha256, "",
        )
        assertTrue(
            "the same comparison must pass on its own release",
            applied.verifyAgainst(matching, "").isEmpty(),
        )
        assertEquals(k22Release, UltraKernelPlan.K22_ORACLE.kernelRelease)
    }

    // ---------------------------------------------------------------------------------------
    // The generated-plan contract. These use the shipped k22 spec as the oracle, so the numbers
    // below are the ones the host generator produced for the real boot image.
    // ---------------------------------------------------------------------------------------

    @Test
    fun `a generated plan derives its digests instead of trusting a pin`() {
        val generated = UltraKernelPlanFixtures.k22Plan()
        val derived = generated.derived ?: error("the fixture must be applied")
        assertEquals(16, derived.records)
        assertEquals(UltraKernelPlanFixtures.SYNTHETIC_CHANGED_BYTES, derived.changedBytes)
        assertEquals(UltraKernelPlanFixtures.SYNTHETIC_CHANGED_BYTES, derived.changedBytes)
        assertEquals(0, derived.outsideSites)
        assertEquals(UltraKernelPlanFixtures.SYNTHETIC_PATCHED_SHA256, derived.patchedKernelSha256)
        assertEquals(UltraKernelPlanFixtures.SYNTHETIC_BASE_SHA256, generated.baseKernelSha256)

        // "Derived" must mean *reproducible*: replay the same records through the applier and the
        // digest has to come out identical. A pinned constant would not survive this check.
        val kernel = UltraKernelPlanFixtures.syntheticKernel()
        val replayed = UltraKernelSpec.parse(
            generated.specText(UltraKernelPlanFixtures.credential()),
        ).apply(kernel)
        assertEquals(derived.patchedKernelSha256, UltraKernelSpec.sha256(replayed.kernel))
        assertEquals(derived.changedBytes, replayed.differingBytes)
    }

    @Test
    fun `a generated plan is marked GENERATED and experimental, never verified`() {
        val generated = UltraKernelPlanFixtures.k22Plan()
        assertEquals(UltraKernelPlan.Origin.GENERATED, generated.origin)
        assertEquals(UltraKernelPlan.SupportLevel.EXPERIMENTAL, generated.supportLevel)
        assertTrue(generated.experimental)

        val text = generated.specText(UltraKernelPlanFixtures.credential())
        assertTrue(text.contains("#plan.origin=GENERATED"))
        assertTrue(text.contains("#origin=GENERATED"))
        assertTrue(text.contains("#supportLevel=experimental"))

        // Even a shipped-asset plan refuses to answer "verified" on the plan's behalf: that label
        // belongs to the asset, and this type must not invent it.
        val pinned = UltraKernelPlan.fromSpec(
            UltraKernelPlanFixtures.shippedSpec(), credential = UltraKernelCredential.of(UltraKernelPlanFixtures.shippedSpec().key),
        )
        assertEquals(UltraKernelPlan.SupportLevel.ASSET_DECIDES, pinned.supportLevel)
        assertFalse(pinned.experimental)
    }

    @Test
    fun `re-binding a generated plan touches only the declared slots`() {
        val generated = UltraKernelPlanFixtures.k22Plan()
        val rebound = generated.rebind(UltraKernelPlanFixtures.otherCredential())
        val changed = generated.records.indices.filter { index ->
            !generated.records[index].replacement.contentEquals(rebound.records[index].replacement)
        }
        assertEquals(listOf(3, 12, 13), changed)

        val kernel = UltraKernelPlanFixtures.syntheticKernel()
        val patched = rebound.apply(kernel)
        val allowed = HashSet<Int>()
        generated.records.forEach { record ->
            for (index in 0 until record.replacement.size) allowed += record.offset.toInt() + index
        }
        val stray = patched.kernel.indices.filter { index ->
            patched.kernel[index] != kernel[index] && index !in allowed
        }
        assertTrue("bytes changed outside the declared slots: $stray", stray.isEmpty())
    }
}
