package dev.maplesu.manager.ultrakernel

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

class UltraKernelReleaseEndToEndTest {

    private val sample = File("../MapleSU_Reference/Boots/OnePlusAce6_6.6/boot.img")
    private val assetsRoot = File("src/main/assets")
    private val workspaces = ArrayList<File>()

    @After
    fun cleanup() {
        workspaces.forEach { it.deleteRecursively() }
    }

    private fun workspace(): File =
        UltraKernelReleaseFixtures.tempWorkspace("ultrakernel-e2e").also { workspaces += it }

    @Test
    fun prepareBuildsExperimentalCandidateAndRecognizesItAsInstalled() {
        assumeTrue("6.6.89 boot sample not available", sample.isFile)
        val workspace = workspace()
        val flow = UltraKernelFlow(workspace, UltraKernelFileAssets(assetsRoot))
        val notices = ArrayList<String>()

        val preparation = flow.prepare(sample) { notices += it }
        assertEquals("k22", preparation.variant!!.id)
        val asset = requireNotNull(preparation.variant)
        assertFalse(preparation.alreadyInstalled)
        assertEquals("experimental", preparation.verification)
        assertEquals("ULTRA_KERNEL_ASSET_EXPERIMENTAL:k22", preparation.warning)
        assertTrue(preparation.experimental)
        val spec = UltraKernelSpec.read(File(assetsRoot, "ultra-kernels/k22-ultra-6.6.89.spec"))
        assertEquals(UltraKernelCredential.of(spec.key), preparation.credential)

        val candidate = requireNotNull(preparation.candidate)
        assertEquals(UltraKernelReleaseFixtures.K22_KERNEL, candidate.kernelSha256)
        assertEquals(UltraKernelReleaseFixtures.RELEASE, candidate.kernelRelease)
        assertEquals("experimental", candidate.verification)
        assertEquals("sample", candidate.source)
        assertTrue("base kernel must match the pinned digest", candidate.strictBase)
        assertFalse("the rebuilt container must differ from the input", 
            candidate.bootSha256 == candidate.baseBootSha256)
        assertEquals(UltraKernelReleaseFixtures.IMAGE_SIZE, candidate.image.length())

        // Re-open the candidate exactly like the installer would: the read-back kernel digest is
        // the expected one even though the untouched records are no longer "pristine".
        val readback = flow.inspect(candidate.image, asset)
        assertEquals(UltraKernelReleaseFixtures.K22_KERNEL, readback.kernelSha256)
        assertEquals(UltraKernelReleaseFixtures.RELEASE, readback.kernelRelease)

        val receipt = Json.parseToJsonElement(
            File(workspace, "candidate-k22.json").readText(),
        ).jsonObject
        assertTrue(receipt.getValue("readbackVerified").jsonPrimitive.boolean)
        assertEquals("k22", receipt.getValue("asset").jsonPrimitive.content)
        assertEquals(UltraKernelReleaseFixtures.K22_KERNEL,
            receipt.getValue("patchedKernelSha256").jsonPrimitive.content)

        // The candidate is already patched: a second prepare must stop before a build.
        val again = flow.prepare(candidate.image)
        assertTrue(again.alreadyInstalled)
        assertNull(again.candidate)
        assertEquals("k22", again.variant!!.id)
        assertEquals("A reusable patched image must retain its embedded identity",
            preparation.credential, again.credential)
        val reused = flow.candidateForInstall(candidate.image, again)
        assertEquals(candidate.image, reused.image)
        assertEquals(candidate.bootSha256, reused.bootSha256)
        assertEquals(candidate.kernelSha256, reused.kernelSha256)
        assertEquals(0, reused.differingBytes)
        assertThrows(IllegalStateException::class.java) { flow.candidateForInstall(sample, again) }
    }

    @Test
    fun optionalBaseKernelPinStillRequiresExpectedOutput() {
        assumeTrue("6.6.89 boot sample not available", sample.isFile)
        val workspace = workspace()
        val spec = UltraKernelSpec.read(
            File(assetsRoot, "ultra-kernels/k22-ultra-6.6.89.spec"))
        val asset = UltraKernelReleaseCatalog
            .load(UltraKernelFileAssets(assetsRoot))
            .assetsFor(UltraKernelReleaseFixtures.RELEASE)
            .first { it.id == "k22" }

        val unpinned = asset.copy(
            baseKernelSha256 = "",
            knownBaseImageSha256 = "",
            knownBaseImageBootSha256 = "",
        )
        val candidate = UltraKernelBuilder(workspace).generate(sample, unpinned, spec)
        assertFalse("no pinned base means expected-byte mode", candidate.strictBase)
        assertEquals(UltraKernelReleaseFixtures.K22_KERNEL, candidate.kernelSha256)
        assertEquals(UltraKernelReleaseFixtures.IMAGE_SIZE, candidate.image.length())

        val wrong = unpinned.copy(expectedKernelSha256 = "0".repeat(64))
        val error = assertThrows(IllegalStateException::class.java) {
            UltraKernelBuilder(workspace).generate(sample, wrong, spec)
        }
        assertTrue(error.message!!.startsWith("ULTRA_KERNEL_RESULT_DIGEST_MISMATCH"))
    }

    @Test
    fun experimentalAssetSurfacesWarningThroughPreparation() {
        assumeTrue("6.6.89 boot sample not available", sample.isFile)
        val workspace = workspace()
        val flow = UltraKernelFlow(
            workspace,
            UltraKernelReleaseFixtures.releaseAssets(
                UltraKernelReleaseFixtures.meta(verification = "experimental"),
            ),
        )
        val notices = ArrayList<String>()

        val preparation = flow.prepare(sample) { notices += it }
        assertNotNull(preparation.variant)
        assertTrue(preparation.experimental)
        assertEquals("ULTRA_KERNEL_ASSET_EXPERIMENTAL:k22", preparation.warning)
        assertTrue(notices.contains("ULTRA_KERNEL_ASSET_EXPERIMENTAL:k22"))
    }
}
