package dev.maplesu.manager.ultrakernel

import dev.maplesu.image.BootImageInspector
import java.io.File
import java.nio.file.Files
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Replays the app's catalogue-first entry on the reported 6.6.118 image, without flashing. */
class UltraKernelCrossReleaseFlowTest {
    private val sample = File("../Boot_Research/簌/boot.img")
    private val assets = UltraKernelFileAssets(File("src/main/assets"))
    private val credential = UltraKernelCredential.of("Aa1".repeat(16))
    private val workspaces = ArrayList<File>()

    @After
    fun cleanup() {
        workspaces.forEach { it.deleteRecursively() }
    }

    private fun flow(): UltraKernelFlow {
        assumeTrue("reported 6.6.118 boot sample not available", sample.isFile)
        val workspace = Files.createTempDirectory("ultrakernel-cross-release-").toFile()
        workspaces += workspace
        return UltraKernelFlow(workspace, assets)
    }

    @Test
    fun differentBuildOfTheSameSeriesGeneratesFromTheActualImage() {
        val flow = flow()
        val before = UltraKernelSpec.sha256(sample)
        val selection = requireNotNull(flow.selectForRelease(flow.releaseOf(sample)))
        assertTrue(selection.usable.all { !flow.inspect(sample, it).pristine })

        val preparation = flow.prepare(sample, credential)
        assertFalse(preparation.alreadyInstalled)
        assertTrue(preparation.generated)
        assertEquals("EXPERIMENTAL", preparation.supportLevel)
        assertEquals("16/16", preparation.siteMatch)
        assertEquals(flow.generatePlan(sample, credential).credential, preparation.credential)
        val candidate = requireNotNull(preparation.candidate)
        assertEquals(sample.length(), candidate.image.length())
        assertEquals(flow.releaseOf(sample), candidate.kernelRelease)
        assertEquals(candidate.bootSha256, BootImageInspector.inspect(candidate.image).sha256)
        assertEquals(flow.generatePlan(sample, credential).derived?.patchedKernelSha256,
            candidate.kernelSha256)
        assertEquals(before, UltraKernelSpec.sha256(sample))
    }

    @Test
    fun aPinnedK22CandidateUsesThePreparedDeviceIdentity() {
        val (flow, selection) = pinnedFixture()
        var reads = 0
        val prepared = flow.prepare(sample, selection, { reads++; credential }) {}
        assertEquals(1, reads)
        assertEquals(flow.generatePlan(sample, credential).credential, prepared.credential)
        assertTrue(prepared.generated)
        val candidate = requireNotNull(prepared.candidate)
        assertEquals(candidate.bootSha256, BootImageInspector.inspect(candidate.image).sha256)
        val again = flow.prepare(candidate.image, selection, { credential }) {}
        assertTrue(again.alreadyInstalled)
        assertEquals(prepared.credential, again.credential)
    }

    @Test
    fun aPinnedK22DigestFailureDoesNotPrepareAnotherIdentity() {
        val (flow, selection) = pinnedFixture()
        val asset = (selection.primary as UltraKernelReleaseAsset).copy(expectedKernelSha256 = "0".repeat(64))
        assertThrows(IllegalStateException::class.java) {
            flow.prepare(sample, selection.copy(usable = listOf(asset)), {
                error("invalid pinned output must fail before identity generation")
            }) {}
        }
    }

    @Test
    fun aPreparedIdentityFailureNeverFallsBackToAnotherAssetsKey() {
        val (flow, selection) = pinnedFixture()
        val fallback = (selection.primary as UltraKernelReleaseAsset).copy(id = "k21")
        val failure = assertThrows(IllegalStateException::class.java) {
            flow.prepare(sample, selection.copy(usable = selection.usable + fallback), {
                error("ULTRA_KERNEL_CREDENTIAL_STORE_FAILED")
            }) {}
        }
        assertEquals("ULTRA_KERNEL_CREDENTIAL_STORE_FAILED", failure.message)
    }

    private fun pinnedFixture(): Pair<UltraKernelFlow, UltraKernelSelection> {
        val base = flow()
        val plan = base.generatePlan(sample, UltraKernelCredential.of("Bb2".repeat(16)))
        val spec = plan.specText(plan.credential).toByteArray()
        val report = BootImageInspector.inspect(sample)
        val source = object : UltraKernelAssetSource by assets {
            override fun read(path: String) = if (path == "fixture.spec") spec else assets.read(path)
        }
        val selection = requireNotNull(base.selectForRelease(base.releaseOf(sample)))
        val asset = (selection.primary as UltraKernelReleaseAsset).copy(
            id = "k22", specAsset = "fixture.spec", specSha256 = UltraKernelSpec.sha256(spec),
            kernelRelease = plan.kernelRelease, baseKernelSha256 = plan.baseKernelSha256,
            expectedKernelSha256 = requireNotNull(plan.derived).patchedKernelSha256,
            knownBaseImageSha256 = "", knownBaseImageBootSha256 = "",
            patches = plan.records.size, imageSizeBytes = report.fileSize, ramdiskSize = report.ramdiskSize,
        )
        val workspace = Files.createTempDirectory("ultrakernel-pinned-identity-").toFile()
        workspaces += workspace
        return UltraKernelFlow(workspace, source) to selection.copy(usable = listOf(asset))
    }

    @Test
    fun missingCredentialReportsTheActualGenerationPrerequisite() {
        val flow = flow()
        val failure = assertThrows(UltraKernelCredentialRequiredException::class.java) {
            flow.prepare(sample, null as UltraKernelCredential?)
        }
        assertTrue(failure.message.orEmpty().startsWith("ULTRA_KERNEL_CREDENTIAL_REQUIRED:"))
    }

    @Test
    fun assetOnlyEntryStillRejectsTheMismatchingStaticRecords() {
        val flow = flow()
        val selection = requireNotNull(flow.selectForRelease(flow.releaseOf(sample)))
        val failure = assertThrows(IllegalStateException::class.java) {
            flow.prepare(sample, selection) {}
        }
        assertTrue(failure.message.orEmpty().startsWith("ULTRA_KERNEL_ALL_VARIANTS_FAILED:"))
        assertNotNull(selection.usable.firstOrNull { it.id == "k22" })
    }

    @Test
    fun explicitlySelectedK22UsesTheSameGeneratedPathAsTheApp() {
        val flow = flow()
        val selection = requireNotNull(flow.selectForRelease(flow.releaseOf(sample)))
        val chosen = selection.copy(usable = selection.usable.filter { it.id == "k22" })
        var credentialReads = 0
        val preparation = flow.prepare(sample, chosen, {
            credentialReads++
            credential
        }) {}
        assertTrue(preparation.generated)
        assertNotNull(preparation.candidate)
        assertEquals(1, credentialReads)
    }

    @Test
    fun explicitlySelectedK21DoesNotSilentlyBecomeTheK22Recipe() {
        val flow = flow()
        val selection = requireNotNull(flow.selectForRelease(flow.releaseOf(sample)))
        val chosen = selection.copy(usable = selection.usable.filter { it.id == "k21" })
        val failure = assertThrows(IllegalStateException::class.java) {
            flow.prepare(sample, chosen, { error("k21 must not request a k22 credential") }) {}
        }
        assertTrue(failure.message.orEmpty().startsWith("ULTRA_KERNEL_ALL_VARIANTS_FAILED:"))
    }

    @Test
    fun aRejectedSiblingDoesNotBlockIndependentK22Generation() {
        val flow = flow()
        val selection = requireNotNull(flow.selectForRelease(flow.releaseOf(sample))).copy(
            rejected = listOf("fixture:ULTRA_KERNEL_SPEC_DIGEST_MISMATCH"),
        )
        val notices = ArrayList<String>()
        val preparation = flow.prepare(sample, selection, { credential }, notices::add)
        assertTrue(preparation.generated)
        assertNotNull(preparation.candidate)
        assertEquals(flow.generatePlan(sample, credential).credential, preparation.credential)
        assertTrue(notices.any { it.contains("fixture:ULTRA_KERNEL_SPEC_DIGEST_MISMATCH") })
    }

    @Test
    fun aRejectedSiblingDoesNotSkipPinnedK22IdentityBinding() {
        val (flow, selected) = pinnedFixture()
        val selection = selected.copy(rejected = listOf("fixture:ULTRA_KERNEL_SPEC_DIGEST_MISMATCH"))
        var reads = 0
        val preparation = flow.prepare(sample, selection, { reads++; credential }) {}
        assertEquals(1, reads)
        assertTrue(preparation.generated)
        assertEquals(flow.generatePlan(sample, credential).credential, preparation.credential)
        val candidate = requireNotNull(preparation.candidate)
        val again = flow.prepare(candidate.image, selection, { credential }) {}
        assertTrue(again.alreadyInstalled)
        assertEquals(preparation.credential, again.credential)
    }
}
