package dev.maplesu.manager.workmode.switch

import dev.maplesu.manager.workmode.TestFixtures
import dev.maplesu.manager.workmode.detect.Clock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/** 01 §8.1 `BaselineStoreTest`：STALE 判定、import 校验、takeover 禁止晋升。 */
class BaselineStoreTest {
    private val device = DeviceBootFacts(slot = "_a", firmware = "fw-1", kernelRelease = "5.10.101")
    private val clock = Clock { 1_000L }

    private fun store(root: File = TestFixtures.tempDir("baseline").toFile(), deviceFacts: () -> DeviceBootFacts = { device }) =
        FileBaselineStore(root, deviceFacts, clock)

    // ------------------------------------------------------------------ 纯规则

    @Test
    fun presentOkWhenEverythingMatches() {
        val verification = BaselineRules.evaluate(TestFixtures.baselineManifest(), device)
        assertEquals(BaselineState.PRESENT_OK, verification.state)
        assertEquals(null, verification.blocker)
        assertEquals("bl-1", verification.check?.id)
        assertEquals(TestFixtures.hash('e'), verification.check?.bootSha256)
        assertEquals(TestFixtures.hash('f'), verification.check?.initBootSha256)
        assertTrue(verification.check?.clean == true)
    }

    @Test
    fun staleOnSlotChange() {
        val verification = BaselineRules.evaluate(
            TestFixtures.baselineManifest(slot = "_b"),
            device,
        )
        assertEquals(BaselineState.STALE, verification.state)
        assertEquals(BaselineErrors.BASELINE_STALE, verification.blocker)
        assertTrue(verification.mismatch.any { it.startsWith("slot:") })
    }

    @Test
    fun firmwareLabelChangeDoesNotInvalidateVerifiedStock() {
        val verification = BaselineRules.evaluate(
            TestFixtures.baselineManifest(firmware = "fw-2"),
            device,
        )
        assertEquals(BaselineState.PRESENT_OK, verification.state)
        assertTrue(verification.mismatch.isEmpty())
    }

    @Test
    fun installedKernelReleaseDoesNotInvalidateVerifiedStock() {
        val verification = BaselineRules.evaluate(
            TestFixtures.baselineManifest(kernelRelease = "6.1.1"),
            device,
        )
        assertEquals(BaselineState.PRESENT_OK, verification.state)
        assertTrue(verification.mismatch.isEmpty())
    }

    @Test
    fun staleOnShaMismatch() {
        val manifest = TestFixtures.baselineManifest()
        val verification = BaselineRules.evaluate(
            manifest, device,
            shaForPartition = { name -> if (name == "boot") TestFixtures.hash('9') else null },
        )
        assertEquals(BaselineState.STALE, verification.state)
        assertEquals(listOf("sha:boot"), verification.mismatch)
    }

    @Test
    fun staleOnAvbTailNotPreserved() {
        val verification = BaselineRules.evaluate(
            TestFixtures.baselineManifest(avbTailPreserved = false),
            device,
        )
        assertEquals(BaselineState.STALE, verification.state)
        assertTrue(verification.mismatch.any { it.startsWith("avb_tail:") })
    }

    @Test
    fun importRejectsPatchMarkers() {
        val manifest = TestFixtures.baselineManifest(markers = PatchMarkers(liteMarker = true))
        assertEquals(BaselineErrors.BASELINE_UNCLEAN, BaselineRules.validateImport("/tmp/oem.img", manifest))
        assertEquals(
            BaselineErrors.BASELINE_UNCLEAN,
            BaselineRules.validateImport("/tmp/oem.img", TestFixtures.baselineManifest(clean = false)),
        )
    }

    @Test
    fun importRejectsStudyImagesFromAce6() {
        val manifest = TestFixtures.baselineManifest()
        assertTrue(BaselineRules.isStudyImage("D:/images/Ace6/boot.img"))
        assertTrue(BaselineRules.isStudyImage("/repo/.analysis/boot.img"))
        assertEquals(
            BaselineErrors.BASELINE_PROVENANCE_UNKNOWN,
            BaselineRules.validateImport("D:/images/Ace6/boot.img", manifest),
        )
        assertEquals(
            BaselineErrors.BASELINE_PROVENANCE_UNKNOWN,
            BaselineRules.validateImport("/repo/.analysis/boot.img", manifest),
        )
        assertNull(BaselineRules.validateImport("/sdcard/oem-boot.img", manifest))
    }

    @Test
    fun importRejectsUnknownProvenance() {
        val manifest = TestFixtures.baselineManifest(provenance = "UNKNOWN_SOURCE")
        assertEquals(
            BaselineErrors.BASELINE_PROVENANCE_UNKNOWN,
            BaselineRules.validateImport("/sdcard/oem-boot.img", manifest),
        )
    }

    @Test
    fun corruptManifestIsCorrupt() {
        assertEquals(
            BaselineState.CORRUPT,
            BaselineRules.evaluate(TestFixtures.baselineManifest(immutable = false), device).state,
        )
        assertEquals(
            BaselineState.CORRUPT,
            BaselineRules.evaluate(null, device, corruptManifest = true).state,
        )
    }

    @Test
    fun missingIsNeverCaptured() {
        val verification = BaselineRules.evaluate(null, device)
        assertEquals(BaselineState.MISSING_NEVER_CAPTURED, verification.state)
        assertEquals(BaselineErrors.BASELINE_MISSING, verification.blocker)
        assertNull(verification.check)
    }

    @Test
    fun promoteTakeoverForbidden() {
        try {
            BaselineRules.promoteTakeover("takeover-1")
            fail("takeover must never be promoted to baseline")
        } catch (error: IllegalStateException) {
            assertEquals(BaselineErrors.BASELINE_PROMOTION_FORBIDDEN, error.message)
        }
    }

    // ------------------------------------------------------------------ 文件实现

    @Test
    fun selectedInputsAreExplicitOnlyAndDoNotReplaceTheLatestFactoryBackup() {
        val store = store()
        val stock = TestFixtures.baselineManifest()
        assertTrue(store.import(BaselineImportRequest("/selected", stock)) is BaselineResult.Ok)
        val selected = stock.copy(id = "selected-input", createdAt = stock.createdAt + 1,
            provenance = BaselineProvenance.USER_SELECTED, clean = false,
            patchMarkers = PatchMarkers(ksuKo = true))
        assertTrue(store.import(BaselineImportRequest("/selected", selected)) is BaselineResult.Ok)
        assertEquals(BaselineState.IMPORT_REQUIRED, BaselineRules.evaluate(selected, device).state)
        assertEquals(BaselineState.PRESENT_OK, store.verify(selected.id).state)
        assertEquals(false, store.verify(selected.id).check?.clean)
        assertEquals(stock.id, store.verify().id)
        assertEquals(stock.id, store.manifest()?.id)
        assertEquals(stock.id, store.check().id)
    }

    @Test
    fun selectedInputStillChecksSlotAndDigestAndCanReplaceAStaleBackup() {
        val root = TestFixtures.tempDir("selected-input").toFile()
        val store = store(root)
        val selected = TestFixtures.baselineManifest().copy(id = "selected-input",
            provenance = BaselineProvenance.USER_SELECTED, clean = false)
        assertTrue(store.import(BaselineImportRequest("/selected", selected)) is BaselineResult.Ok)
        store.markStale("old stock backup")
        assertEquals(BaselineState.PRESENT_OK, store.verify(selected.id).state)
        assertEquals(BaselineState.STALE, BaselineRules.evaluate(selected, device.copy(slot = "_b"),
            allowUserSelected = true).state)
        File(root, "boot/baseline/${selected.id}/boot.img").writeBytes(byteArrayOf(1))
        assertEquals(BaselineState.STALE, store.verify(selected.id).state)
    }

    @Test
    fun captureThenVerifyPresentOk() {
        val store = store()
        val result = store.capture(BaselineCaptureRequest("bl-1", TestFixtures.baselineManifest()))
        assertTrue(result is BaselineResult.Ok)
        val verification = store.verify("bl-1")
        assertEquals(BaselineState.PRESENT_OK, verification.state)
        assertEquals("bl-1", verification.id)
        assertEquals(1, store.history().size)
    }

    @Test
    fun originalStockIsReusedAcrossUltraAndNormalKernelChanges() {
        val root = TestFixtures.tempDir("baseline-workmodes").toFile()
        var running = device.copy(kernelRelease = "6.6.89-android15-8-stock")
        val store = store(root) { running }
        val boot = "original-boot".toByteArray()
        val initBoot = "original-init-boot".toByteArray()
        val manifest = TestFixtures.baselineManifest(kernelRelease = running.kernelRelease).copy(
            partitions = listOf(
                BaselinePartition("boot", boot.size.toLong(), dev.maplesu.manager.workmode.Hashes.sha256(boot), true),
                BaselinePartition("init_boot", initBoot.size.toLong(), dev.maplesu.manager.workmode.Hashes.sha256(initBoot), true),
            ),
        )
        assertTrue(store.capture(BaselineCaptureRequest(manifest.id, manifest)) is BaselineResult.Ok)
        File(root, "boot/baseline/${manifest.id}/boot.img").writeBytes(boot)
        File(root, "boot/baseline/${manifest.id}/init_boot.img").writeBytes(initBoot)

        for (release in listOf("6.6.101-android15-8-ultra", "6.6.115-android15-8-normal")) {
            running = running.copy(firmware = "reported-$release", kernelRelease = release)
            val verification = store.verify(manifest.id)
            assertEquals(release, BaselineState.PRESENT_OK, verification.state)
            assertEquals(manifest.id, verification.check?.id)
            assertEquals(manifest, store.manifest(manifest.id))
        }
        assertEquals(listOf(manifest), store.history())
    }

    @Test
    fun captureRejectsOverwrite() {
        val store = store()
        assertTrue(store.capture(BaselineCaptureRequest("bl-1", TestFixtures.baselineManifest())) is BaselineResult.Ok)
        val second = store.capture(BaselineCaptureRequest("bl-1", TestFixtures.baselineManifest()))
        assertTrue(second is BaselineResult.Failed)
        assertEquals(BaselineErrors.BASELINE_PROMOTION_FORBIDDEN, (second as BaselineResult.Failed).code)
    }

    @Test
    fun verifyDetectsImageShaMismatch() {
        val root = TestFixtures.tempDir("baseline-sha").toFile()
        val store = store(root)
        assertTrue(store.capture(BaselineCaptureRequest("bl-1", TestFixtures.baselineManifest())) is BaselineResult.Ok)
        File(root, "boot/baseline/bl-1/boot.img").writeBytes(byteArrayOf(1, 2, 3))
        val verification = store.verify("bl-1")
        assertEquals(BaselineState.STALE, verification.state)
        assertTrue(verification.mismatch.contains("sha:boot"))
    }

    @Test
    fun markStaleForcesStaleState() {
        val store = store()
        store.capture(BaselineCaptureRequest("bl-1", TestFixtures.baselineManifest()))
        store.markStale("slot changed")
        assertEquals(BaselineState.STALE, store.state())
        assertEquals(BaselineErrors.BASELINE_STALE, store.verify().blocker)
    }

    @Test
    fun emptyStoreIsMissingAndCheckIsEmptyProjection() {
        val store = store()
        assertEquals(BaselineState.MISSING_NEVER_CAPTURED, store.state())
        assertEquals("", store.check().id)
        assertTrue(store.history().isEmpty())
    }
}
