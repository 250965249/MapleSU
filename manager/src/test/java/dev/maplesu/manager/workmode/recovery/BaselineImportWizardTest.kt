package dev.maplesu.manager.workmode.recovery

import dev.maplesu.manager.workmode.switch.AvbFacts
import dev.maplesu.manager.workmode.switch.BaselineCaptureRequest
import dev.maplesu.manager.workmode.switch.BaselineCheck
import dev.maplesu.manager.workmode.switch.BaselineErrors
import dev.maplesu.manager.workmode.switch.BaselineImportRequest
import dev.maplesu.manager.workmode.switch.BaselineManifest
import dev.maplesu.manager.workmode.switch.BaselinePartition
import dev.maplesu.manager.workmode.switch.BaselineProvenance
import dev.maplesu.manager.workmode.switch.BaselineResult
import dev.maplesu.manager.workmode.switch.BaselineState
import dev.maplesu.manager.workmode.switch.BaselineStore
import dev.maplesu.manager.workmode.switch.BaselineVerification
import dev.maplesu.manager.workmode.switch.DeviceBootFacts
import dev.maplesu.manager.workmode.switch.PatchMarkers
import dev.maplesu.manager.workmode.switch.TakeoverRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.FileDescriptor

/** baseline 导入向导（主文档 §6.5/§6.6）：来源校验、takeover 禁晋升、host 接口接线。 */
class BaselineImportWizardTest {

    /** 只记录调用的 host fake，不触盘。 */
    private class FakeBaselineStore(
        var nextImportFailure: String? = null,
        var verificationState: BaselineState = BaselineState.PRESENT_OK,
    ) : BaselineStore {
        var lastImport: BaselineImportRequest? = null
        var lastTakeover: TakeoverRequest? = null
        var lastCapture: BaselineCaptureRequest? = null
        var importCount = 0

        override fun state(): BaselineState = verificationState
        override fun verify(id: String?): BaselineVerification = BaselineVerification(
            state = verificationState,
            id = id,
            check = null,
            mismatch = emptyList(),
            blocker = when (verificationState) {
                BaselineState.PRESENT_OK -> null
                BaselineState.STALE -> BaselineErrors.BASELINE_STALE
                BaselineState.CORRUPT -> BaselineErrors.BASELINE_CORRUPT
                else -> BaselineErrors.BASELINE_MISSING
            },
        )

        override fun capture(request: BaselineCaptureRequest): BaselineResult {
            lastCapture = request
            return BaselineResult.Ok(request.manifest)
        }

        override fun import(request: BaselineImportRequest): BaselineResult {
            lastImport = request
            importCount++
            return nextImportFailure?.let { BaselineResult.Failed(it, "fake") }
                ?: BaselineResult.Ok(request.manifest)
        }

        override fun open(id: String, partition: String): FileDescriptor? = null
        override fun captureTakeover(request: TakeoverRequest): BaselineResult {
            lastTakeover = request
            return BaselineResult.Ok(request.manifest)
        }

        override fun markStale(reason: String) = Unit
        override fun history(): List<BaselineManifest> = emptyList()
        override fun check(id: String?): BaselineCheck = BaselineCheck("", "", "", "", false)
    }

    private val device = DeviceBootFacts("_a", "PLQ110", "6.1.75")

    private fun manifest(
        id: String = "baseline-1",
        provenance: String = BaselineProvenance.OEM_PACKAGE,
        clean: Boolean = true,
        markers: PatchMarkers = PatchMarkers(),
        partitions: List<BaselinePartition> = listOf(
            BaselinePartition("boot", 64, "a".repeat(64), avbTailPreserved = true),
            BaselinePartition("init_boot", 8, "b".repeat(64), avbTailPreserved = true),
        ),
    ) = BaselineManifest(
        id = id,
        createdAt = 1,
        provenance = provenance,
        clean = clean,
        verifiedAt = 1,
        slot = "_a",
        firmware = "PLQ110",
        kernelRelease = "6.1.75",
        partitions = partitions,
        avb = AvbFacts(vbmetaPresent = true, vbmetaSha256 = "c".repeat(64), verificationDisabled = false),
        patchMarkers = markers,
    )

    @Test
    fun studyImageCannotBecomeBaseline() {
        val store = FakeBaselineStore()
        val wizard = BaselineImportWizard(store)
        val state = wizard.chooseSource(BaselineSourceKind.OEM_IMAGE_FILE, "Ace6/boot.img", 64, "a".repeat(64))
        assertEquals(BaselineWizardStep.FAILED, state.step)
        assertEquals(BaselineErrors.BASELINE_PROVENANCE_UNKNOWN, state.errorCode)
        assertFalse(state.canCommit)
    }

    @Test
    fun blankSourceIsRejected() {
        val wizard = BaselineImportWizard(FakeBaselineStore())
        val state = wizard.chooseSource(BaselineSourceKind.OEM_IMAGE_FILE, "", 0, "")
        assertEquals(BaselineWizardStep.FAILED, state.step)
    }

    @Test
    fun validSourceMovesToReview() {
        val wizard = BaselineImportWizard(FakeBaselineStore())
        val state = wizard.chooseSource(
            BaselineSourceKind.OEM_IMAGE_FILE, "/sdcard/oem/boot.img", 64, "a".repeat(64), device,
        )
        assertEquals(BaselineWizardStep.SOURCE_CHOSEN, state.step)
        assertEquals(BaselineWizardCopyKeys.NEXT_REVIEW, state.nextStepKey)
    }

    @Test
    fun reviewRejectsUncleanManifest() {
        val wizard = BaselineImportWizard(FakeBaselineStore())
        wizard.chooseSource(BaselineSourceKind.OEM_IMAGE_FILE, "/sdcard/oem/boot.img", 64, "a".repeat(64), device)
        val state = wizard.review(manifest(clean = false, markers = PatchMarkers(liteMarker = true)))
        assertEquals(BaselineWizardStep.FAILED, state.step)
        assertEquals(BaselineErrors.BASELINE_UNCLEAN, state.errorCode)
    }

    @Test
    fun reviewRejectsUnknownProvenance() {
        val wizard = BaselineImportWizard(FakeBaselineStore())
        wizard.chooseSource(BaselineSourceKind.OEM_IMAGE_FILE, "/sdcard/oem/boot.img", 64, "a".repeat(64), device)
        val state = wizard.review(manifest(provenance = "TAKEOVER_RANDOM"))
        assertEquals(BaselineWizardStep.FAILED, state.step)
        assertEquals(BaselineErrors.BASELINE_PROVENANCE_UNKNOWN, state.errorCode)
    }

    @Test
    fun reviewRejectsEmptyPartitions() {
        val wizard = BaselineImportWizard(FakeBaselineStore())
        wizard.chooseSource(BaselineSourceKind.OEM_IMAGE_FILE, "/sdcard/oem/boot.img", 64, "a".repeat(64), device)
        val state = wizard.review(manifest(partitions = emptyList()))
        assertEquals(BaselineWizardStep.FAILED, state.step)
        assertEquals(BaselineErrors.BASELINE_CORRUPT, state.errorCode)
    }

    @Test
    fun validReviewEnablesCommit() {
        val wizard = BaselineImportWizard(FakeBaselineStore())
        wizard.chooseSource(BaselineSourceKind.OEM_IMAGE_FILE, "/sdcard/oem/boot.img", 64, "a".repeat(64), device)
        val state = wizard.review(manifest())
        assertEquals(BaselineWizardStep.VALIDATED, state.step)
        assertTrue(state.canCommit)
        assertEquals(BaselineWizardCopyKeys.NEXT_CONFIRM, state.nextStepKey)
    }

    @Test
    fun commitCallsHostImportAndVerifies() {
        val store = FakeBaselineStore()
        val wizard = BaselineImportWizard(store)
        wizard.chooseSource(BaselineSourceKind.OEM_IMAGE_FILE, "/sdcard/oem/boot.img", 64, "a".repeat(64), device)
        wizard.review(manifest())
        val state = wizard.commit()
        assertEquals(BaselineWizardStep.IMPORTED, state.step)
        assertEquals(1, store.importCount)
        assertEquals("baseline-1", store.lastImport?.manifest?.id)
        assertEquals(BaselineState.PRESENT_OK, state.verification?.state)
        assertEquals(BaselineWizardCopyKeys.NEXT_DONE, state.nextStepKey)
    }

    @Test
    fun importFailureIsSurfacedAndNotSwallowed() {
        val store = FakeBaselineStore(nextImportFailure = BaselineErrors.BASELINE_PROMOTION_FORBIDDEN)
        val wizard = BaselineImportWizard(store)
        wizard.chooseSource(BaselineSourceKind.OEM_IMAGE_FILE, "/sdcard/oem/boot.img", 64, "a".repeat(64), device)
        wizard.review(manifest())
        val state = wizard.commit()
        assertEquals(BaselineWizardStep.FAILED, state.step)
        assertEquals(BaselineErrors.BASELINE_PROMOTION_FORBIDDEN, state.errorCode)
    }

    @Test
    fun takeoverCannotBePromotedToBaseline() {
        val store = FakeBaselineStore()
        val wizard = BaselineImportWizard(store)
        wizard.chooseSource(BaselineSourceKind.TAKEOVER_SNAPSHOT, "/data/adb/maplesu-workmode/boot/takeover/x")
        val state = wizard.review(manifest(provenance = BaselineProvenance.PRE_FIRST_WRITE_CAPTURE))
        assertEquals(BaselineWizardStep.FAILED, state.step)
        assertEquals(BaselineErrors.BASELINE_PROMOTION_FORBIDDEN, state.errorCode)
        assertFalse(state.canCommit)
        assertEquals(0, store.importCount)
    }

    @Test
    fun captureTakeoverWritesSeparateDirectoryAndForcesProvenance() {
        val store = FakeBaselineStore()
        val wizard = BaselineImportWizard(store)
        val state = wizard.captureTakeover("takeover-1", manifest())
        assertEquals(BaselineWizardStep.IMPORTED, state.step)
        assertNotNull(store.lastTakeover)
        assertEquals("takeover-1", store.lastTakeover?.id)
        assertEquals(
            BaselineProvenance.PRE_FIRST_WRITE_CAPTURE,
            store.lastTakeover?.manifest?.provenance,
        )
        assertEquals(BaselineSourceKind.TAKEOVER_SNAPSHOT, state.sourceKind)
        assertTrue(state.isTakeover)
    }

    @Test
    fun staleVerificationAfterImportIsReported() {
        val store = FakeBaselineStore(verificationState = BaselineState.STALE)
        val wizard = BaselineImportWizard(store)
        wizard.chooseSource(BaselineSourceKind.OEM_IMAGE_FILE, "/sdcard/oem/boot.img", 64, "a".repeat(64), device)
        wizard.review(manifest())
        val state = wizard.commit()
        assertEquals(BaselineWizardStep.IMPORTED, state.step)
        assertEquals(BaselineState.STALE, state.verification?.state)
        assertEquals(BaselineWizardCopyKeys.NEXT_IMPORT_AGAIN, state.nextStepKey)
    }

    @Test
    fun reviewBeforeChoosingSourceFails() {
        val wizard = BaselineImportWizard(FakeBaselineStore())
        val state = wizard.review(manifest())
        assertEquals(BaselineWizardStep.FAILED, state.step)
        assertFalse(state.canCommit)
    }

    @Test
    fun resetReturnsToInitialState() {
        val wizard = BaselineImportWizard(FakeBaselineStore())
        wizard.chooseSource(BaselineSourceKind.OEM_IMAGE_FILE, "/sdcard/oem/boot.img", 64, "a".repeat(64), device)
        wizard.review(manifest())
        val state = wizard.reset()
        assertEquals(BaselineWizardStep.IDLE, state.step)
        assertEquals(null, state.manifest)
    }
}
