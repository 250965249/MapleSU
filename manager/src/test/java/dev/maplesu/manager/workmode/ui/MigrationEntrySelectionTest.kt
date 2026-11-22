package dev.maplesu.manager.workmode.ui

import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.migration.*
import org.junit.Assert.*
import org.junit.Test

class MigrationEntrySelectionTest {
    private val detected = MigrationUiSnapshot(
        stage = MigrationStage.DETECTED,
        detection = MigrationDetectionUi(
            familyKey = MigrationFamilyKeys.KSU, versionLabel = null, uapi = null,
            patchedPartitions = emptyList(), cleanImagePartitions = emptyList(),
            usableStockBackups = 0, totalStockBackups = 0, managerPackageCount = 1,
            bestEffort = false, supported = true, blockerKeys = emptyList(), eligible = true,
        ),
        targetOptions = listOf(
            MigrationTargetOption(WorkMode.LITE, recommended = true, enabled = true),
            MigrationTargetOption(WorkMode.KSU, recommended = false, enabled = false),
        ),
        selectedTarget = WorkMode.LITE,
    )

    @Test fun disabledCarriedTargetIsNotReplacedWithRecommendationOrConfirmed() {
        val result = migrationEntrySelection(detected, WorkMode.KSU, confirmOnOpen = true)
        assertNull(result.selectedTarget)
        assertEquals(MigrationStage.DETECTED, result.stage)
        assertFalse(result.confirming)
        assertFalse(result.canStart)
    }

    @Test fun supportedCarriedTargetOpensConfirmation() {
        val result = migrationEntrySelection(detected, WorkMode.LITE, confirmOnOpen = true)
        assertEquals(WorkMode.LITE, result.selectedTarget)
        assertEquals(MigrationStage.CONFIRMING, result.stage)
        assertTrue(result.confirming)
    }

    @Test fun enteringWithoutAChoiceKeepsTheDetectedRecommendation() {
        val result = migrationEntrySelection(detected, null, confirmOnOpen = false)
        assertEquals(WorkMode.LITE, result.selectedTarget)
        assertTrue(result.canStart)
        assertEquals(MigrationStage.DETECTED, result.stage)
    }
}
