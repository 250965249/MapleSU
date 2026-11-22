package dev.maplesu.manager.workmode.ui

import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.*
import org.junit.Test

/** 选择框只接受目标，执行结果由进度页展示。 */
class WorkModeSheetModelTest {
    private val ready = WorkModeUiState(
        current = WorkMode.LITE,
        phase = WorkModePhase.READY,
        availability = SwitchAvailability(canSwitch = true, target = WorkMode.KSU),
    )

    @Test fun currentModeIsDisabledWhileTheOtherModeCanBeConfirmed() {
        assertEquals(WorkModeSheetCta.CurrentMode, workModeSheetCta(WorkMode.LITE, ready))
        assertEquals(WorkModeSheetCta.SwitchTo(WorkMode.KSU, true), workModeSheetCta(WorkMode.KSU, ready))
        val normal = ready.copy(current = WorkMode.KSU)
        assertEquals(WorkModeSheetCta.CurrentMode, workModeSheetCta(WorkMode.KSU, normal))
        assertEquals(WorkModeSheetCta.SwitchTo(WorkMode.LITE, true), workModeSheetCta(WorkMode.LITE, normal))
    }

    @Test fun staleAvailabilityDoesNotDelayEnteringTheProgressPage() {
        val blocked = ready.copy(availability = SwitchAvailability(
            canSwitch = false,
            blockers = listOf(SwitchBlocker(SwitchBlockerCodes.PENDING_INSTALL)),
        ))
        assertEquals(WorkModeSheetCta.SwitchTo(WorkMode.KSU, true), workModeSheetCta(WorkMode.KSU, blocked))
        assertNull(workModeSheetNotice(WorkMode.KSU, blocked))
    }

    @Test fun confirmationIsAcceptedBeforeBackgroundDetectionCompletes() {
        val analyzing = ready.copy(phase = WorkModePhase.ANALYZING)
        assertEquals(WorkModeSheetCta.SwitchTo(WorkMode.KSU, true), workModeSheetCta(WorkMode.KSU, analyzing))
        val accepted = analyzing.reduce(WorkModeEvent.StartSwitch(WorkMode.KSU))
        assertEquals(WorkModePhase.RUNNING, accepted.phase)
        assertEquals(WorkMode.KSU, accepted.target)
    }

    @Test fun aRunningSwitchCannotBeClosedBeforeHandOff() {
        val running = ready.reduce(WorkModeEvent.StartSwitch(WorkMode.KSU))
        assertEquals(WorkModeSheetCta.Switching, workModeSheetCta(WorkMode.KSU, running))
        assertFalse(workModeSheetDismissible(running))
    }

    @Test fun progressHandOffIsConsumedOnce() {
        val running = ready.reduce(WorkModeEvent.StartSwitch(WorkMode.KSU))
            .reduce(WorkModeEvent.Started("real-id"))
        assertEquals("real-id", running.progressToOpen)
        assertNull(running.reduce(WorkModeEvent.ProgressOpened("real-id")).progressToOpen)
    }

    @Test fun manualRecoveryIsOfferedOnlyWithAnActualId() {
        val failed = ready.copy(
            phase = WorkModePhase.FAILED,
            failure = WorkModeFailure("WRITE_ROLLBACK_FAILED", "not user copy", rolledBack = false),
        )
        val notice = workModeSheetNotice(WorkMode.KSU, failed) as WorkModeSheetNotice.Failed
        assertTrue(notice.needsManualRecovery)
        assertNull(notice.recoverySwitchId)
        val withId = failed.reduce(WorkModeEvent.PendingSwitch("real-failure-id"))
        assertEquals("real-failure-id", (workModeSheetNotice(WorkMode.KSU, withId) as WorkModeSheetNotice.Failed).recoverySwitchId)
    }

    @Test fun maskingNeverEnablesAConfirmation() {
        assertEquals(WorkModeSheetCta.NoSelection, workModeSheetCta(WorkMode.KSU, ready.copy(masked = true)))
        assertFalse(ready.copy(masked = true).canStartSwitch)
    }

    @Test fun selectionDoesNotCallTheServiceOrRunTheSwitch() {
        val source = java.io.File("src/main/java/dev/maplesu/manager/workmode/ui/WorkModeViewModel.kt").readText()
        for (remoteCall in listOf("statusAsync(", "availabilityFor(", "startSwitch(", "computeAvailability(")) {
            assertFalse("Selection must not wait for $remoteCall", source.contains(remoteCall))
        }
        assertTrue("The previous operation remains available to recovery",
            source.contains("pendingId.takeIf { WorkModeSwitchSession.pending }"))
    }
}
