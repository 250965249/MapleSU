package dev.maplesu.manager.workmode.recovery

import dev.maplesu.manager.workmode.control.schema.SwitchHeadView
import dev.maplesu.manager.workmode.switch.BaselineState
import dev.maplesu.manager.workmode.switch.SwitchStateNames
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** W16 恢复决策矩阵（主文档 §5.7 / §6.6）：≥18 行。 */
class RecoveryDecisionTest {

    private fun head(
        state: String,
        bootIdAtBegin: String = "boot-1",
        switchId: String = "3f2b0c9e-6a1d-4c47-9c2e-1b7d5a0f8e33",
        errorCode: String = "",
    ) = SwitchHeadView(
        schema = 1,
        switchId = switchId,
        state = state,
        from = "A",
        to = "B",
        bootIdAtBegin = bootIdAtBegin,
        pending = SwitchStateNames.isPending(state),
        attempts = 0,
        errorCode = errorCode,
        errorStage = "",
        updatedAt = 1,
    )

    private fun input(
        head: SwitchHeadView? = null,
        baseline: BaselineState = BaselineState.PRESENT_OK,
        root: Boolean = true,
        bootId: String = "boot-1",
        journalState: String? = null,
        journalCorrupt: Boolean = false,
        verifyFailures: Int = 0,
        rebootRequests: Int = 0,
        migrationPending: Boolean = false,
        expectedSlot: String = "",
        slot: String = "",
    ) = RecoveryInput(
        head = head,
        journalState = journalState,
        journalCorrupt = journalCorrupt,
        baselineState = baseline,
        currentBootId = bootId,
        slot = slot,
        expectedSlot = expectedSlot,
        rootAvailable = root,
        bootVerifyFailures = verifyFailures,
        rebootRequests = rebootRequests,
        migrationPending = migrationPending,
    )

    private fun decide(input: RecoveryInput): RecoveryDecision = RecoveryDecisionEngine.decide(input)

    // ---- 无 pending

    @Test
    fun noPendingSwitchIsNoAction() {
        val decision = decide(input())
        assertSame(RecoveryAction.NONE, decision.action)
        assertTrue(decision.reasons.contains(RecoveryReason.NO_PENDING_SWITCH))
        assertTrue(decision.allows(RecoveryControl.NORMAL_OPERATIONS))
        assertFalse(decision.requiresExternalImage)
        assertFalse(decision.diagnosticOnly)
    }

    @Test
    fun baselineStaleWithoutPendingBlocksSwitchButAllowsImport() {
        val decision = decide(input(baseline = BaselineState.STALE))
        assertSame(RecoveryAction.NONE, decision.action)
        assertTrue(decision.reasons.contains(RecoveryReason.BASELINE_STALE))
        assertTrue(decision.blocks(RecoveryControl.SWITCH))
        assertTrue(decision.allows(RecoveryControl.IMPORT_BASELINE))
        assertEquals(RecoveryCopyKeys.NEXT_IMPORT_BASELINE, decision.nextStepKey)
    }

    @Test
    fun migrationPendingBlocksOrdinaryTransactions() {
        val decision = decide(input(migrationPending = true))
        assertTrue(decision.reasons.contains(RecoveryReason.MIGRATION_PENDING))
        assertTrue(decision.blocks(RecoveryControl.SWITCH))
        assertTrue(decision.blocks(RecoveryControl.INSTALL))
        assertTrue(decision.blocks(RecoveryControl.MODULE))
    }

    // ---- 进行中

    @Test
    fun activeSwitchIsInProgressAndBlocksWrites() {
        val decision = decide(input(head = head(SwitchStateNames.COMMIT)))
        assertSame(RecoveryAction.IN_PROGRESS, decision.action)
        assertTrue(decision.reasons.contains(RecoveryReason.SWITCH_ACTIVE))
        assertTrue(decision.blocks(RecoveryControl.SWITCH))
        assertTrue(decision.blocks(RecoveryControl.ROLLBACK))
        assertFalse(decision.autoRecoverable)
    }

    @Test
    fun rollingBackIsInProgress() {
        val decision = decide(input(head = head(SwitchStateNames.ROLLING_BACK)))
        assertSame(RecoveryAction.IN_PROGRESS, decision.action)
        assertTrue(decision.reasons.contains(RecoveryReason.ROLLBACK_ACTIVE))
    }

    // ---- REBOOT_REQUIRED

    @Test
    fun rebootRequiredWithSameBootIdAsksForReboot() {
        val decision = decide(input(head = head(SwitchStateNames.REBOOT_REQUIRED)))
        assertSame(RecoveryAction.RESUME_REBOOT, decision.action)
        assertTrue(decision.reasons.contains(RecoveryReason.REBOOT_NOT_OBSERVED))
        assertTrue(decision.allows(RecoveryControl.REBOOT))
        assertFalse(decision.requiresExternalImage)
    }

    @Test
    fun rebootObservedTriggersAutoVerify() {
        val decision = decide(
            input(head = head(SwitchStateNames.REBOOT_REQUIRED), bootId = "boot-2"),
        )
        assertSame(RecoveryAction.AUTO_VERIFY, decision.action)
        assertTrue(decision.reasons.contains(RecoveryReason.REBOOT_OBSERVED))
        assertTrue(decision.allows(RecoveryControl.VERIFY))
        assertTrue(decision.autoRecoverable)
    }

    @Test
    fun rebootLimitWithUsableBaselineOffersRollback() {
        val decision = decide(
            input(head = head(SwitchStateNames.REBOOT_REQUIRED), rebootRequests = 2),
        )
        assertSame(RecoveryAction.AUTO_ROLLBACK, decision.action)
        assertTrue(decision.reasons.contains(RecoveryReason.REBOOT_LIMIT_REACHED))
        assertTrue(decision.allows(RecoveryControl.ROLLBACK))
        assertFalse(decision.allows(RecoveryControl.REBOOT))
    }

    @Test
    fun rebootLimitWithoutRootNeedsExternalImage() {
        val decision = decide(
            input(
                head = head(SwitchStateNames.REBOOT_REQUIRED),
                rebootRequests = 3,
                root = false,
            ),
        )
        assertSame(RecoveryAction.EXTERNAL_RECOVERY, decision.action)
        assertTrue(decision.requiresExternalImage)
        assertTrue(decision.reasons.contains(RecoveryReason.NO_ROOT_CHANNEL))
    }

    @Test
    fun verifyingWithChangedBootIdAutoVerifies() {
        val decision = decide(input(head = head(SwitchStateNames.VERIFYING), bootId = "boot-2"))
        assertSame(RecoveryAction.AUTO_VERIFY, decision.action)
        assertTrue(decision.allows(RecoveryControl.VERIFY))
    }

    // ---- 终态

    @Test
    fun verifiedTerminalNeedsNoRecovery() {
        val decision = decide(input(head = head(SwitchStateNames.VERIFIED)))
        assertSame(RecoveryAction.NONE, decision.action)
        assertTrue(decision.reasons.contains(RecoveryReason.VERIFIED))
        assertTrue(decision.allows(RecoveryControl.NORMAL_OPERATIONS))
    }

    @Test
    fun failedPreWriteIsSafeTerminal() {
        val decision = decide(input(head = head(SwitchStateNames.FAILED_PRE_WRITE)))
        assertSame(RecoveryAction.NONE, decision.action)
        assertTrue(decision.reasons.contains(RecoveryReason.FAILED_PRE_WRITE))
        assertFalse(decision.requiresExternalImage)
    }

    // ---- RECOVERY_REQUIRED

    @Test
    fun recoveryRequiredWithRootAndBaselineAllowsAutoRollback() {
        val decision = decide(input(head = head(SwitchStateNames.RECOVERY_REQUIRED)))
        assertSame(RecoveryAction.AUTO_ROLLBACK, decision.action)
        assertTrue(decision.reasons.contains(RecoveryReason.RECOVERY_REQUIRED))
        assertTrue(decision.reasons.contains(RecoveryReason.ROLLBACK_AVAILABLE))
        assertTrue(decision.allows(RecoveryControl.ROLLBACK))
        assertTrue(decision.autoRecoverable)
    }

    @Test
    fun recoveryRequiredWithoutRootNeedsExternalImage() {
        val decision = decide(input(head = head(SwitchStateNames.RECOVERY_REQUIRED), root = false))
        assertSame(RecoveryAction.EXTERNAL_RECOVERY, decision.action)
        assertTrue(decision.requiresExternalImage)
        assertTrue(decision.blocked.containsAll(setOf(RecoveryControl.REBOOT, RecoveryControl.VERIFY)))
        assertTrue(decision.allows(RecoveryControl.EXPORT_DIAGNOSTICS))
    }

    @Test
    fun recoveryRequiredWithMissingBaselineNeedsExternalImageButAllowsImport() {
        val decision = decide(
            input(head = head(SwitchStateNames.RECOVERY_REQUIRED), baseline = BaselineState.MISSING_NEVER_CAPTURED),
        )
        assertSame(RecoveryAction.EXTERNAL_RECOVERY, decision.action)
        assertTrue(decision.reasons.contains(RecoveryReason.BASELINE_MISSING))
        assertTrue(decision.allows(RecoveryControl.IMPORT_BASELINE))
    }

    @Test
    fun recoveryRequiredWithStaleBaselineIsNotAutoRollback() {
        val decision = decide(
            input(head = head(SwitchStateNames.RECOVERY_REQUIRED), baseline = BaselineState.STALE),
        )
        assertSame(RecoveryAction.EXTERNAL_RECOVERY, decision.action)
        assertTrue(decision.reasons.contains(RecoveryReason.BASELINE_STALE))
        assertFalse(decision.autoRecoverable)
    }

    @Test
    fun recoveryRequiredAfterTwoVerifyFailuresForbidsRetryButAllowsExplicitRollback() {
        val decision = decide(
            input(head = head(SwitchStateNames.RECOVERY_REQUIRED), verifyFailures = 2),
        )
        assertSame(RecoveryAction.FORBIDDEN, decision.action)
        assertTrue(decision.reasons.contains(RecoveryReason.VERIFY_FAILED_TWICE))
        assertFalse(decision.allows(RecoveryControl.VERIFY))
        assertFalse(decision.allows(RecoveryControl.REBOOT))
        assertTrue(decision.allows(RecoveryControl.ROLLBACK))
        assertTrue(decision.allows(RecoveryControl.EXPORT_DIAGNOSTICS))
    }

    @Test
    fun deviceMismatchForbidsWritesAndNeedsDiagnosis() {
        val decision = decide(
            input(
                head = head(SwitchStateNames.RECOVERY_REQUIRED),
                expectedSlot = "_a",
                slot = "_b",
            ),
        )
        assertSame(RecoveryAction.FORBIDDEN, decision.action)
        assertTrue(decision.reasons.contains(RecoveryReason.DEVICE_MISMATCH))
        assertTrue(decision.diagnosticOnly)
        assertFalse(decision.allows(RecoveryControl.ROLLBACK))
    }

    @Test
    fun workModeKernelChangeKeepsRollbackAvailableOnSameSlot() {
        val changedKernel = input(
            head = head(SwitchStateNames.RECOVERY_REQUIRED),
            expectedSlot = "_a",
            slot = "_a",
        ).copy(
            firmware = "normal-reported-firmware",
            expectedFirmware = "ultra-reported-firmware",
            kernelRelease = "6.6.115-android15-8-normal",
            expectedKernelRelease = "6.6.101-android15-8-ultra",
        )
        assertFalse(changedKernel.deviceMismatch)
        val decision = decide(changedKernel)
        assertSame(RecoveryAction.AUTO_ROLLBACK, decision.action)
        assertTrue(decision.allows(RecoveryControl.ROLLBACK))
        assertFalse(decision.reasons.contains(RecoveryReason.DEVICE_MISMATCH))
    }

    // ---- 现场不可信

    @Test
    fun corruptJournalIsDiagnosticOnly() {
        val decision = decide(input(head = head(SwitchStateNames.COMMIT), journalCorrupt = true))
        assertSame(RecoveryAction.FORBIDDEN, decision.action)
        assertTrue(decision.reasons.contains(RecoveryReason.JOURNAL_CORRUPT))
        assertTrue(decision.diagnosticOnly)
        assertTrue(decision.allows(RecoveryControl.EXPORT_DIAGNOSTICS))
        assertFalse(decision.allows(RecoveryControl.ROLLBACK))
    }

    @Test
    fun unknownStateIsConservative() {
        val decision = decide(input(head = head("SOMETHING_NEW")))
        assertSame(RecoveryAction.FORBIDDEN, decision.action)
        assertTrue(decision.reasons.contains(RecoveryReason.UNKNOWN_STATE))
        assertTrue(decision.blocked.containsAll(setOf(RecoveryControl.SWITCH, RecoveryControl.INSTALL)))
    }

    @Test
    fun journalWithoutAuthoritativeHeadIsNotAutoRepaired() {
        val decision = decide(
            input(journalState = SwitchStateNames.COMMIT),
        )
        assertSame(RecoveryAction.FORBIDDEN, decision.action)
        assertTrue(decision.reasons.contains(RecoveryReason.JOURNAL_MISSING))
        assertFalse(decision.autoRecoverable)
    }

    @Test
    fun terminalJournalWithoutHeadIsNormalOperations() {
        val decision = decide(input(journalState = SwitchStateNames.VERIFIED))
        assertSame(RecoveryAction.NONE, decision.action)
        assertTrue(decision.reasons.contains(RecoveryReason.NO_PENDING_SWITCH))
    }

    // ---- 通用不变量

    @Test
    fun everyDecisionNeverAllowsSwitchWhileSwitchPending() {
        val states = listOf(
            SwitchStateNames.BEGIN, SwitchStateNames.SNAPSHOT, SwitchStateNames.PRODUCE,
            SwitchStateNames.COMMIT, SwitchStateNames.REBOOT_REQUIRED, SwitchStateNames.VERIFYING,
            SwitchStateNames.ROLLING_BACK, SwitchStateNames.RECOVERY_REQUIRED,
        )
        for (state in states) {
            val decision = decide(input(head = head(state)))
            assertTrue("state=$state must block SWITCH", decision.blocks(RecoveryControl.SWITCH))
            assertTrue("state=$state must allow diagnostics", decision.allows(RecoveryControl.EXPORT_DIAGNOSTICS))
        }
    }

    @Test
    fun autoActionsRequireRootForRollback() {
        val withRoot = decide(input(head = head(SwitchStateNames.RECOVERY_REQUIRED)))
        val withoutRoot = decide(input(head = head(SwitchStateNames.RECOVERY_REQUIRED), root = false))
        assertSame(RecoveryAction.AUTO_ROLLBACK, withRoot.action)
        assertSame(RecoveryAction.EXTERNAL_RECOVERY, withoutRoot.action)
        assertTrue(withRoot.allows(RecoveryControl.ROLLBACK))
        assertFalse(withoutRoot.allows(RecoveryControl.ROLLBACK))
    }
}
