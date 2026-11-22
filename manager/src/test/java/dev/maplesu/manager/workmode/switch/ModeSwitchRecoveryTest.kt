package dev.maplesu.manager.workmode.switch

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/** 恢复判定纯函数（02 §6.2）：所有不确定输入都必须落到 RECOVERY_REQUIRED。 */
class ModeSwitchRecoveryTest {

    private fun observation(
        state: String = SwitchStateNames.COMMIT,
        failureRecorded: Boolean = false,
        current: Map<String, String> = mapOf("boot" to "target"),
        pre: Map<String, String> = mapOf("boot" to "pre"),
        target: Map<String, String> = mapOf("boot" to "target"),
        failures: Int = 0,
        bootChanged: Boolean = false,
        corrupt: Boolean = false,
    ) = SwitchObservation(state, failureRecorded, current, pre, target, failures, bootChanged, corrupt)

    @Test
    fun terminalStateIsNothingToDo() {
        assertEquals(RecoveryDecision.NOTHING_TO_DO,
            ModeSwitchReconciler.decide(observation(state = SwitchStateNames.VERIFIED)))
        assertEquals(RecoveryDecision.NOTHING_TO_DO,
            ModeSwitchReconciler.decide(observation(state = SwitchStateNames.ROLLED_BACK)))
        assertEquals(RecoveryDecision.NOTHING_TO_DO,
            ModeSwitchReconciler.decide(observation(state = SwitchStateNames.FAILED_PRE_WRITE)))
    }

    @Test
    fun journalCorruptionForcesRecovery() {
        assertEquals(RecoveryDecision.RECOVERY_REQUIRED,
            ModeSwitchReconciler.decide(observation(corrupt = true)))
    }

    @Test
    fun unreadablePartitionsCannotBeAssumedSafe() {
        assertEquals(RecoveryDecision.RECOVERY_REQUIRED,
            ModeSwitchReconciler.decide(observation(current = emptyMap())))
    }

    @Test
    fun contentOutsidePreOrTargetForcesRecovery() {
        assertEquals(RecoveryDecision.RECOVERY_REQUIRED,
            ModeSwitchReconciler.decide(observation(current = mapOf("boot" to "third"))))
    }

    @Test
    fun recordedFailureRequestsRollbackEvenIfContentLooksTargeted() {
        assertEquals(RecoveryDecision.ROLLBACK,
            ModeSwitchReconciler.decide(observation(failureRecorded = true)))
    }

    @Test
    fun twoBootVerifyFailuresForceRecovery() {
        assertEquals(RecoveryDecision.RECOVERY_REQUIRED,
            ModeSwitchReconciler.decide(observation(bootChanged = true, failures = 2)))
    }

    @Test
    fun rebootRequiredWithChangedBootIdResumesForward() {
        assertEquals(RecoveryDecision.RESUME_FORWARD,
            ModeSwitchReconciler.decide(
                observation(state = SwitchStateNames.REBOOT_REQUIRED, bootChanged = true),
            ))
    }

    @Test
    fun rebootRequiredWithoutBootChangeWaits() {
        assertEquals(RecoveryDecision.NOTHING_TO_DO,
            ModeSwitchReconciler.decide(observation(state = SwitchStateNames.REBOOT_REQUIRED)))
    }

    @Test
    fun allTargetOrAllPreBothResumeForward() {
        assertEquals(RecoveryDecision.RESUME_FORWARD,
            ModeSwitchReconciler.decide(observation(current = mapOf("boot" to "target"))))
        assertEquals(RecoveryDecision.RESUME_FORWARD,
            ModeSwitchReconciler.decide(observation(current = mapOf("boot" to "pre"))))
    }

    @Test
    fun mixedPartitionsResumeForwardStepByStep() {
        val decision = ModeSwitchReconciler.decide(
            observation(
                current = mapOf("boot" to "target", "init_boot" to "pre"),
                pre = mapOf("boot" to "pre", "init_boot" to "pre"),
                target = mapOf("boot" to "target", "init_boot" to "target2"),
            ),
        )
        assertEquals(RecoveryDecision.RESUME_FORWARD, decision)
    }

    @Test
    fun postRollbackStateOnlyRolledBackWhenAllPre() {
        assertEquals(SwitchStateNames.ROLLED_BACK,
            ModeSwitchReconciler.postRollbackState(observation(current = mapOf("boot" to "pre"))))
        assertEquals(SwitchStateNames.RECOVERY_REQUIRED,
            ModeSwitchReconciler.postRollbackState(observation(current = mapOf("boot" to "target"))))
    }

    @Test
    fun observeProjectsRecordIntoDecisionInput() {
        val record = SwitchRecord(
            switchId = java.util.UUID.randomUUID().toString(),
            state = SwitchStateNames.COMMIT,
            fromMode = "LITE",
            toMode = "KSU",
            partitions = listOf(
                SwitchRecordPartition("boot", "RESTORE_BASELINE", 4096, "pre", "target", "", "INTENT"),
            ),
            attempts = SwitchRecordAttempts(bootVerifyFailures = 1),
        )
        val observation = ModeSwitchReconciler.observe(record, mapOf("boot" to "target"), bootIdChanged = true)
        assertEquals("pre", observation.preSha["boot"])
        assertEquals("target", observation.targetSha["boot"])
        assertEquals(1, observation.bootVerifyFailures)
        assertEquals(RecoveryDecision.RESUME_FORWARD, ModeSwitchReconciler.decide(observation))
        assertFalse(observation.failureRecorded)
    }
}
