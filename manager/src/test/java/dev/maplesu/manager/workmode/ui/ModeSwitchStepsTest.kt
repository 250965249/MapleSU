package dev.maplesu.manager.workmode.ui

import org.junit.Assert.*
import org.junit.Test

class ModeSwitchStepsTest {
    @Test fun stageAndStateAreMappedToHumanSteps() {
        val cases = listOf(
            "S0" to ModeSwitchStep.PREPARE, "S1" to ModeSwitchStep.PREPARE,
            "S2" to ModeSwitchStep.BACKUP, "S3" to ModeSwitchStep.BUILD,
            "S4" to ModeSwitchStep.WRITE, "S5" to ModeSwitchStep.REBOOT,
            "S6" to ModeSwitchStep.VERIFY,
        )
        cases.forEach { (wire, expected) -> assertEquals(wire, expected, modeSwitchStepOf("", wire, "")) }
        listOf(
            "BEGIN" to ModeSwitchStep.PREPARE, "SNAPSHOT" to ModeSwitchStep.BACKUP,
            "PRODUCE" to ModeSwitchStep.BUILD, "COMMIT" to ModeSwitchStep.WRITE,
            "REBOOT_REQUIRED" to ModeSwitchStep.REBOOT, "VERIFYING" to ModeSwitchStep.VERIFY,
            "VERIFIED" to ModeSwitchStep.VERIFY,
        ).forEach { (wire, expected) -> assertEquals(wire, expected, modeSwitchStepOf(wire, "", "")) }
    }

    @Test fun morePreciseStepTakesPriorityAndUnknownValuesFallBack() {
        assertEquals(ModeSwitchStep.RESTORE, modeSwitchStepOf("COMMIT", "S4", "4e"))
        assertEquals(ModeSwitchStep.RESTORE, modeSwitchStepOf("COMMIT", "S4", "4f"))
        assertEquals(ModeSwitchStep.VERIFY, modeSwitchStepOf("VERIFYING", "S6", "6.4"))
        assertNull(modeSwitchStepOf("FUTURE", "S99", "99z"))
        assertEquals(ModeSwitchStep.WRITE, modeSwitchStepOf("COMMIT", "S99", "99z"))
    }

    @Test fun failedAndFinishedRowsAreNotConfused() {
        val rows = modeSwitchStepRows(ModeSwitchStep.WRITE, failed = true)
        assertEquals(StepStatus.DONE, rows.first().status)
        assertEquals(StepStatus.FAILED, rows[ModeSwitchStep.WRITE.ordinal].status)
        assertEquals(StepStatus.PENDING, rows.last().status)
        assertTrue(modeSwitchStepRows(null, finished = true).all { it.status == StepStatus.DONE })
    }

    @Test fun rebootRequiredIsNotACompletedBoot() {
        assertEquals(ModeSwitchHeadline.AWAITING_REBOOT, modeSwitchHeadline(ModeSwitchPhase.SUCCEEDED, "REBOOT_REQUIRED", true))
        assertEquals(ModeSwitchHeadline.DONE, modeSwitchHeadline(ModeSwitchPhase.SUCCEEDED, "VERIFIED", false))
        assertEquals(ModeSwitchHeadline.ROLLED_BACK, modeSwitchHeadline(ModeSwitchPhase.FAILED, "ROLLED_BACK", false))
        assertEquals(ModeSwitchHeadline.NEEDS_RECOVERY, modeSwitchHeadline(ModeSwitchPhase.NEEDS_RECOVERY, "RECOVERY_REQUIRED", false))
        assertEquals(ModeSwitchHeadline.RUNNING, modeSwitchHeadline(ModeSwitchPhase.RUNNING, "FUTURE", false))
    }
}
