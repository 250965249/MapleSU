package dev.maplesu.manager.installer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pending-state policy shared by the two partition writers (02-switch-contract §5.5). */
class InstallerPendingPolicyTest {
    @Test
    fun installActiveStatesMatchTheExistingBootTransaction() {
        for (state in listOf("PREPARING", "PREPARED", "WRITING", "RESTORING", "RECOVERY_REQUIRED")) {
            assertTrue(state, InstallerPending.isPendingInstallState(state))
        }
        for (state in listOf("WRITTEN", "VERIFIED", "RESTORED", "FAILED_BEFORE_WRITE", "", null)) {
            assertFalse(state.orEmpty(), InstallerPending.isPendingInstallState(state))
        }
    }

    @Test
    fun switchPendingStatesMatchTheStateMachine() {
        assertEquals(setOf("BEGIN", "SNAPSHOT", "PRODUCE", "COMMIT", "REBOOT_REQUIRED",
            "VERIFYING", "ROLLING_BACK", "RECOVERY_REQUIRED"), InstallerPending.switchPendingStates)
        assertEquals(setOf("VERIFIED", "ROLLED_BACK", "FAILED_PRE_WRITE", "CANCELLED"),
            InstallerPending.switchTerminalStates)
        assertTrue(InstallerPending.switchPendingStates.intersect(InstallerPending.switchTerminalStates).isEmpty())
    }

    @Test
    fun switchPendingPredicates() {
        for (state in InstallerPending.switchPendingStates) {
            assertTrue(state, InstallerPending.isPendingSwitchState(state))
        }
        for (state in InstallerPending.switchTerminalStates) {
            assertFalse(state, InstallerPending.isPendingSwitchState(state))
        }
        assertFalse(InstallerPending.isPendingSwitchState(""))
        assertFalse(InstallerPending.isPendingSwitchState(null))
    }

    @Test
    fun recoveryRequiredBlocksBothWriters() {
        assertTrue(InstallerPending.isPendingInstallState("RECOVERY_REQUIRED"))
        assertTrue(InstallerPending.isPendingSwitchState("RECOVERY_REQUIRED"))
    }
}
