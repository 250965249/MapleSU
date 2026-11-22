package com.maplesu.core.ui.screen.settings

import com.maplesu.core.R
import dev.maplesu.manager.jailbreak.JailbreakSelinuxHideState
import org.junit.Assert.assertEquals
import org.junit.Test

class JailbreakSelinuxHideStatusTest {
    @Test fun activeNeedsAConfirmedBackendReceipt() {
        assertEquals(R.string.jailbreak_selinux_hide_effective,
            JailbreakSelinuxHideState(true, true, true).statusRes())
        assertEquals(R.string.jailbreak_selinux_hide_inactive,
            JailbreakSelinuxHideState(true, false, false).statusRes())
        assertEquals(R.string.jailbreak_selinux_hide_pending,
            JailbreakSelinuxHideState(true, true, false).statusRes())
    }

    @Test fun rootTransportFailuresAreNotARebootInstruction() {
        assertEquals(R.string.jailbreak_selinux_hide_unavailable,
            JailbreakSelinuxHideState(true, true, null, "SU_GATE_NOT_ARMED").statusRes())
    }

    @Test fun absentOriginalSnapshotHasItsOwnDiagnosis() {
        assertEquals(R.string.jailbreak_selinux_hide_baseline_missing,
            JailbreakSelinuxHideState(true, true, null, "JAILBREAK_SELINUX_BASELINE_MISSING").statusRes())
    }

    @Test fun oldResidentBackendIsNotConfusedWithAMissingBaseline() {
        assertEquals(R.string.jailbreak_selinux_hide_backend_missing,
            JailbreakSelinuxHideState(true, true, null,
                "JAILBREAK_SELINUX_HOOK:1:JAILBREAK_SELINUX_BACKEND_UNAVAILABLE").statusRes())
    }

    @Test fun failedLiveSwitchNeverShowsApplied() {
        assertEquals(R.string.jailbreak_selinux_hide_switch_unsupported,
            JailbreakSelinuxHideState(true, false, true, "JAILBREAK_SELINUX_SWITCH_UNSUPPORTED").statusRes())
    }

    @Test fun pendingInitializationHasItsOwnDiagnosis() {
        assertEquals(R.string.jailbreak_selinux_hide_initializing,
            JailbreakSelinuxHideState(true, true, null, "JAILBREAK_SELINUX_INITIALIZATION_PENDING").statusRes())
    }
}
