package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.*
import org.junit.Test

class UltraProbeAdmissionTest {
    @Test fun busyAdmissionPreservesTheLastObservationOnlyForTheSameKeyAndBoot() {
        val probe = UltraEnvironmentProbe
        for (previous in UltraEnvironmentProbe.State.entries) {
            assertEquals(previous, probe.stateAfterAdmission(previous, UltraEnvironmentProbe.State.Unknown, "MAPLESU_SDK_BUSY", true))
            assertEquals(UltraEnvironmentProbe.State.Unknown, probe.stateAfterAdmission(previous, UltraEnvironmentProbe.State.Unknown, "MAPLESU_SDK_BUSY", false))
        }
    }

    @Test fun cancelledAdmissionContainsNoNewEnvironmentObservation() {
        val probe = UltraEnvironmentProbe
        for (previous in UltraEnvironmentProbe.State.entries) {
            assertEquals(previous, probe.stateAfterAdmission(previous, UltraEnvironmentProbe.State.Unknown, "MAPLESU_SDK_INTERRUPTED", true))
            assertEquals(UltraEnvironmentProbe.State.Unknown, probe.stateAfterAdmission(previous, UltraEnvironmentProbe.State.Unknown, "MAPLESU_SDK_INTERRUPTED", false))
        }
    }

    @Test fun actualFaultAndUninstallationReplaceThePreviousRunningObservation() {
        val probe = UltraEnvironmentProbe
        assertEquals(UltraEnvironmentProbe.State.Fault, probe.stateAfterAdmission(UltraEnvironmentProbe.State.Running, UltraEnvironmentProbe.State.Fault, "OK", true))
        assertEquals(UltraEnvironmentProbe.State.NotInstalled, probe.stateAfterAdmission(UltraEnvironmentProbe.State.Running, UltraEnvironmentProbe.State.NotInstalled, "OK", true))
        assertEquals(UltraEnvironmentProbe.State.Unknown, probe.stateAfterAdmission(UltraEnvironmentProbe.State.Running, UltraEnvironmentProbe.State.Unknown, "BROKEN_TRANSPORT", true))
    }

    @Test fun anUnconfirmedEnvironmentNeverDisplaysSuAsDisabled() {
        val probe = UltraEnvironmentProbe
        assertNull(probe.suEnabledState(UltraEnvironmentProbe.State.Unknown))
        assertNull(probe.suEnabledState(UltraEnvironmentProbe.State.NoKey))
        assertEquals(true, probe.suEnabledState(UltraEnvironmentProbe.State.Running))
        assertEquals(false, probe.suEnabledState(UltraEnvironmentProbe.State.Fault))
        assertEquals(false, probe.suEnabledState(UltraEnvironmentProbe.State.NotInstalled))
    }
}
