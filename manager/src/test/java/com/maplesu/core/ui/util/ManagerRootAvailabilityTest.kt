package com.maplesu.core.ui.util

import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootCapability
import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.*
import org.junit.Test

class ManagerRootAvailabilityTest {
    @Test fun runningUltraIsAvailableWithoutOpeningItsDisabledLegacyShell() {
        assertTrue(managerRootAvailable(WorkMode.LITE, true,
            RootCapability(RootBackend.ULTRA_ENV, true)) { error("legacy shell must stay disabled") })
    }

    @Test fun unresolvedVerifiedUltraUsesTheSameAvailableRoot() {
        assertTrue(managerRootAvailable(null, true,
            RootCapability(RootBackend.ULTRA_ENV, true)) { error("legacy shell must stay disabled") })
    }

    @Test fun aVerifiedIdentityAloneDoesNotClaimRoot() {
        assertFalse(managerRootAvailable(WorkMode.LITE, true,
            RootCapability.NONE) { error("legacy shell must stay disabled") })
    }

    @Test fun aTemporaryUltraHookIsAvailableWithoutAUltraIdentity() {
        assertTrue(managerRootAvailable(WorkMode.LITE, false,
            RootCapability(RootBackend.HOOK, true)) { error("legacy shell must stay disabled") })
    }

    @Test fun normalKeepsItsActualKsuShellVerdict() {
        assertFalse(managerRootAvailable(WorkMode.KSU, true,
            RootCapability(RootBackend.ULTRA_ENV, true)) { false })
        assertTrue(managerRootAvailable(WorkMode.KSU, false,
            RootCapability.NONE) { true })
    }

    @Test fun normalDoesNotInheritAStaleUltraIdentityWhenItsActualShellWorks() {
        assertTrue(managerRootAvailable(WorkMode.KSU, true,
            RootCapability.NONE) { true })
    }

    @Test fun aNonUltraRootProviderStillUsesItsOrdinarySuProof() {
        var checked = false
        assertTrue(managerRootAvailable(null, false, RootCapability.NONE) {
            checked = true
            true
        })
        assertTrue(checked)
    }

    @Test fun aLegacyCredentialByItselfStillNeedsItsRealShellProof() {
        assertFalse(managerRootAvailable(WorkMode.LITE, false,
            RootCapability(RootBackend.LITE_KERNEL, true)) { false })
    }

    @Test fun productionRootAvailabilityUsesTheModeAwareCapability() {
        val source = listOf(java.io.File("src/main/java/com/maplesu/core/ui/util/KsuCli.kt"),
            java.io.File("manager/src/main/java/com/maplesu/core/ui/util/KsuCli.kt"))
            .first { it.isFile }.readText()
        val function = source.substringAfter("fun rootAvailable(): Boolean").substringBefore("suspend fun getCurrentKmi")
        assertTrue("The live Ultra capability must not be replaced by DeadShell.isRoot",
            function.contains("managerRootAvailable("))
    }
}
