package dev.maplesu.manager.installer

import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Test

class InstallerServiceLaunchPolicyTest {
    @Test
    fun persistentUltraKeepsItsUltraRootChannelEvenWhenAHookExists() {
        assertEquals(InstallerServiceLaunchRoute.ROOT_EXEC,
            installerServiceLaunchRoute(WorkMode.LITE, InstallTargetMode.ULTRA, true, verifiedUltraIdentity = true))
    }

    @Test
    fun cachedUltraWithoutVerifiedUltraUsesTheCurrentHookForAnExplicitInstall() {
        assertEquals(InstallerServiceLaunchRoute.HOOK,
            installerServiceLaunchRoute(WorkMode.LITE, InstallTargetMode.ULTRA, true))
    }

    @Test
    fun normalInstallationKeepsTheKsuShell() {
        assertEquals(InstallerServiceLaunchRoute.SHELL,
            installerServiceLaunchRoute(WorkMode.KSU, InstallTargetMode.NORMAL, true))
    }

    @Test
    fun existingKsuWithAnExplicitUltraHookUsesTheHook() {
        assertEquals(InstallerServiceLaunchRoute.HOOK,
            installerServiceLaunchRoute(WorkMode.KSU, InstallTargetMode.ULTRA, true))
    }

    @Test
    fun anUnrelatedServiceRequestDoesNotTakeOverTheHook() {
        assertEquals(InstallerServiceLaunchRoute.SHELL,
            installerServiceLaunchRoute(WorkMode.KSU, null, true))
    }

    @Test
    fun anExpiredHookDoesNotChooseTheHookTransport() {
        assertEquals(InstallerServiceLaunchRoute.SHELL,
            installerServiceLaunchRoute(WorkMode.KSU, InstallTargetMode.ULTRA, false))
    }

    @Test
    fun anExplicitFirstUltraInstallCanUseTheHookBeforeModeActivation() {
        assertEquals(InstallerServiceLaunchRoute.HOOK,
            installerServiceLaunchRoute(null, InstallTargetMode.ULTRA, true))
    }

    @Test
    fun aVerifiedUltraIdentityWorksBeforeModeActivation() {
        assertEquals(InstallerServiceLaunchRoute.ROOT_EXEC,
            installerServiceLaunchRoute(null, InstallTargetMode.ULTRA, false, verifiedUltraIdentity = true))
    }

    @Test
    fun aVerifiedUltraIdentityNeverFallsBackToTheTemporaryHook() {
        assertEquals(InstallerServiceLaunchRoute.ROOT_EXEC,
            installerServiceLaunchRoute(null, InstallTargetMode.ULTRA, true, verifiedUltraIdentity = true))
    }
}
