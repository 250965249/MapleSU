package dev.maplesu.manager.installer

import dev.maplesu.manager.workmode.WorkMode

/** Only an explicit Ultra installation may take over the current temporary Hook root. */
internal enum class InstallerServiceLaunchRoute { ROOT_EXEC, HOOK, SHELL }

internal fun installerServiceLaunchRoute(
    active: WorkMode?,
    target: InstallTargetMode?,
    hookAvailable: Boolean,
    verifiedUltraIdentity: Boolean = false,
): InstallerServiceLaunchRoute = when {
    // Preserve the persistent Ultra identity and its own root recovery path.
    verifiedUltraIdentity -> InstallerServiceLaunchRoute.ROOT_EXEC
    target == InstallTargetMode.ULTRA && hookAvailable -> InstallerServiceLaunchRoute.HOOK
    active == WorkMode.LITE -> InstallerServiceLaunchRoute.ROOT_EXEC
    else -> InstallerServiceLaunchRoute.SHELL
}
