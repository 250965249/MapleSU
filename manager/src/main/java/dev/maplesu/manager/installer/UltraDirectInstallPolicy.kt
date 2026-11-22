package dev.maplesu.manager.installer

import dev.maplesu.manager.runtime.ultra.UltraEnvUpgrade
import dev.maplesu.manager.runtime.ultra.UltraEnvFacts
import dev.maplesu.manager.runtime.ultra.UltraEnvUpgradePolicy
import dev.maplesu.manager.runtime.ultra.UltraInstalledIdentityProbe
import dev.maplesu.manager.workmode.WorkMode

/** Only an ordinary, same-mode direct install can update the running environment. */
internal data class UltraDirectInstallRequest(
    val activeMode: WorkMode?,
    val target: InstallTargetMode,
    val source: InstallSourceKind,
    val partition: String?,
    val defaultKernel: Boolean = true,
    val signing: Boolean = false,
    val bootOptions: Boolean = false,
    val environmentWasRunning: Boolean = false,
    val forceRepatch: Boolean = false,
)

internal object UltraDirectInstallPolicy {
    fun eligible(request: UltraDirectInstallRequest): Boolean =
        request.activeMode == WorkMode.LITE && request.target == InstallTargetMode.ULTRA &&
            request.source == InstallSourceKind.CURRENT_PARTITION && request.partition in setOf("boot", "init_boot") &&
            request.defaultKernel && !request.signing && !request.bootOptions && !request.forceRepatch

    fun requiresModuleChoice(target: InstallTargetMode, activeMode: WorkMode?): Boolean =
        target == InstallTargetMode.ULTRA && activeMode != WorkMode.LITE

    /** A rejected or interrupted environment update must never fall through to boot patching. */
    fun <T> dispatch(request: UltraDirectInstallRequest, facts: () -> UltraEnvFacts,
                     upgrade: () -> T, unavailable: (UltraEnvUpgrade) -> T, patchBoot: () -> T,
                     requiresKernelUpdate: () -> Boolean = { false }): T {
        if (eligible(request)) {
            val current = facts()
            if ((current.running || current.installedVersion != null) &&
                !current.suspended && !current.quiescing && !current.submittedThisBoot &&
                requiresKernelUpdate()) return patchBoot()
            when (val decision = UltraEnvUpgradePolicy.decide(current)) {
                is UltraEnvUpgrade.Available, is UltraEnvUpgrade.Unverified -> return upgrade()
                is UltraEnvUpgrade.Rebooting -> return unavailable(decision)
                UltraEnvUpgrade.None -> {
                    if (current.suspended || current.quiescing) return unavailable(decision)
                    // The installer performs a fresh channel/boot/identity check before repairing
                    // an idle helper. Never reinterpret Unknown as Running or patch over it.
                    if (!current.running && current.installedVersion != null &&
                        UltraInstalledIdentityProbe.normalizeSha(current.installedHelperSha256) != null) return upgrade()
                    if (!current.running && (request.environmentWasRunning || current.installedVersion != null)) {
                        return unavailable(decision)
                    }
                    if (current.readUnknown) return unavailable(decision)
                }
            }
        }
        return patchBoot()
    }
}
