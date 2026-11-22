package dev.maplesu.manager.modules

enum class UltraModulePolicyBackend { SDK, HOOK }

/** Root-owned requested state and this boot's independently proven backend state. */
data class UltraModulePolicyState(
    val requested: Int = 0,
    val effective: Int? = null,
    val capabilities: Int = 0,
    val loaded: Boolean = false,
    val error: String? = null,
    val unverifiedHide: Boolean = false,
    val canTryUnverified: Boolean = false,
    val hideFailed: Boolean = false,
    val backend: UltraModulePolicyBackend = UltraModulePolicyBackend.SDK,
) {
    val loadRequested: Boolean get() = requested and 1 != 0
    val hideRequested: Boolean get() = requested and 2 != 0
    val needsEnvironmentUpgrade: Boolean get() = loaded && error == null && effective == null && backend == UltraModulePolicyBackend.SDK
    val needsSessionPreparation: Boolean get() = loaded && error == null && effective == null && backend == UltraModulePolicyBackend.HOOK
    // Saving a preference does not claim that the current boot has applied it.
    val operable: Boolean get() = loaded && error == null
    val hideOperable: Boolean get() = operable && (capabilities and 2 != 0 || canTryUnverified || hideRequested)
    val hideNeedsRiskConfirmation: Boolean get() = hideOperable && capabilities and 2 == 0 && !hideRequested
    val pendingReboot: Boolean get() = effective != null && requested != effective
    val effectiveLoadAllowed: Boolean get() = effective?.let { it and 1 != 0 } == true

    fun withLoad(enabled: Boolean): UltraModulePolicyState = copy(requested = if (enabled) requested or 1 else 0,
        unverifiedHide = enabled && unverifiedHide)
    fun withHide(enabled: Boolean, acceptUnverified: Boolean = false): UltraModulePolicyState =
        if (loadRequested && (!enabled || hideOperable) && !(enabled && hideNeedsRiskConfirmation && !acceptUnverified))
            copy(requested = if (enabled) 3 else 1,
                unverifiedHide = enabled && (unverifiedHide || acceptUnverified && canTryUnverified && capabilities and 2 == 0)) else this

    fun shouldWarn(hasPolicy: Boolean, suppressed: Boolean): Boolean =
        hasPolicy && !suppressed && (!loadRequested || !effectiveLoadAllowed)

    companion object {
        fun fromBackend(requested: Int, effective: Int?, capabilities: Int,
            unverifiedHide: Boolean = false, canTryUnverified: Boolean = false, hideFailed: Boolean = false,
            backend: UltraModulePolicyBackend = UltraModulePolicyBackend.SDK): UltraModulePolicyState {
            require(requested in setOf(0, 1, 3)) { "MODULE_POLICY_INVALID_REQUEST" }
            require(effective == null || effective in setOf(0, 1, 3)) { "MODULE_POLICY_INVALID_EFFECTIVE" }
            require(capabilities in setOf(0, 1, 3) && (effective != null || capabilities == 0) &&
                (effective == null || capabilities and 1 != 0) &&
                (effective != 3 || capabilities and 2 != 0)) { "MODULE_POLICY_INVALID_CAPABILITIES" }
            require(!unverifiedHide || requested == 3) { "MODULE_POLICY_INVALID_EXPERIMENTAL_REQUEST" }
            return UltraModulePolicyState(requested, effective, capabilities, loaded = true,
                unverifiedHide = unverifiedHide, canTryUnverified = canTryUnverified, hideFailed = hideFailed, backend = backend)
        }
    }
}
