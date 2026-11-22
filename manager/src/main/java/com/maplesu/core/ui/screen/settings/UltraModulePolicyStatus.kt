package com.maplesu.core.ui.screen.settings

import com.maplesu.core.R
import dev.maplesu.manager.modules.UltraModulePolicyState
import dev.maplesu.manager.modules.UltraModulePolicyBackend

internal fun UltraModulePolicyState.statusRes(): Int? = when {
    error != null -> R.string.ultra_module_policy_read_failed
    !loaded -> null
    hideFailed -> R.string.ultra_module_policy_hide_fallback
    effective == null && unverifiedHide -> R.string.ultra_module_policy_hide_failed
    needsSessionPreparation -> R.string.ultra_module_policy_session_pending
    needsEnvironmentUpgrade -> R.string.ultra_module_policy_unavailable
    else -> null
}

internal fun UltraModulePolicyState.hideUnavailableRes(): Int = when {
    error != null -> R.string.ultra_module_policy_read_failed
    backend == UltraModulePolicyBackend.HOOK -> R.string.ultra_module_policy_hook_hide_unavailable
    else -> R.string.ultra_module_policy_hide_unavailable
}
