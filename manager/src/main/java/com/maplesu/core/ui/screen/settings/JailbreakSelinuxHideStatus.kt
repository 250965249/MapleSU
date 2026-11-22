package com.maplesu.core.ui.screen.settings

import com.maplesu.core.R
import dev.maplesu.manager.jailbreak.JailbreakSelinuxHideState

internal fun JailbreakSelinuxHideState.statusRes(): Int = when {
    error?.contains("BASELINE_MISSING") == true -> R.string.jailbreak_selinux_hide_baseline_missing
    error?.contains("SWITCH_UNSUPPORTED") == true -> R.string.jailbreak_selinux_hide_switch_unsupported
    error?.contains("BACKEND_UNAVAILABLE") == true -> R.string.jailbreak_selinux_hide_backend_missing
    error?.contains("INITIALIZATION_PENDING") == true -> R.string.jailbreak_selinux_hide_initializing
    error != null || effective == null -> R.string.jailbreak_selinux_hide_unavailable
    requested != effective -> R.string.jailbreak_selinux_hide_pending
    effective -> R.string.jailbreak_selinux_hide_effective
    else -> R.string.jailbreak_selinux_hide_inactive
}
