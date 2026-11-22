package com.maplesu.core.ui.viewmodel

/** Follow the home card's settled installation state without treating startup as uninstalled. */
internal object MainNavigationPolicy {
    fun isHomeOnly(
        hasInstalledVersion: Boolean,
        liteInstalled: Boolean,
        isGkiKernel: Boolean,
        litePending: Boolean,
        hiddenMasking: Boolean,
        hiddenConfirming: Boolean,
    ): Boolean = when {
        hiddenConfirming -> false
        hiddenMasking -> isGkiKernel
        hasInstalledVersion || liteInstalled || litePending -> false
        else -> isGkiKernel
    }

    fun resolvePage(page: Int, homeOnly: Boolean): Int =
        if (homeOnly) 0 else MainPagerConfig.coercePage(page)
}
