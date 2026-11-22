package com.maplesu.core.ui.screen.install

import android.content.Context
import dev.maplesu.manager.workmode.migration.MigrationPaths

internal data class OriginalRootManager(val packageName: String, val label: String)

/** Installed manager names are choices, not evidence of the active root implementation. */
internal fun originalRootManagers(context: Context): List<OriginalRootManager> =
    MigrationPaths.ALL_MANAGER_PACKAGES.filter { it != context.packageName }.mapNotNull { packageName ->
        runCatching {
            val pm = context.packageManager
            val info = pm.getApplicationInfo(packageName, 0)
            OriginalRootManager(packageName, pm.getApplicationLabel(info).toString())
        }.getOrNull()
    }.sortedBy { it.label }
