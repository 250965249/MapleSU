package com.maplesu.core.ui.viewmodel

import dev.maplesu.manager.workmode.WorkMode

/** Wait for the actual mode gate; a loading preview never selects a backend. */
internal class SuperuserStartupLoader(
    private val currentMode: () -> WorkMode?,
    private val awaitMode: suspend () -> WorkMode?,
) {
    /** False means the gate is still unresolved, not a completed empty app list. */
    suspend fun load(
        onWaiting: () -> Unit,
        load: suspend (WorkMode) -> Unit,
    ): Boolean {
        val mode = currentMode() ?: run {
            onWaiting()
            awaitMode()
        } ?: return false
        load(mode)
        return true
    }
}
