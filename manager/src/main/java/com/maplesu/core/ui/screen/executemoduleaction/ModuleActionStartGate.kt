package com.maplesu.core.ui.screen.executemoduleaction

internal enum class ModuleActionStart { START, ALREADY_STARTED, RESTORED_RUNNING, RESTORED_COMPLETE }

/** A recreated UI may attach repeatedly; a restored process must never repeat a command. */
internal class ModuleActionStartGate(
    private val restoredStarted: Boolean,
    private val restoredComplete: Boolean,
) {
    private var claimed = false

    fun claim(): ModuleActionStart {
        if (claimed) return ModuleActionStart.ALREADY_STARTED
        claimed = true
        return when {
            restoredComplete -> ModuleActionStart.RESTORED_COMPLETE
            restoredStarted -> ModuleActionStart.RESTORED_RUNNING
            else -> ModuleActionStart.START
        }
    }
}
