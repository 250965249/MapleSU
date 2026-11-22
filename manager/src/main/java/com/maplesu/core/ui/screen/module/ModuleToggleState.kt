package com.maplesu.core.ui.screen.module

import com.maplesu.core.data.model.Module

data class ModuleToggleChange(val confirmed: Module, val enabled: Boolean) {
    fun present(module: Module): Module = module.copy(enabled = enabled,
        needsReboot = confirmed.needsReboot || enabled != confirmed.enabled)
}

internal fun ModuleUiState.withModuleToggleRequest(id: String, enabled: Boolean): ModuleUiState {
    val current = modules.firstOrNull { it.id == id } ?: return this
    val change = ModuleToggleChange(current, enabled)
    return copy(toggleChanges = toggleChanges + (id to change)).presentToggle(id, change::present)
}

internal fun ModuleUiState.finishModuleToggle(id: String, success: Boolean): ModuleUiState {
    val change = toggleChanges[id] ?: return this
    return copy(toggleChanges = toggleChanges - id).presentToggle(id) { module ->
        if (success) change.present(module) else module.copy(enabled = change.confirmed.enabled,
            needsReboot = change.confirmed.needsReboot)
    }
}

private fun ModuleUiState.presentToggle(id: String, project: (Module) -> Module): ModuleUiState {
    fun List<Module>.present() = map { if (it.id == id) project(it) else it }
    return copy(modules = modules.present(), moduleList = moduleList.present(), searchResults = searchResults.present())
}
