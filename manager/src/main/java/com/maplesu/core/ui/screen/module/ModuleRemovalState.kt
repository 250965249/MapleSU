package com.maplesu.core.ui.screen.module

import com.maplesu.core.data.model.Module

/** Latest UI intent and last acknowledged state; SDK writes remain ordered per module. */
data class ModuleRemovalChange(val confirmed: Module, val remove: Boolean) {
    fun present(module: Module): Module = module.copy(
        remove = remove,
        runtimeStatus = if (!remove && module.runtimeStatus == "remove_pending") "" else module.runtimeStatus,
        canToggle = if (!remove && module.remove) true else module.canToggle,
    )
}

internal fun ModuleUiState.withModuleRemovalRequest(id: String, remove: Boolean): ModuleUiState {
    val current = modules.firstOrNull { it.id == id } ?: return this
    val change = removalChanges[id]?.copy(remove = remove) ?: ModuleRemovalChange(current, remove)
    return copy(removalChanges = removalChanges + (id to change)).presentRemoval(id, change::present)
}

internal fun ModuleUiState.withModuleRemovalResult(id: String, attempted: Boolean, success: Boolean): ModuleUiState {
    val change = removalChanges[id] ?: return this
    if (!success) return this
    val confirmed = change.copy(remove = attempted).present(change.confirmed)
    return copy(removalChanges = removalChanges + (id to change.copy(confirmed = confirmed)))
}

/** Failure rolls back only removal fields; unrelated updates and other rows survive. */
internal fun ModuleUiState.finishModuleRemoval(id: String): ModuleUiState {
    val change = removalChanges[id] ?: return this
    return copy(removalChanges = removalChanges - id).presentRemoval(id) { module ->
        module.copy(remove = change.confirmed.remove, runtimeStatus = change.confirmed.runtimeStatus,
            canToggle = change.confirmed.canToggle)
    }
}

private fun ModuleUiState.presentRemoval(id: String, project: (Module) -> Module): ModuleUiState {
    fun List<Module>.present() = map { if (it.id == id) project(it) else it }
    return copy(modules = modules.present(), moduleList = moduleList.present(), searchResults = searchResults.present())
}
