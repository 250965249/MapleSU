package com.maplesu.core.data.model

import androidx.compose.runtime.Immutable

@Immutable
data class Module(
    val id: String,
    val name: String,
    val author: String,
    val version: String,
    val versionCode: Int,
    val description: String,
    val enabled: Boolean,
    val update: Boolean,
    val remove: Boolean,
    val updateJson: String,
    val hasWebUi: Boolean,
    val hasActionScript: Boolean,
    val metamodule: Boolean,
    val actionIconPath: String?,
    val webUiIconPath: String?,
    val runtimeStatus: String = "",
    val runtimeExitCode: Int? = null,
    val canToggle: Boolean = true,
    /** T4: capabilities this backend cannot serve for the module (never empty in practice). */
    val unsupported: List<String> = emptyList(),
    /** T4: applied `system.prop` entries (`key=value`). */
    val propsApplied: List<String> = emptyList(),
    /** T4: failed `system.prop` entries (`key=value:reason`). */
    val propsFailed: List<String> = emptyList(),
    /** T6: shipped by the Manager and installed by default (UI-only fact). */
    val builtin: Boolean = false,
    val needsReboot: Boolean = false,
    val preinit: String = "",
    /** Original list-row metadata for the first WebUI bridge query; never an authority. */
    val webUiInfoJson: String? = null,
)
