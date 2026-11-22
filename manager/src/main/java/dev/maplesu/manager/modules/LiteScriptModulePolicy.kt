package dev.maplesu.manager.modules

import dev.maplesu.manager.ModuleArchiveInspector.Report

/** Inventory only. Module requirements are handled by their runtime consumers. */
internal object LiteScriptModulePolicy {
    private val optionalTools = setOf("busybox", "resetprop", "unzip", "zip", "curl", "wget", "sqlite3")

    @Suppress("UNUSED_PARAMETER")
    fun check(report: Report, scripts: Map<String, String>): Set<String> = linkedSetOf<String>().apply {
        scripts.values.forEach { text ->
            val executable = text.lineSequence().filterNot { it.trimStart().startsWith('#') }.joinToString("\n")
            optionalTools.filterTo(this) {
                Regex("(?<![A-Za-z0-9_])$it(?![A-Za-z0-9_])").containsMatchIn(executable)
            }
        }
    }
}
