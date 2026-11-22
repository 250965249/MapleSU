package dev.maplesu.manager.installer

/** Runtime confirmation is independent of image write/readback confirmation. */
internal object VivoCompatibilityStatus {
    fun requireActive(mode: String, filterStatus: String, modules: String) {
        val active = when (mode) {
            "LITE" -> filterStatus.trim() in setOf("Y", "1", "KERNEL_VERIFIED")
            "KSU" -> filterStatus.lineSequence().any { it.trim() == "Value: 1" } &&
                filterStatus.lineSequence().any { it.trim() == "Feature: vr_filter (7)" }
            else -> false
        }
        check(active) { "INSTALLER_VR_FILTER_INACTIVE" }
        check(modules.lineSequence().none { it.substringBefore(' ') == "vr" }) { "INSTALLER_VR_ALREADY_LOADED" }
    }
}
