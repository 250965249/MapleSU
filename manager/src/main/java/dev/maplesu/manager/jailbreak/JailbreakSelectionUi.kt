package dev.maplesu.manager.jailbreak

/** Presentation gates only; execution still uses the existing admission checks. */
internal data class JailbreakSelectionUi(
    val method: JailbreakMethod,
    val ghostlockReady: Boolean,
    val shizukuReady: Boolean = false,
) {
    val showGhostlockConfiguration: Boolean
        get() = method == JailbreakMethod.GHOSTLOCK && !ghostlockReady

    fun canStart(
        running: Boolean,
        checksReady: Boolean,
        blockersPresent: Boolean,
        parsing: Boolean,
        awaitingOverwrite: Boolean,
    ): Boolean = !running && checksReady && !blockersPresent && !parsing &&
        when (method) {
            JailbreakMethod.DIRTYFRAG -> true
            JailbreakMethod.GHOSTLOCK -> ghostlockReady && !awaitingOverwrite
            JailbreakMethod.MAPLESU_93260 -> shizukuReady
            JailbreakMethod.GHOSTSAM -> true // admission + artifact + capability gate decide
        }
}
