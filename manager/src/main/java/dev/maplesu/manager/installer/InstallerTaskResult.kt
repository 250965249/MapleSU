package dev.maplesu.manager.installer

import com.maplesu.core.ui.util.FlashOutcome
import com.maplesu.core.ui.util.FlashResult

internal enum class ImageRestorationKind(val completedState: String) {
    EXACT_STOCK("STOCK_RESTORED"),
    OWNED_WRITES_REMOVED("OWNED_WRITES_REMOVED");

    companion object {
        fun fromWire(value: String?): ImageRestorationKind = when (value) {
            null, "", "EXACT_STOCK" -> EXACT_STOCK // Durable receipts from older releases were exact-only.
            "OWNED_WRITES_REMOVED" -> OWNED_WRITES_REMOVED
            else -> error("INSTALLER_RESTORATION_KIND_INVALID")
        }
    }
}

internal fun imageRestorationAfterBoot(previousBoot: String, currentBoot: String, kind: String?): ImageRestorationKind? {
    if (!previousBoot.matches(Regex("[0-9a-fA-F-]{36}")) ||
        !currentBoot.matches(Regex("[0-9a-fA-F-]{36}")) || previousBoot == currentBoot) return null
    return ImageRestorationKind.fromWire(kind)
}

/** Shared by the live result and a result recovered from its durable task. */
internal fun installerTaskResult(
    state: String,
    rebootRequired: Boolean,
    error: String = "",
    restoring: Boolean = false,
): FlashResult {
    val restored = state in setOf("RESTORED", "ROLLED_BACK")
    val stockRestored = state == "STOCK_RESTORED"
    val ownedRemoved = state == "OWNED_WRITES_REMOVED"
    val written = state in setOf("REBOOT_REQUIRED", "REBOOT_REQUESTED", "BOOT_IMAGE_VERIFIED", "BOOT_VERIFIED", "VERIFIED")
    val success = if (restoring) restored else written || stockRestored || ownedRemoved
    val outcome = when {
        restored || stockRestored -> FlashOutcome.RESTORED
        written || ownedRemoved -> FlashOutcome.WRITTEN
        state in setOf("BEGIN", "SNAPSHOT", "PRODUCE", "COMMIT", "VERIFYING", "ROLLING_BACK",
            "WRITING", "RESTORING", "RECOVERY_REQUIRED") -> FlashOutcome.RECOVERY_REQUIRED
        else -> FlashOutcome.FAILED
    }
    return FlashResult(if (success) 0 else 1,
        if (success) "" else error.ifBlank { "INSTALLER_INTERRUPTED_$state" },
        rebootRequired, outcome)
}
