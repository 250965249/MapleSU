package dev.maplesu.manager.installer

/** Only an unfinished task belongs on the install page. Actions require the task's own capabilities. */
internal data class InstallerTaskPresentation(
    val state: String = "",
    val kind: String = "",
    val operationActive: Boolean = false,
    val canCancel: Boolean = false,
    val canRestore: Boolean = false,
    val rebootRequired: Boolean = false,
    val loading: Boolean = false,
    val readFailed: Boolean = false,
) {
    val visible: Boolean
        get() = loading || readFailed || rebootRequired || state !in TERMINAL_STATES &&
            (operationActive || state in UNFINISHED_STATES)

    val actionsReady: Boolean get() = !loading && !readFailed && !operationActive
    val showCancel: Boolean get() = actionsReady && canCancel
    val showRestore: Boolean get() = actionsReady && canRestore
    val showReboot: Boolean get() = actionsReady && rebootRequired
    val showContinue: Boolean
        get() = actionsReady && state == "PREPARED" && kind !in setOf("NATIVE", "MODE_SWITCH")

    companion object {
        private val TERMINAL_STATES = setOf("", "NONE", "VERIFIED", "BOOT_VERIFIED", "STOCK_RESTORED", "OWNED_WRITES_REMOVED", "CANCELLED", "RESTORED", "ROLLED_BACK")
        private val UNFINISHED_STATES = setOf(
            "BEGIN", "SNAPSHOT", "PRODUCE", "COMMIT", "VERIFYING", "ROLLING_BACK", "PREPARING", "PREPARED",
            "WRITING", "RESTORING", "RECOVERY_REQUIRED", "REBOOT_REQUIRED", "REBOOT_REQUESTED",
            "BOOT_IMAGE_VERIFIED", "FAILED_PRE_WRITE", "FAILED_BEFORE_WRITE",
        )
    }
}
