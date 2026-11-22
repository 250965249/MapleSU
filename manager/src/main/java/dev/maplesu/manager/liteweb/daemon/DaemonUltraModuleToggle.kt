package dev.maplesu.manager.liteweb.daemon

import dev.maplesu.manager.liteweb.LiteWebToggleView
import dev.maplesu.manager.modules.compat.UltraModuleHost
import dev.maplesu.manager.modules.compat.UltraModuleToggleTransaction
import dev.maplesu.manager.modules.compat.validUltraModuleControlId
import dev.maplesu.manager.runtime.ultra.UltraOutcome
import dev.maplesu.manager.runtime.ultra.UltraReceipt

/** Same persistence/readback transaction as the app, without Android process state. */
internal class DaemonUltraModuleToggle(
    host: UltraModuleHost,
    mutationAllowed: () -> Boolean,
    private val journal: (UltraReceipt) -> Unit,
) {
    private val transaction = UltraModuleToggleTransaction(host, mutationAllowed, journal)

    fun setEnabled(moduleId: String, enabled: Boolean): LiteWebToggleView {
        if (!moduleId.startsWith("maplesu:") || !validUltraModuleControlId(moduleId.removePrefix("maplesu:"))) {
            return LiteWebToggleView.Failed("MODULE_ID_INVALID", moduleId)
        }
        val receipt = transaction.setEnabled(moduleId.removePrefix("maplesu:"), enabled)
        journal(receipt)
        return when (receipt.outcome) {
            UltraOutcome.COMPLETED, UltraOutcome.PENDING_REBOOT -> LiteWebToggleView.Ok(moduleId, enabled, receipt.needsReboot)
            else -> LiteWebToggleView.Failed(receipt.outcome.name, "Module state requires a fresh read")
        }
    }
}
