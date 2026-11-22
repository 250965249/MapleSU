package dev.maplesu.manager.modules.compat

import dev.maplesu.manager.runtime.ultra.NativeReceipt
import dev.maplesu.manager.runtime.ultra.UltraOutcome
import dev.maplesu.manager.runtime.ultra.UltraPhase
import dev.maplesu.manager.runtime.ultra.UltraReceipt
import java.util.UUID

internal fun validUltraModuleControlId(id: String): Boolean =
    id.isNotEmpty() && id != "." && id != ".." && '/' !in id && '\u0000' !in id &&
        id.toByteArray(Charsets.UTF_8).size < 1024

/** Persist desired state once and confirm a fresh SDK read; never replay lifecycle callbacks. */
class UltraModuleToggleTransaction(
    private val host: UltraModuleHost,
    private val mutationAllowed: () -> Boolean = { true },
    private val beforeMutation: (UltraReceipt) -> Unit = {},
) {
    fun setEnabled(id32: String, enabled: Boolean): UltraReceipt {
        val operationId = UUID.randomUUID().toString()
        fun result(native: NativeReceipt?, outcome: UltraOutcome, reboot: Boolean = false) = UltraReceipt.of(
            operationId, "set_module_enabled", native, UltraPhase.BUSINESS_PROBED, outcome,
            moduleId = id32, needsReboot = reboot,
        )
        if (!validUltraModuleControlId(id32) || !mutationAllowed()) {
            return result(NativeReceipt.bridgeFailure("set_module_enabled", "MAPLESU_MODULE_CONTROL_CONDITION",
                "Module ID or active mode changed"), UltraOutcome.CONDITION_UNMET)
        }
        val initial = host.moduleControl(id32)
        if (!valid(initial, id32)) return result(initial, UltraOutcome.CONDITION_UNMET)
        if (!mutationAllowed()) return result(null, UltraOutcome.CONDITION_UNMET)
        if (initial.bool("enabled") == enabled) {
            return result(initial, if (initial.bool("needsReboot") == true) UltraOutcome.PENDING_REBOOT
                else UltraOutcome.COMPLETED, initial.bool("needsReboot") == true)
        }
        try {
            beforeMutation(UltraReceipt.of(operationId, "set_module_enabled", initial, UltraPhase.PREPARED,
                UltraOutcome.NEEDS_RECONCILIATION, moduleId = id32))
        } catch (error: Exception) {
            if (error is java.util.concurrent.CancellationException) throw error
            if (error is InterruptedException) {
                Thread.currentThread().interrupt()
                throw error
            }
            return UltraReceipt.of(operationId, "set_module_enabled", null, UltraPhase.PREPARED,
                UltraOutcome.FAILED, moduleId = id32,
                unknowns = mapOf("operationLog" to (error.message ?: "operation_log_write_failed")))
                .copy(sdkError = "MAPLESU_OPERATION_LOG_WRITE_FAILED", sdkErrorCode = -1001,
                    reason = "The state change was not submitted because its operation record could not be saved.")
        }
        if (!mutationAllowed()) return result(null, UltraOutcome.CONDITION_UNMET)
        val changed = host.setModuleEnabled(id32, enabled)
        val confirmed = host.moduleControl(id32)
        if (!changed.succeeded && !(changed.operation == "set_module_enabled" && changed.operationCompleted))
            return result(changed, if (changed.sdkError == "MAPLESU_MODULE_CONTROL_IO")
            UltraOutcome.NEEDS_RECONCILIATION else UltraOutcome.FAILED)
        val native = if (changed.succeeded) confirmed else changed
        if (!mutationAllowed() || !valid(confirmed, id32) || confirmed.bool("enabled") != enabled) {
            return result(native, UltraOutcome.NEEDS_RECONCILIATION).copy(unknowns = mapOf(
                "moduleControl" to if (!confirmed.succeeded) confirmed.reason ?: confirmed.sdkError
                    else "module_control_unverified",
            ))
        }
        val reboot = confirmed.bool("needsReboot") == true
        return result(native, if (reboot) UltraOutcome.PENDING_REBOOT else UltraOutcome.COMPLETED, reboot)
    }

    private fun valid(receipt: NativeReceipt, id: String): Boolean {
        val data = receipt.data ?: return false
        return receipt.succeeded && receipt.string("id32") == id &&
            data.opt("abiVersion") == 1 && data.opt("supportsEnableToggle") == true &&
            data.opt("enabled") is Boolean && data.opt("needsReboot") is Boolean &&
            receipt.string("runtimeState") in setOf("NotRunning", "Running", "Abnormal")
    }
}
