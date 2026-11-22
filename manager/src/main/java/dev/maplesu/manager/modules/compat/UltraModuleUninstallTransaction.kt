package dev.maplesu.manager.modules.compat

import dev.maplesu.manager.runtime.ultra.UltraOutcome
import dev.maplesu.manager.runtime.ultra.UltraPhase
import dev.maplesu.manager.runtime.ultra.UltraReceipt
import java.net.URLDecoder
import java.util.UUID

/** Uninstall once, then confirm one SDK list snapshot before removing the catalog entry. */
class UltraModuleUninstallTransaction(
    private val host: UltraModuleHost,
    private val removeCatalog: (String) -> Unit,
) {
    fun uninstall(id32: String): UltraReceipt = uninstall(id32, UUID.randomUUID().toString())

    internal fun uninstall(id32: String, operationId: String,
                           onCommitted: (String) -> Unit = {}): UltraReceipt {
        val receipt = host.uninstallModule(id32)
        val correctOperation = receipt.operation == "uninstall_module"
        if (!correctOperation || !(receipt.succeeded || receipt.operationCompleted)) {
            return UltraReceipt.of(
                operationId, "uninstall_module", receipt, UltraPhase.HOST_CALLED,
                if (receipt.succeeded || receipt.bool("reconciliationRequired") == true) UltraOutcome.NEEDS_RECONCILIATION
                else UltraOutcome.FAILED,
                moduleId = id32,
            )
        }
        onCommitted(id32)
        val listed = host.moduleList()
        val rows = listed.array("modules")
        var postState: String? = null
        var validList = listed.operation == "get_all_modules_list" && listed.succeeded && rows != null
        if (validList) {
            for (index in 0 until rows!!.length()) {
                val row = rows.optJSONObject(index)
                val encodedId = row?.optJSONObject("desc")?.optString("id32").orEmpty()
                val decodedId = runCatching { URLDecoder.decode(encodedId, "UTF-8") }.getOrNull()
                if (decodedId.isNullOrBlank()) validList = false
                if (decodedId == id32) {
                    if (postState != null) validList = false
                    postState = row?.optString("state").orEmpty()
                }
            }
        }
        var outcome = when {
            !validList -> UltraOutcome.NEEDS_RECONCILIATION
            postState == null -> UltraOutcome.COMPLETED
            postState == "RemovedPendingReboot" -> UltraOutcome.PENDING_REBOOT
            else -> UltraOutcome.NEEDS_RECONCILIATION
        }
        var cleanup = "catalog_record_kept"
        if (outcome == UltraOutcome.COMPLETED) {
            if (runCatching { removeCatalog(id32) }.isSuccess) cleanup = "catalog_record_removed"
            else {
                outcome = UltraOutcome.NEEDS_RECONCILIATION
                cleanup = "catalog_record_removal_failed"
            }
        }
        return UltraReceipt.of(
            operationId, "uninstall_module", if (listed.succeeded || !receipt.succeeded) receipt else listed,
            UltraPhase.BUSINESS_PROBED, outcome, moduleId = id32,
            needsReboot = outcome == UltraOutcome.PENDING_REBOOT,
            cleanupOutcome = cleanup,
            unknowns = buildMap {
                if (outcome == UltraOutcome.NEEDS_RECONCILIATION) {
                    put("postState", if (!validList) "module_list_unverified" else postState.orEmpty())
                    if (!listed.succeeded) put("moduleList", listed.reason ?: listed.sdkError)
                }
            },
        )
    }
}
