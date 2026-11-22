package dev.maplesu.manager.workmode.ui

import androidx.compose.runtime.Immutable
import dev.maplesu.manager.workmode.recovery.RecoveryAction
import dev.maplesu.manager.workmode.recovery.RecoveryControl
import dev.maplesu.manager.workmode.recovery.RecoveryDecision
import dev.maplesu.manager.workmode.switch.BaselineState

@Immutable
data class RecoveryUiState(
    val switchId: String = "",
    val loading: Boolean = true,
    val decision: RecoveryDecision? = null,
    val baselineState: BaselineState? = null,
    val readFailed: Boolean = false,
    val exportStatus: String? = null,
    val error: String? = null,
) {
    val unavailable: Boolean get() = !loading && (decision == null || readFailed)
    val diagnosticOnly: Boolean get() = decision?.diagnosticOnly == true
    val requiresExternalImage: Boolean get() = decision?.requiresExternalImage == true
    val action: RecoveryAction? get() = decision?.action
    // A failed refresh retains the last running decision and its navigation lock.
    val blocksBack: Boolean get() = action == RecoveryAction.IN_PROGRESS
    fun allows(control: RecoveryControl): Boolean =
        !loading && !readFailed && decision?.allows(control) == true
    fun blocks(control: RecoveryControl): Boolean = decision?.blocks(control) == true
}
