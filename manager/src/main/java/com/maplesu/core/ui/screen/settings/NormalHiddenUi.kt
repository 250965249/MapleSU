package com.maplesu.core.ui.screen.settings

import dev.maplesu.manager.liteweb.RecoveryWebUiState
import dev.maplesu.manager.litehidden.HiddenModePolicy

/** Presentation only. The recovery URL stays in the ViewModel, outside settings snapshots. */
data class NormalHiddenUi(
    val visible: Boolean = false,
    val preparing: Boolean = false,
    val activating: Boolean = false,
    val checkingWebUi: Boolean = false,
    val webUiState: RecoveryWebUiState = RecoveryWebUiState.UNKNOWN,
    val linkAvailable: Boolean = false,
    val linkAccessed: Boolean = false,
    val linkSaved: Boolean = false,
    val failure: NormalHiddenFailure? = null,
    val completed: Boolean = false,
    val portText: String = HiddenModePolicy.defaultPort().toString(),
) {
    val portValid: Boolean get() = HiddenModePolicy.validatePort(portText).valid
    val busy: Boolean get() = preparing || activating || checkingWebUi
    val canPrepare: Boolean get() = visible && !busy && !completed
    val canConfirm: Boolean
        get() = canPrepare && portValid && webUiState != RecoveryWebUiState.STOPPED && linkAvailable && linkAccessed && linkSaved
    val canSaveLink: Boolean
        get() = canPrepare && webUiState != RecoveryWebUiState.STOPPED && linkAvailable && linkAccessed && !linkSaved
    fun withPort(raw: String): NormalHiddenUi {
        if (!canPrepare) return this
        val digits = raw.filter { it in '0'..'9' }.take(5)
        if (digits == portText) return this
        return copy(portText = digits, linkAvailable = false, linkAccessed = false, linkSaved = false, failure = null)
    }
}

enum class NormalHiddenFailure { PREPARE, ACTIVATE, COPY, OPEN }
