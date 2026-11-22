package com.maplesu.core.ui.util

import androidx.annotation.StringRes
import com.maplesu.core.R
import dev.maplesu.manager.runtime.State

/** Labels report authorization and delivery without prescribing a target launch. */
@StringRes
fun suStateLabel(state: State): Int = when (state) {
    State.NOT_AUTHORIZED -> R.string.maplesu_state_not_authorized
    State.DELIVERED -> R.string.maplesu_state_delivered
    State.PENDING_WIRING -> R.string.maplesu_state_pending_wiring
    State.AUTHORIZATION_PENDING -> R.string.maplesu_state_authorization_pending
    State.ENTRY_UNAVAILABLE -> R.string.maplesu_state_entry_unavailable
    State.WIRED -> R.string.maplesu_state_wired
    // The application was updated or reinstalled after it was authorized, so the record no
    // longer admits it. The wording has to say that, otherwise the user sees a grant that
    // silently stopped working.
    State.STALE -> R.string.maplesu_state_stale
}
