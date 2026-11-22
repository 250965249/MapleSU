package com.maplesu.core.ui.webui.file

import com.topjohnwu.superuser.Shell

/** Only observes bridge destruction/page gating; actual KsuIO has separate lifecycle tests. */
class KsuIO(
    private val shellFactory: () -> Shell = { error("Unexpected fixture shell") },
    private val pageCurrent: () -> Boolean = { true },
) {
    private var destroyed = false
    fun destroy() { destroyed = true }
    internal fun canOpenStream() = !destroyed && pageCurrent()
}
