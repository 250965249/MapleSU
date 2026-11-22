package dev.maplesu.manager.workmode.boot

/** Unresolved startup may skip idle time, never the live detection/handshake. */
internal object PairedStartupPolicy {
    fun shouldExpedite(
        modeResolved: Boolean,
        suspended: Boolean,
    ): Boolean = !modeResolved && !suspended

    /** Called only after phase one. No KSU evidence means defer to the original path. */
    fun refreshEnvironmentIfEligible(
        modeResolved: Boolean,
        ksuResponded: Boolean?,
        readRunning: () -> Boolean,
    ): Boolean {
        if (modeResolved || ksuResponded != false) return false
        return runCatching { readRunning() }.getOrDefault(false)
    }
}
