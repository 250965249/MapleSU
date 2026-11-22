package dev.maplesu.manager.runtime.ultra

/** One bounded repair per request; only a fresh SDK observation decides whether to retry. */
internal object UltraAutoSetupAttempt {
    interface Port {
        fun blockedReason(): String?
        fun state(): UltraEnvironmentProbe.State
        fun recordAttempt()
        fun install(): UltraEnvironmentInstaller.Outcome
        fun refresh()
    }

    fun run(port: Port, recoverIdle: () -> UltraEnvironmentAutoSetup.Result? = { null }): UltraEnvironmentAutoSetup.Result {
        fun skipped(reason: String) = UltraEnvironmentAutoSetup.Result(false, false, reason)
        port.blockedReason()?.let { return skipped(it) }
        val state = runCatching { port.state() }.getOrElse { return skipped("PROBE_FAILED") }
        when (state) {
            UltraEnvironmentProbe.State.Running -> return skipped("ALREADY_RUNNING")
            UltraEnvironmentProbe.State.NotInstalled -> Unit
            UltraEnvironmentProbe.State.Unknown -> return recoverIdle() ?: skipped("STATE_$state")
            else -> return skipped("STATE_$state")
        }
        // Probe may block across a key change, reboot, pause, or mode switch.
        port.blockedReason()?.let { return skipped(it) }
        // Diagnostics never suppress a later foreground request after a failed
        // submission. Running/Unknown/Fault are reconciled by the next live probe.
        runCatching { port.recordAttempt() }
        port.blockedReason()?.let { return skipped(it) }
        val outcome = try {
            port.install()
        } catch (error: Exception) {
            if (error is InterruptedException) Thread.currentThread().interrupt()
            return UltraEnvironmentAutoSetup.Result(true, false, "EXCEPTION:${error.javaClass.simpleName}")
        }
        runCatching { port.refresh() }
        val installed = outcome.ok && outcome.verified
        return UltraEnvironmentAutoSetup.Result(true, installed, when {
            !outcome.ok -> "SDK_ERROR_${outcome.sdkError}"
            !outcome.verified -> "INSTALL_UNVERIFIED"
            else -> "INSTALLED"
        })
    }
}
