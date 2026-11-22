package dev.maplesu.manager.workmode.ui

/** Readiness is a verified listener/token/port pair, never merely a prepared config. */
object LiteHiddenRecoveryLinkPolicy {
    fun usesDirectDaemon(kernelRootService: Boolean): Boolean = kernelRootService

    fun isReady(started: Boolean, actualPort: Int, linkPort: Int, authenticatedProbe: Boolean): Boolean =
        started && actualPort in 1024..65535 && actualPort == linkPort && authenticatedProbe

    fun canActivate(canConfirm: Boolean, linkReady: Boolean, copied: Boolean, preparing: Boolean): Boolean =
        canConfirm && linkReady && copied && !preparing
}
