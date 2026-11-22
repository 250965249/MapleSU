package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootExecResult

/** Only readiness may bind/start a daemon. A mutation keeps the already selected Binder. */
internal class ModeSwitchRootBinderOwner<T>(
    private val bind: () -> T,
    private val alive: (T) -> Boolean,
) {
    private var service: T? = null

    @Synchronized
    fun prepare(): RootExecResult {
        val selected = bind()
        check(alive(selected)) { ModeSwitchRootProtocol.UNAVAILABLE }
        service = selected
        return RootExecResult(RootBackend.ULTRA_ENV, 0, "")
    }

    @Synchronized
    fun current(): T = checkNotNull(service) { ModeSwitchRootProtocol.UNAVAILABLE }.also {
        check(alive(it)) { ModeSwitchRootProtocol.UNAVAILABLE }
    }
}
