package dev.maplesu.manager.workmode.detect.probes

import android.content.Context
import dev.maplesu.manager.jailbreak.JailbreakRequest
import dev.maplesu.manager.jailbreak.JailbreakStatus
import dev.maplesu.manager.runtime.NativeSuDaemon
import dev.maplesu.manager.runtime.TrustedRuntime
import dev.maplesu.manager.workmode.detect.JailbreakLeaseProbe
import dev.maplesu.manager.workmode.detect.ProcBootIdSource

/**
 * 越狱租约适配器（`TrustedRuntime.state()/origin()`）。
 * Hook 会话重新证明真实 SU 通道并恢复发布；不运行提权。普通租约保留既有判据。
 */
class JailbreakLeaseAdapter internal constructor(
    private val status: () -> JailbreakStatus?,
    private val reproveHook: () -> String?,
    private val leaseState: () -> TrustedRuntime.State,
    private val bootId: () -> String? = { ProcBootIdSource.read() },
) : JailbreakLeaseProbe {
    constructor(context: Context) : this(
        status = { JailbreakStatus.read(context.applicationContext) },
        reproveHook = { NativeSuDaemon.reproveHook(context.applicationContext) },
        leaseState = { TrustedRuntime.jailbreakState(context.applicationContext) },
    )

    override fun valid(): Boolean = runCatching {
        val record = status() ?: return false
        if (record.stage != JailbreakStatus.STAGE_DAEMON_READY ||
            !record.claimsCurrentBoot(bootId())) return false
        if (record.rootBackend == JailbreakRequest.BACKEND_HOOK) {
            val attempt = record.attemptId
            !attempt.isNullOrBlank() && reproveHook() == attempt
        } else {
            val state = leaseState()
            state.ready && state.origin == TrustedRuntime.Origin.JAILBREAK
        }
    }.getOrDefault(false)
}
