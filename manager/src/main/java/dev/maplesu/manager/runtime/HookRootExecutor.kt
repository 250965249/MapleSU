package dev.maplesu.manager.runtime

import android.content.Context
import dev.maplesu.manager.jailbreak.DirtyfragAttempt
import dev.maplesu.manager.jailbreak.JailbreakRequest
import dev.maplesu.manager.jailbreak.JailbreakStatus
import java.io.File
import java.util.concurrent.TimeUnit

/** Root carried by the current Ultra Hook attempt, independent of Ultra SDK pairing. */
class HookRootExecutor(
    private val status: () -> JailbreakStatus?,
    private val bootId: () -> String?,
    private val readGate: (String, String) -> SuGate.Gate,
    private val runScript: (SuGate.Gate, String, Int) -> NativeSu.SuResult,
    private val timeoutMillis: Int = NativeSu.DEFAULT_TIMEOUT_MILLIS,
) : RootExecutor {
    override val backend = RootBackend.HOOK

    private fun gate(): SuGate.Gate {
        val current = status() ?: return SuGate.Gate.UNAVAILABLE_GATE
        val boot = bootId()?.takeIf { it.isNotBlank() } ?: return SuGate.Gate.UNAVAILABLE_GATE
        val attempt = current.attemptId?.takeIf { it.isNotBlank() } ?: return SuGate.Gate.UNAVAILABLE_GATE
        if (current.stage != JailbreakStatus.STAGE_DAEMON_READY || current.failure != null ||
            current.rootBackend != JailbreakRequest.BACKEND_HOOK || current.bootId != boot
        ) return SuGate.Gate.UNAVAILABLE_GATE
        return readGate(attempt, boot).takeIf {
            it.armed && it.attempt == attempt && it.bootId == boot
        } ?: SuGate.Gate.UNAVAILABLE_GATE
    }

    override fun available(): Boolean = runCatching { gate().armed }.getOrDefault(false)

    override fun run(script: String): RootExecResult {
        val current = runCatching { gate() }.getOrDefault(SuGate.Gate.UNAVAILABLE_GATE)
        if (!current.armed) return RootExecResult(backend, NativeSu.EXIT_GATE_DENIED, "", SuGate.ERROR_NOT_ARMED)
        if (Thread.currentThread().isInterrupted) {
            return RootExecResult(backend, -1, "", "ROOT_EXECUTION_INTERRUPTED")
        }
        val timeout = PageReadDeadline.currentNanos()?.let { deadline ->
            val remaining = deadline - System.nanoTime()
            if (remaining <= 0) return RootExecResult(backend, -1, "", "ROOT_EXECUTION_BUSY")
            minOf(timeoutMillis.toLong(), TimeUnit.NANOSECONDS.toMillis(remaining).coerceAtLeast(1L)).toInt()
        } ?: timeoutMillis
        val result = runScript(current, script, timeout)
        return RootExecResult(backend, result.code, result.out, result.err)
    }

    companion object {
        fun production(context: Context, timeoutMillis: Int = NativeSu.DEFAULT_TIMEOUT_MILLIS): HookRootExecutor {
            val app = context.applicationContext
            return HookRootExecutor(
                status = { JailbreakStatus.read(app) },
                bootId = { DirtyfragAttempt.readBootId() },
                readGate = { attempt, boot -> SuGate.read(app, attempt, boot) },
                runScript = { gate, script, timeout ->
                    NativeSu.executeScript(gate, script, File(app.filesDir, NativeSu.FALLBACK_NAME), timeout)
                },
                timeoutMillis = timeoutMillis,
            )
        }
    }
}
