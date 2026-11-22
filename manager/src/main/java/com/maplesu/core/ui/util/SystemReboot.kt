package com.maplesu.core.ui.util

import android.content.Context
import android.util.Log
import dev.maplesu.manager.jailbreak.DirtyfragAttempt
import dev.maplesu.manager.jailbreak.JailbreakRequest
import dev.maplesu.manager.jailbreak.JailbreakStatus
import dev.maplesu.manager.jailbreak.carrierBindsAttempt
import dev.maplesu.manager.ksu.KsuRootChannel
import dev.maplesu.manager.runtime.ultra.UltraSdkCredentials
import dev.maplesu.manager.runtime.NativeSu
import dev.maplesu.manager.runtime.RootExec
import dev.maplesu.manager.runtime.SuGate
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import java.io.File

/** Explicit user action. Call off the UI thread; success means the backend accepted the request. */
internal fun requestSystemReboot(context: Context, reason: String): Boolean {
    if (reason !in RebootDispatcher.REASONS) return false
    return try {
        val app = context.applicationContext
        val jailbreak = JailbreakStatus.read(app)?.takeIf {
            /*
             * T11: readiness comes from the record plus its carrier-proof binding; a
             * proof written for another attempt or boot must not authorize a reboot
             * through this record.
             */
            it.stage == JailbreakStatus.STAGE_DAEMON_READY && it.failure == null &&
                it.bootId == DirtyfragAttempt.readBootId() && carrierBindsAttempt(it)
        }
        /*
         * T11: the attempt that just succeeded owns the reboot. The work mode is the
         * fallback only - an Ultra attempt on a Normal-mode device used to select the
         * KSU backend (absent) and the soft reboot silently never happened.
         */
        val hook = jailbreak?.takeIf { it.rootBackend == JailbreakRequest.BACKEND_HOOK }
        val normal = when {
            hook != null -> false
            jailbreak?.rootBackend == JailbreakRequest.BACKEND_KSU -> true
            else -> when (ModeRuntime.active) {
                WorkMode.KSU -> true
                WorkMode.LITE -> false
                null -> false
            }
        }
        val backend = RebootDispatcher.backend(
            normal = normal,
            hook = hook != null,
            // The attempt that just succeeded owns the reboot: a live hook record must
            // not be outranked by a Ultra identity that has no session for this attempt.
            ultraRunning = hook == null && UltraEnvironmentProbe.isRunning(),
            verifiedUltraIdentity = hook == null && UltraEnvironmentProbe.usesUltraBackend(app),
        )
        fun runRoot(command: String): Boolean = when (backend) {
            RebootBackend.NORMAL -> KsuRootChannel().exec(app, command, globalMnt = true).code == 0
            RebootBackend.HOOK -> {
                val gate = SuGate.read(app,
                    hook?.carrier?.attemptId ?: hook?.attemptId,
                    hook?.carrier?.bootId ?: hook?.bootId)
                if (!gate.armed) {
                    Log.w("MapleSUReboot", "gate not armed for this attempt")
                    false
                } else {
                    val result = NativeSu.executeScript(gate, command,
                        File(app.filesDir, NativeSu.FALLBACK_NAME))
                    // The only honest way to see which fallback fired: exit code + output.
                    Log.w("MapleSUReboot", "hook rc=" + result.code +
                        " out=" + result.out.take(200) + " err=" + result.err.take(200))
                    result.code == 0
                }
            }
            else -> runRebootRootCommand(app, command)
        }
        val executed = RebootDispatcher(
            backend = backend,
            restartUltra = {
                UltraSdkCredentials.client(app).restartZygote64().succeeded
            },
            runRoot = ::runRoot,
        ).execute(reason)
        if (!executed) {
            // Never fail silently again: this line is what was missing when a soft
            // reboot "did nothing" and logcat had no trace.
            Log.w("MapleSUReboot", "rejected backend=" + backend + " reason=" + reason)
        }
        executed
    } catch (error: Exception) {
        Log.w("MapleSUReboot", "Reboot request failed", error)
        false
    }
}

/** Shared with the read-only device regression; this function never retries the submitted script. */
internal fun runRebootRootCommand(context: Context, command: String): Boolean {
    return RootExec.execute(context, command).ok
}
