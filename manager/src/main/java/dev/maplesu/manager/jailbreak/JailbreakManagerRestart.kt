package dev.maplesu.manager.jailbreak

import android.content.Context
import android.util.Log
import com.maplesu.core.CrashReporter
import com.maplesu.core.R
import com.maplesu.core.ui.MainActivity
import dev.maplesu.manager.runtime.CarrierProver
import dev.maplesu.manager.workmode.backend.KsuBackendRegistry
import java.io.File

/** Restart only after the Provider has saved the completed Normal carrier proof. */
internal object JailbreakManagerRestart {
    fun required(method: JailbreakMethod, backend: String, outcome: JailbreakController.Outcome): Boolean =
        method == JailbreakMethod.MAPLESU_93260 && backend == JailbreakRequest.BACKEND_KSU &&
            outcome.stage == JailbreakStatus.STAGE_DAEMON_READY && outcome.failure == null &&
            !outcome.attemptId.isNullOrBlank()

    internal fun confirmed(outcome: JailbreakController.Outcome, status: JailbreakStatus?, boot: String?): Boolean {
        if (status == null || status.method != JailbreakMethod.MAPLESU_93260.wireName ||
            !required(JailbreakMethod.MAPLESU_93260, status.rootBackend.orEmpty(), outcome) ||
            status.stage != JailbreakStatus.STAGE_DAEMON_READY || status.failure != null ||
            status.attemptId != outcome.attemptId || !status.isCurrentBoot(boot)) return false
        val carrier = status.carrier ?: return false
        val probe = carrier.probe ?: return false
        return carrier.kind == CarrierProver.KIND_KSU && carrierBindsAttempt(status) &&
            probe.exitCode == 0 && probe.uid == 0 && probe.stdout.trim() == "0"
    }

    fun restart(context: Context, outcome: JailbreakController.Outcome): Boolean = runCatching {
        val status = JailbreakStatus.read(context)
        if (!confirmed(outcome, status, DirtyfragAttempt.readBootId())) return@runCatching false
        val request = JailbreakRequest(status!!.method, status.attemptId!!, status.bootId,
            softReboot = false, rootBackend = status.rootBackend)
        val directory = JailbreakDiagnostics.attemptDirectory(context.filesDir, request.attemptId)
        val ready = File(directory, "manager-restart.ready").apply { writeText("") }
        val log = File(directory, "manager-restart.log").apply { appendText("schedule ${request.attemptId}\n") }
        JailbreakDiagnostics.progress(context.filesDir, request, "restart",
            context.getString(R.string.maplesu_jailbreak_manager_restart))
        val accepted = KsuBackendRegistry.runNormalHandoverCommand(context, request,
            command(context.packageName, MainActivity::class.java.name, request.attemptId, ready, log))
        if (accepted) CrashReporter.clearSessionMarker(context)
        else JailbreakDiagnostics.progress(context.filesDir, request, "restart", "管理器重启派发失败，请手动重新打开")
        accepted
    }.onFailure { Log.w("MapleSUJailbreak", "Manager restart dispatch failed", it) }.getOrDefault(false)

    internal fun command(packageName: String, activity: String, attempt: String, ready: File, log: File): String {
        fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"
        val token = quote("scheduled:$attempt")
        // KsuRootChannel's ksud su leaves the App cgroup. This child also detaches
        // its streams and ignores HUP so force-stop cannot kill its own relaunch.
        val child = """
            trap '' HUP
            echo $token > ${quote(ready.path)} || exit 1
            /system/bin/sleep 2
            echo force-stop
            /system/bin/am force-stop --user 0 ${quote(packageName)} || exit 1
            echo relaunch
            /system/bin/am start --user 0 -n ${quote("$packageName/$activity")}
        """.trimIndent()
        return """
            /system/bin/nohup /system/bin/sh -c ${quote(child)} </dev/null >>${quote(log.path)} 2>&1 &
            for n in 1 2 3 4 5 6 7 8 9 10; do
                if [ "${'$'}(cat ${quote(ready.path)})" = $token ]; then exit 0; fi
                /system/bin/sleep 0.1
            done
            exit 1
        """.trimIndent()
    }
}
