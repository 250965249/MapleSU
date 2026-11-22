package dev.maplesu.manager.jailbreak

import java.io.File
import org.json.JSONObject

/** Persistent per-attempt evidence, including attempts made before a reboot. */
object JailbreakDiagnostics {
    val liveFiles = linkedMapOf(
        "native-stage.log" to "native-stage.log",
        "maplesu-ultravider.log" to "maplesu-ultravider.log",
        "maplesu-hook.json" to "maplesu-hook.json",
        "maplesu-hook-attest.json" to "maplesu-hook-attest.json",
        "maplesu-hook-unload.json" to "maplesu-hook-unload.json",
        "maplesu-hook-daemon.json" to "maplesu-hook-daemon.json",
        "maplesu-handover.json" to "maplesu-handover.json",
        "maplesu-93260-source.json" to "maplesu-93260-source.json",
        "maplesu-handover-env" to "maplesu-handover-env.log",
        "maplesu-hook-env" to "maplesu-hook-env.log",
        "maplesu-teardown" to "maplesu-teardown.log",
        "stage-marks" to "stage-marks.log",
        "launcher-output" to "launcher-output.log",
        "su-audit.log" to "su-audit.log",
        "su-audit.log.1" to "su-audit.1.log",
    )

    @JvmStatic
    fun attemptDirectory(filesDirectory: File, attemptId: String): File {
        require(Regex("[A-Za-z0-9_-]{1,128}").matches(attemptId)) { "JAILBREAK_DIAGNOSTICS_ATTEMPT_INVALID" }
        return File(filesDirectory, "jailbreak/attempts/$attemptId").apply { mkdirs() }
    }

    /** Bind the live reader before admission or a provider process has produced status. */
    fun begin(filesDirectory: File, request: JailbreakRequest) {
        val directory = attemptDirectory(filesDirectory, request.attemptId)
        File(directory, "request.json").writeText(JSONObject().apply {
            put("attemptId", request.attemptId)
            put("method", request.method)
            put("rootBackend", request.rootBackend ?: JSONObject.NULL)
            put("startedAtMillis", System.currentTimeMillis())
        }.toString())
        progress(filesDirectory, request, "request", "method=${request.method} backend=${request.rootBackend} softReboot=${request.softReboot}")
    }

    /** Diagnostics only: progress messages never advance the provider state machine. */
    @Synchronized
    fun progress(filesDirectory: File, request: JailbreakRequest, step: String, message: String) {
        runCatching {
            File(attemptDirectory(filesDirectory, request.attemptId), "progress.jsonl").appendText(
                JSONObject().put("updatedAtMillis", System.currentTimeMillis())
                    .put("step", step).put("message", message).toString() + "\n")
        }.onFailure { android.util.Log.w("JailbreakDiagnostics", "Progress log failed", it) }
    }

    /** Caller-side errors are diagnostics, never a provider status or readiness claim. */
    fun recordOutcome(filesDirectory: File, request: JailbreakRequest, outcome: JailbreakController.Outcome) {
        val document = JSONObject().apply {
            put("method", request.method)
            put("rootBackend", request.rootBackend ?: JSONObject.NULL)
            put("attemptId", request.attemptId)
            put("bootId", request.bootId ?: JSONObject.NULL)
            put("stage", outcome.stage)
            put("message", outcome.message)
            put("failure", outcome.failure ?: JSONObject.NULL)
            put("completedAtMillis", System.currentTimeMillis())
        }
        File(attemptDirectory(filesDirectory, request.attemptId), "caller-outcome.json").writeText(document.toString())
    }

    fun record(protectedDirectory: File, filesDirectory: File, status: JailbreakStatus, json: String) {
        val attempt = status.attemptId ?: return
        val directory = attemptDirectory(filesDirectory, attempt)
        File(directory, "status.json").writeText(json)
        File(directory, "status-history.jsonl").appendText(json.trim() + "\n")
        // Early admission runs before old fixed-path evidence is cleared.
        if (status.stage == JailbreakStatus.STAGE_IDLE || status.stage == JailbreakStatus.STAGE_TARGET_CHECKED) return
        liveFiles.forEach { (source, name) ->
            val file = File(protectedDirectory, source)
            if (file.isFile && file.lastModified() >= status.startedAtMillis) {
                runCatching { file.copyTo(File(directory, name), overwrite = true) }
            }
        }
    }
}
