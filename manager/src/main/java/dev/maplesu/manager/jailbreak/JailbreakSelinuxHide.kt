package dev.maplesu.manager.jailbreak

import android.content.Context
import android.util.Log
import dev.maplesu.manager.modules.ModuleToolDeployment
import dev.maplesu.manager.runtime.HookRootExecutor
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import org.json.JSONObject
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

data class JailbreakSelinuxHideState(
    val visible: Boolean = false,
    val requested: Boolean = false,
    val effective: Boolean? = false,
    val error: String? = null,
)

/** Observed per-attempt history, with an explicit kernel default when capture is denied. */
object JailbreakSelinuxHide {
    private const val PREFS = "jailbreak_selinux_hide"
    private const val ENABLED = "enabled"
    private const val BASELINE = "selinux-status-baseline"
    private const val NORMAL_BOOT = "normal_boot"
    private const val NORMAL_ATTEMPT = "normal_attempt"
    private const val NORMAL_EFFECTIVE = "normal_effective"
    private const val NORMAL_APPLIED = "normal_applied"
    private fun preferences(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private fun requested(context: Context) = preferences(context).getBoolean(ENABLED, true)
    private fun snapshot(context: Context, attempt: String) =
        File(DirtyfragAttempt.attemptDirectory(context), "$BASELINE-$attempt")

    fun capture(context: Context, request: JailbreakRequest) {
        if (request.rootBackend == JailbreakRequest.BACKEND_KSU) {
            val target = File(DirtyfragAttempt.attemptDirectory(context), "jailbreak-selinux-hide-request")
            target.writeText(if (requested(context)) "1\n" else "0\n")
            android.system.Os.chmod(target.path, 384)
            return
        }
        if (request.rootBackend != JailbreakRequest.BACKEND_HOOK) return
        runCatching {
            var captured = false
            for (retry in 1..4) {
                val bytes = File("/sys/fs/selinux/status").readBytes()
                if (!JailbreakSelinuxBaseline.stock(bytes)) continue
                captureSnapshot(context, request, bytes, "app")
                captured = true
                break
            }
            check(captured) { "JAILBREAK_SELINUX_STATUS_UNSTABLE" }
        }.onFailure {
            Log.w("MapleSUSELinux", "Pre-entry baseline capture failed", it)
            record(context, request.attemptId, "capture", JSONObject()
                .put("bootId", request.bootId).put("error", it.message ?: it.javaClass.simpleName))
        }
    }

    /** Shell is observed before RootFlow; a root window is stored separately. */
    internal fun captureShizuku(context: Context, request: JailbreakRequest, output: String) {
        if (request.rootBackend != JailbreakRequest.BACKEND_HOOK) return
        val words = output.trim().split(Regex("\\s+"))
        check(words.size == 5) { "JAILBREAK_SELINUX_BASELINE_SIZE" }
        val bytes = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
        for (word in words) {
            val value = word.toLongOrNull()
            check(value != null && value in 0..0xffffffffL) { "JAILBREAK_SELINUX_BASELINE_INVALID" }
            bytes.putInt(value.toInt())
        }
        captureSnapshot(context, request, bytes.array(), "shizuku")
    }

    private fun captureSnapshot(context: Context, request: JailbreakRequest, bytes: ByteArray, source: String) {
        val boot = DirtyfragAttempt.readBootId()
        check(boot == request.bootId) { "JAILBREAK_SELINUX_BOOT_CHANGED" }
        check(JailbreakSelinuxBaseline.stock(bytes)) { "JAILBREAK_SELINUX_BASELINE_INVALID" }
        val target = snapshot(context, request.attemptId)
        JailbreakSelinuxBaseline.atomicWrite(target, bytes)
        android.system.Os.chmod(target.path, 384)
        JailbreakSelinuxBaseline.atomicWrite(File(target.path + ".boot"), "$boot\n".toByteArray())
        val fields = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        record(context, request.attemptId, "capture", JSONObject().put("bootId", boot).put("source", source)
            .put("version", fields.int).put("sequence", fields.int).put("enforcing", fields.int)
            .put("policyload", fields.int).put("denyUnknown", fields.int))
    }

    private fun current(context: Context): JailbreakStatus? {
        val status = JailbreakStatus.read(context) ?: return null
        val bootId = DirtyfragAttempt.readBootId()
        if (bootId.isNullOrBlank() || status.stage != JailbreakStatus.STAGE_DAEMON_READY || status.failure != null ||
            status.bootId != bootId || status.attemptId.isNullOrBlank()) return null
        return when (ModeRuntime.active) {
            WorkMode.LITE -> status.takeIf {
                it.rootBackend == JailbreakRequest.BACKEND_HOOK &&
                    !dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe.usesUltraBackend(context) &&
                    HookRootExecutor.production(context).available()
            }
            WorkMode.KSU -> {
                if (status.rootBackend != JailbreakRequest.BACKEND_KSU) return null
                if (!com.maplesu.core.Natives.isLateLoadMode)
                    dev.maplesu.manager.workmode.backend.KsuBackendRegistry.prepareJailbreakManager(context)
                status.takeIf { com.maplesu.core.Natives.isLateLoadMode }
            }
            else -> null
        }
    }

    /** Called explicitly before late module tasks, after the authenticated root probe. */
    @Synchronized fun prepareHook(context: Context) {
        val status = current(context) ?: return
        if (status.rootBackend != JailbreakRequest.BACKEND_HOOK) return
        applyHook(context, status, requested(context))
    }

    private fun baseline(context: Context, status: JailbreakStatus): File? {
        val baseline = snapshot(context, checkNotNull(status.attemptId))
        check(DirtyfragAttempt.readBootId() == status.bootId) { "JAILBREAK_SELINUX_BOOT_CHANGED" }
        val directory = File(context.filesDir, "jailbreak/attempts/${status.attemptId}")
        val windows = directory.listFiles()?.filter { it.isDirectory && it.name.startsWith("ghostlock-") }
            ?.map { File(it, "selinux-window.json") }?.filter { it.exists() }.orEmpty()
        val selected = JailbreakSelinuxBaseline.select(baseline, checkNotNull(status.bootId),
            status.attemptId, windows) {
            val stat = android.system.Os.lstat(it.path)
            stat.st_uid == 0 && stat.st_nlink == 1L && (stat.st_mode and 18) == 0 &&
                android.system.OsConstants.S_ISREG(stat.st_mode)
        }
        record(context, status.attemptId, "baseline", JSONObject().put("bootId", status.bootId)
            .put("source", selected.source).put("detail", selected.detail))
        return selected.file
    }

    private fun applyHook(context: Context, status: JailbreakStatus, enabled: Boolean) {
        runCatching {
            val data = queryHook(context)
            check(data.getBoolean("available")) { "JAILBREAK_SELINUX_BACKEND_UNAVAILABLE" }
            val prepared = if (data.getBoolean("initialized")) {
                if (data.getBoolean("effective") == enabled) data else {
                    check(data.optBoolean("toggleSupported", false)) { "JAILBREAK_SELINUX_SWITCH_UNSUPPORTED" }
                    queryHook(context, " set " + if (enabled) 1 else 0)
                }
            } else {
                val path = baseline(context, status)?.absolutePath?.replace("'", "'\\''")
                queryHook(context, (if (path == null) " default " else " '$path' ") + if (enabled) 1 else 0)
            }
            check(prepared.getBoolean("initialized") && prepared.getBoolean("effective") == enabled) {
                "JAILBREAK_SELINUX_REQUEST_NOT_APPLIED"
            }
            prepared
        }.onSuccess {
            record(context, checkNotNull(status.attemptId), "prepare", it.put("bootId", status.bootId)
                .put("requested", enabled))
        }.onFailure {
            record(context, checkNotNull(status.attemptId), "prepare", JSONObject()
                .put("bootId", status.bootId).put("requested", enabled)
                .put("error", it.message ?: it.javaClass.simpleName))
        }.getOrThrow()
    }

    private fun queryHook(context: Context, arguments: String = ""): JSONObject {
        val source = ModuleToolDeployment.policySource(context).absolutePath.replace("'", "'\\''")
        val result = HookRootExecutor.production(context).run("'$source' jailbreak-hide$arguments")
        check(result.ok) { "JAILBREAK_SELINUX_HOOK:${result.code}:${result.detail.take(256)}" }
        return JSONObject(result.output.trim())
    }

    fun read(context: Context): JailbreakSelinuxHideState {
        val status = runCatching { current(context) }.getOrNull() ?: return JailbreakSelinuxHideState()
        val target = requested(context)
        return runCatching {
            val effective = if (status.rootBackend == JailbreakRequest.BACKEND_KSU) {
                val prefs = preferences(context)
                val current = com.maplesu.core.data.repository.SettingsRepositoryImpl().isSelinuxHideEnabled()
                if (prefs.getString(NORMAL_BOOT, null) == status.bootId &&
                    prefs.getString(NORMAL_ATTEMPT, null) == status.attemptId && prefs.getBoolean(NORMAL_APPLIED, false) &&
                    prefs.getBoolean(NORMAL_EFFECTIVE, false) == current) current else null
            } else {
                val data = queryHook(context)
                check(data.getBoolean("available")) { "JAILBREAK_SELINUX_BACKEND_UNAVAILABLE" }
                if (!data.getBoolean("initialized")) {
                    baseline(context, status)
                    error("JAILBREAK_SELINUX_INITIALIZATION_PENDING")
                }
                record(context, checkNotNull(status.attemptId), "query", data.put("bootId", status.bootId)
                    .put("requested", target))
                data.getBoolean("effective")
            }
            JailbreakSelinuxHideState(true, target, effective)
        }.getOrElse { error ->
            Log.w("MapleSUSELinux", "Jailbreak status view query failed", error)
            record(context, checkNotNull(status.attemptId), "query", JSONObject()
                .put("bootId", status.bootId).put("requested", target)
                .put("error", error.message ?: error.javaClass.simpleName))
            JailbreakSelinuxHideState(true, target, effective = null, error = error.message ?: error.javaClass.simpleName)
        }
    }

    @Synchronized fun save(context: Context, enabled: Boolean): JailbreakSelinuxHideState {
        val status = checkNotNull(current(context)) { "JAILBREAK_SELINUX_SESSION_MISSING" }
        if (status.rootBackend == JailbreakRequest.BACKEND_KSU) {
            val repo = com.maplesu.core.data.repository.SettingsRepositoryImpl()
            val result = repo.setSelinuxHideEnabled(enabled)
            check(result == 0 || result == -android.system.OsConstants.EAGAIN) { "JAILBREAK_SELINUX_KSU:$result" }
            // This is a jailbreak-session override, never a persisted KSU feature default.
            check(preferences(context).edit().putString(NORMAL_BOOT, status.bootId)
                .putString(NORMAL_ATTEMPT, status.attemptId)
                .putBoolean(NORMAL_EFFECTIVE, enabled).putBoolean(NORMAL_APPLIED, result == 0).commit())
            record(context, checkNotNull(status.attemptId), "prepare", JSONObject()
                .put("bootId", status.bootId).put("backend", status.rootBackend)
                .put("requested", enabled).put("effective", if (result == 0) enabled else JSONObject.NULL)
                .put("result", result))
        }
        check(preferences(context).edit().putBoolean(ENABLED, enabled).commit()) { "JAILBREAK_SELINUX_SAVE_FAILED" }
        if (status.rootBackend == JailbreakRequest.BACKEND_HOOK) {
            runCatching { applyHook(context, status, enabled) }.onFailure { error ->
                return read(context).copy(error = error.message ?: error.javaClass.simpleName)
            }
        }
        return read(context)
    }

    /** Normal already owns policy backup/hiding; apply only in a proven jailbroken boot. */
    @Synchronized fun prepareNormal(context: Context) {
        val status = current(context) ?: return
        if (status.rootBackend != JailbreakRequest.BACKEND_KSU) return
        val prefs = preferences(context)
        val target = requested(context)
        if (prefs.getString(NORMAL_BOOT, null) == status.bootId &&
            prefs.getString(NORMAL_ATTEMPT, null) == status.attemptId && prefs.getBoolean(NORMAL_APPLIED, false) &&
            prefs.getBoolean(NORMAL_EFFECTIVE, false) == target &&
            com.maplesu.core.data.repository.SettingsRepositoryImpl().isSelinuxHideEnabled() == target) return
        save(context, target)
    }

    private fun record(context: Context, attempt: String, phase: String, data: JSONObject) {
        runCatching {
            val directory = File(context.filesDir, "jailbreak/attempts/$attempt").apply { mkdirs() }
            File(directory, "selinux-$phase.json").writeText(data.put("atMillis", System.currentTimeMillis()).toString(2))
        }.onFailure { Log.w("MapleSUSELinux", "SELinux receipt write failed", it) }
    }
}
