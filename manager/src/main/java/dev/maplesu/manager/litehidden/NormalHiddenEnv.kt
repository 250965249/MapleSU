package dev.maplesu.manager.litehidden

import android.content.Context
import dev.maplesu.manager.liteweb.RecoveryWebUiScripts
import dev.maplesu.manager.recovery.RecoveryBundle
import dev.maplesu.manager.recovery.RecoveryPaths
import dev.maplesu.manager.recovery.RecoveryPrepareResult
import dev.maplesu.manager.recovery.RecoverySource
import dev.maplesu.manager.runtime.RootExec
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import java.io.File

/** Normal has no parasite host; its recovery helper is preserved outside the removed APK. */
object NormalHiddenEnv {
    fun configuredUrl(): String? {
        val result = RouterRootRunner().run("cat '${RecoveryPaths.WEBUI_CONFIG}' 2>/dev/null")
        if (result.code != 0) return null
        val config = dev.maplesu.manager.liteweb.daemon.LiteWebDaemonConfig.parse(result.output) ?: return null
        return config.takeIf { it.workMode == "KSU" }?.let { ParasitePaths.webUiUrl(it.port, it.token) }
    }

    fun configuredPort(): Int? = RouterRootRunner()
        .run("sed -n 's/^webuiPort=//p;s/^port=//p' '${RecoveryPaths.WEBUI_CONFIG}' 2>/dev/null | head -1")
        .takeIf { it.code == 0 }?.output?.trim()?.toIntOrNull()
        ?.takeIf { dev.maplesu.manager.liteweb.LiteWebPortPolicy.validate(it) == null }

    fun create(context: Context): NormalHiddenController? = runCatching {
        val app = context.applicationContext
        val apk = app.applicationInfo.sourceDir ?: return null
        val helper = File(app.applicationInfo.nativeLibraryDir, "libksud_ksu.so")
        val version = app.packageManager.getPackageInfo(app.packageName, 0).longVersionCode
        val root = RouterRootRunner()
        val bundle = RecoveryBundle(RootRecoveryFs(root))
        val probe = HttpHiddenDaemonProbe()
        val client = HttpNormalHiddenClient()
        val sessionToken = NormalHiddenSessionToken(root)
        NormalHiddenController(
            prepareSession = { port ->
                if (ModeRuntime.active != WorkMode.KSU || !RootExec.capability().available || !helper.isFile) {
                    NormalHiddenResult(false, "NORMAL_RECOVERY_UNAVAILABLE")
                } else {
                    val guard = root.run(
                        "for D in '${ParasitePaths.HOST_BACKUP_ROOT}'/*; do [ -d \"\$D\" ] || continue; " +
                            "[ ! -e \"\$D/${ParasitePaths.MANIFEST_NAME}\" ] && [ ! -e \"\$D/${ParasitePaths.BACKUP_MARKER_NAME}\" ] || exit 1; done; echo NORMAL_NO_PARASITE_BACKUP",
                    )
                    if (guard.code != 0 || !guard.output.contains("NORMAL_NO_PARASITE_BACKUP")) {
                        return@NormalHiddenController NormalHiddenResult(false, "NORMAL_PARASITE_RESTORE_REQUIRED")
                    }
                    val old = root.run("cat '${RecoveryPaths.WEBUI_CONFIG}' 2>/dev/null").output
                    val existing = old.lineSequence().firstOrNull { it.startsWith("token=") }
                        ?.substringAfter('=')?.trim()?.takeIf { it.length >= 16 && it.all(Char::isLetterOrDigit) }
                    val token = sessionToken.resolve(existing)
                        ?: return@NormalHiddenController NormalHiddenResult(false, "NORMAL_SESSION_UNREADABLE")
                    // Stop before replacing the recovery APK/config so an older process never owns activation.
                    val stopped = root.run(ParasiteScripts.daemonStop())
                    if (stopped.code != 0 || !stopped.output.contains(ParasiteMarkers.STOPPED)) {
                        NormalHiddenResult(false, "NORMAL_DAEMON_STOP_FAILED")
                    } else {
                        val prepared = bundle.prepare(
                            app.packageName, version, apk,
                            extras = listOf(RecoverySource("NORMAL_RECOVERY_HELPER", helper.absolutePath, "lib/libksud_ksu.so", 0x1c0)),
                            webuiConfig = "webuiPort=$port\ntoken=$token\nworkMode=KSU\n".toByteArray(),
                        )
                        if (prepared !is RecoveryPrepareResult.Ok || !bundle.verify().ok) {
                            NormalHiddenResult(false, "NORMAL_RECOVERY_PREPARE_FAILED")
                        } else {
                            val boot = root.run(NormalRecoveryBoot.installScript())
                            if (boot.code != 0 || !boot.output.lineSequence().any { it.trim() == NormalRecoveryBoot.INSTALLED }) {
                                return@NormalHiddenController NormalHiddenResult(false, "NORMAL_BOOT_RECOVERY_UNVERIFIED")
                            }
                            val started = root.run(RecoveryWebUiScripts.resume() + "\n" + ParasiteScripts.daemonStart())
                            val supported = started.code == 0 && probe.ping(port, token) &&
                                HttpHiddenManagerRemoval().supported(port, token) && client.ready(port, token)
                            if (supported) NormalHiddenResult(true, recoveryUrl = ParasitePaths.webUiUrl(port, token))
                            else NormalHiddenResult(false, "NORMAL_INDEPENDENT_RECOVERY_UNVERIFIED")
                        }
                    }
                }
            },
            activateSession = { url ->
                if (ModeRuntime.active != WorkMode.KSU) NormalHiddenResult(false, "NORMAL_MODE_CHANGED")
                else client.activate(url)
            },
        )
    }.getOrNull()
}
