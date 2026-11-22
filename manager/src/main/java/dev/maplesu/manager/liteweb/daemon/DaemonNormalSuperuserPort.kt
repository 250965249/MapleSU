package dev.maplesu.manager.liteweb.daemon

import dev.maplesu.manager.liteweb.*
import dev.maplesu.manager.recovery.RecoveryPaths
import org.json.JSONObject

/** Fresh KSU helper per request; continues working from the independent recovery bundle. */
class DaemonNormalSuperuserPort(private val shell: DaemonShell) : LiteWebSuperuserPort {
    override val uidScoped = true
    private val protected = setOf("dev.maplesu.manager")

    @Synchronized
    override fun snapshot(): LiteWebSuResult<LiteWebSuSnapshot> {
        val native = call("snapshot") ?: return unavailable()
        val uids = native.optJSONArray("uids") ?: return unavailable()
        val allowed = (0 until uids.length()).map { index ->
            (uids.opt(index) as? Number)?.toInt()?.takeIf { it >= 0 } ?: return unavailable()
        }.toSet()
        val catalog = catalog()
        return LiteWebSuResult.Ok(LiteWebSuSnapshot(
            catalog.apps.filter { it.uid in allowed }.map { it.packageName }.toSet(), catalog, protected,
            native.opt("loggingEnabled") as? Boolean, allowed,
        ))
    }

    override fun setAllowed(packageName: String, allowed: Boolean) = setAllowed(packageName, allowed, null)

    @Synchronized
    override fun setAllowed(packageName: String, allowed: Boolean, uid: Int?): LiteWebSuResult<LiteWebSuMutation> {
        if (!LiteWebSuperuserManager.validPackage(packageName)) return LiteWebSuResult.Failed("SU_AUTH_PACKAGE_INVALID")
        if (!allowed && packageName in protected) return LiteWebSuResult.Failed("SU_AUTH_PROTECTED")
        val catalog = catalog()
        if (!catalog.available) return unavailable()
        val candidates = catalog.apps.filter { it.packageName == packageName && (uid == null || it.uid == uid) }
        val target = candidates.singleOrNull() ?: return LiteWebSuResult.Failed("SU_AUTH_UID_REQUIRED")
        val result = call("set '$packageName' ${target.uid} $allowed") ?: return unavailable()
        val actual = result.opt("allowed") as? Boolean
        val changed = result.opt("changed") as? Boolean
        return if (actual == allowed && changed != null) LiteWebSuResult.Ok(LiteWebSuMutation(packageName, allowed, changed))
            else LiteWebSuResult.Failed("SU_AUTH_READBACK_FAILED")
    }

    @Synchronized
    override fun log(): LiteWebSuResult<LiteWebSuLog> {
        val result = call("log") ?: return unavailable()
        val lines = result.optJSONArray("lines") ?: return unavailable()
        val text = (0 until lines.length()).joinToString("\n") { lines.getString(it) }
        val redacted = LiteWebSuLogRedaction.redact(text)
        return LiteWebSuResult.Ok(LiteWebSuLog(redacted.takeLast(LiteWebSuperuserManager.MAX_LOG_CHARS),
            redacted.length > LiteWebSuperuserManager.MAX_LOG_CHARS, source = "ksu"))
    }

    @Synchronized
    override fun clearLog(): LiteWebSuResult<Unit> =
        if (call("clear-log")?.optBoolean("cleared") == true) LiteWebSuResult.Ok(Unit) else unavailable()

    @Synchronized
    override fun setLogging(enabled: Boolean): LiteWebSuResult<Boolean> =
        if (call("set-logging $enabled")?.opt("enabled") == enabled) LiteWebSuResult.Ok(enabled) else unavailable()

    private fun catalog(): LiteWebSuCatalog {
        val all = shell.run("/system/bin/pm list packages -U --user all 2>/dev/null")
        val parsed = if (all.code == 0) DaemonSuPackageCatalog.parse(all.output) else null
        if (parsed != null) return LiteWebSuCatalog(parsed, true, true)
        val current = shell.run("/system/bin/pm list packages -U 2>/dev/null")
        val fallback = if (current.code == 0) DaemonSuPackageCatalog.parse(current.output) else null
        return if (fallback != null) LiteWebSuCatalog(fallback, true, false) else LiteWebSuCatalog()
    }

    private fun call(arguments: String): JSONObject? = runCatching {
        val result = shell.run("'${RecoveryPaths.LIB_DIR}/libksud_ksu.so' normal-superuser $arguments")
        if (result.code != 0) return null
        val line = result.output.lineSequence().singleOrNull { it.startsWith(MARKER) } ?: return null
        JSONObject(line.removePrefix(MARKER)).takeIf { it.opt("ok") == true }
    }.getOrNull()

    private fun unavailable() = LiteWebSuResult.Failed("SU_AUTH_KSU_UNAVAILABLE", unavailable = true)
    private companion object { const val MARKER = "MAPLESU_NORMAL_SU_V1 " }
}
