package dev.maplesu.manager.liteweb

/** The Ultra SDK grants package names globally, not individual Android users or KSU profiles. */
sealed interface LiteWebSuResult<out T> {
    data class Ok<T>(val value: T) : LiteWebSuResult<T>
    data class Failed(
        val code: String,
        val unavailable: Boolean = false,
        val rollback: String? = null,
    ) : LiteWebSuResult<Nothing>
}

data class LiteWebSuApplication(val packageName: String, val uid: Int) {
    val userId: Int get() = uid / 100_000
}

data class LiteWebSuCatalog(
    val apps: List<LiteWebSuApplication> = emptyList(),
    val available: Boolean = false,
    val complete: Boolean = false,
)

data class LiteWebSuSnapshot(
    val grants: Set<String>,
    val catalog: LiteWebSuCatalog,
    val protectedPackages: Set<String>,
    val loggingEnabled: Boolean?,
    val allowedUids: Set<Int>? = null,
) {
    fun entriesJson(): String {
        val installed = catalog.apps.sortedWith(compareBy({ it.packageName }, { it.uid }))
        val entries = installed.map { app -> entryJson(app.packageName, app.uid) }.toMutableList()
        (grants - installed.map { it.packageName }.toSet()).sorted().forEach { entries += entryJson(it, null) }
        return entries.joinToString(",", "[", "]")
    }

    private fun entryJson(packageName: String, uid: Int?): String =
        "{\"packageName\":${LiteWebJson.quote(packageName)},\"uid\":${uid ?: "null"}," +
            "\"userId\":${uid?.div(100_000) ?: "null"},\"installed\":${uid != null}," +
            "\"allowed\":${if (allowedUids != null && uid != null) uid in allowedUids else packageName in grants},\"protected\":${packageName in protectedPackages}}"

    fun json(): String = "{\"ok\":true,\"backend\":\"${if (allowedUids == null) "ultra-sdk" else "ksu"}\",\"scope\":\"${if (allowedUids == null) "package-global" else "uid"}\"," +
        "\"apps\":${entriesJson()},\"grants\":${grants.sorted().joinToString(",", "[", "]", transform = LiteWebJson::quote)}," +
        "\"capabilities\":{\"grant\":true,\"revoke\":true,\"uidPolicy\":${allowedUids != null}," +
        "\"userScopedPolicy\":${allowedUids != null},\"expiry\":false,\"profiles\":false,\"logging\":true}," +
        "\"loggingEnabled\":${loggingEnabled ?: "null"},\"catalogAvailable\":${catalog.available}," +
        "\"catalogComplete\":${catalog.complete}}"
}

data class LiteWebSuMutation(val packageName: String, val allowed: Boolean, val changed: Boolean)
data class LiteWebSuLog(val text: String, val truncated: Boolean = false, val source: String = "ultra-environment")

/** Recovery URLs contain the real HTTP token; do not return one embedded in environment logs. */
object LiteWebSuLogRedaction {
    private val token = Regex("(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")
    fun redact(text: String): String = text.replace(token, "<REDACTED-TOKEN>")
}

interface LiteWebSuperuserPort {
    val uidScoped: Boolean get() = false
    fun snapshot(): LiteWebSuResult<LiteWebSuSnapshot>
    fun setAllowed(packageName: String, allowed: Boolean): LiteWebSuResult<LiteWebSuMutation>
    fun setAllowed(packageName: String, allowed: Boolean, uid: Int?): LiteWebSuResult<LiteWebSuMutation> =
        setAllowed(packageName, allowed)
    fun log(): LiteWebSuResult<LiteWebSuLog>
    fun clearLog(): LiteWebSuResult<Unit>
    fun setLogging(enabled: Boolean): LiteWebSuResult<Boolean>
}

object UnavailableSuperuserPort : LiteWebSuperuserPort {
    private fun unavailable() = LiteWebSuResult.Failed("SU_AUTH_BACKEND_UNAVAILABLE", unavailable = true)
    override fun snapshot() = unavailable()
    override fun setAllowed(packageName: String, allowed: Boolean) = unavailable()
    override fun log() = unavailable()
    override fun clearLog() = unavailable()
    override fun setLogging(enabled: Boolean) = unavailable()
}

/** Narrow, injectable SDK operations. Reads must reject missing/malformed fields, not return defaults. */
interface LiteWebSuSdk {
    /** An authority-backed write keeps its decision and retries the mirror separately. */
    val retainsCommittedDecisions: Boolean get() = false
    fun packages(): LiteWebSuResult<Set<String>>
    fun setAllowed(packageName: String, allowed: Boolean): LiteWebSuResult<Unit>
    fun loggingEnabled(): LiteWebSuResult<Boolean>
    fun setLogging(enabled: Boolean): LiteWebSuResult<Unit>
    fun log(): LiteWebSuResult<String>
    fun clearLog(): LiteWebSuResult<Unit>
}

/** Serializes this WebUI's writes; compensates only the selected package, never replaces a list. */
class LiteWebSuperuserManager(
    private val sdk: LiteWebSuSdk,
    private val catalog: () -> LiteWebSuCatalog,
    private val protectedPackages: () -> Set<String>,
    private val mutationLock: Any = Any(),
) : LiteWebSuperuserPort {
    override fun snapshot(): LiteWebSuResult<LiteWebSuSnapshot> = synchronized(mutationLock) {
        val grants = sdk.packages()
        if (grants is LiteWebSuResult.Failed) return@synchronized grants
        val protected = protection() ?: return@synchronized protectionFailure()
        val logging = sdk.loggingEnabled()
        LiteWebSuResult.Ok(LiteWebSuSnapshot(
            (grants as LiteWebSuResult.Ok).value,
            runCatching(catalog).getOrDefault(LiteWebSuCatalog()),
            protected,
            (logging as? LiteWebSuResult.Ok)?.value,
        ))
    }

    override fun setAllowed(packageName: String, allowed: Boolean): LiteWebSuResult<LiteWebSuMutation> =
        synchronized(mutationLock) {
            if (!validPackage(packageName)) return@synchronized LiteWebSuResult.Failed("SU_AUTH_PACKAGE_INVALID")
            val protected = protection() ?: return@synchronized protectionFailure()
            if (!allowed && packageName in protected) {
                return@synchronized LiteWebSuResult.Failed("SU_AUTH_PROTECTED")
            }
            val before = sdk.packages()
            if (before is LiteWebSuResult.Failed) return@synchronized before
            val wasAllowed = packageName in (before as LiteWebSuResult.Ok).value
            if (wasAllowed == allowed) {
                return@synchronized LiteWebSuResult.Ok(LiteWebSuMutation(packageName, allowed, changed = false))
            }
            if (allowed) {
                val apps = runCatching(catalog).getOrDefault(LiteWebSuCatalog())
                if (!apps.available) return@synchronized LiteWebSuResult.Failed("SU_AUTH_CATALOG_UNAVAILABLE", unavailable = true)
                if (apps.apps.none { it.packageName == packageName }) {
                    return@synchronized LiteWebSuResult.Failed("SU_AUTH_PACKAGE_NOT_INSTALLED")
                }
            }
            val written = sdk.setAllowed(packageName, allowed)
            val after = sdk.packages()
            if (written is LiteWebSuResult.Ok && after is LiteWebSuResult.Ok &&
                (packageName in after.value) == allowed) {
                return@synchronized LiteWebSuResult.Ok(LiteWebSuMutation(packageName, allowed, changed = true))
            }
            val failure = (written as? LiteWebSuResult.Failed) ?: (after as? LiteWebSuResult.Failed)
                ?: LiteWebSuResult.Failed("SU_AUTH_READBACK_FAILED")
            if (sdk.retainsCommittedDecisions) {
                return@synchronized failure.copy(rollback = "pending-apply")
            }
            // Even an error receipt may have changed SDK state. Restore this package's old membership only.
            val rollback = if (after is LiteWebSuResult.Ok && (packageName in after.value) == wasAllowed) {
                "not-needed"
            } else {
                sdk.setAllowed(packageName, wasAllowed)
                when (val restored = sdk.packages()) {
                    is LiteWebSuResult.Ok -> if ((packageName in restored.value) == wasAllowed) "verified" else "failed"
                    is LiteWebSuResult.Failed -> "unverified"
                }
            }
            failure.copy(rollback = rollback)
        }

    override fun log(): LiteWebSuResult<LiteWebSuLog> = synchronized(mutationLock) {
        when (val result = sdk.log()) {
            is LiteWebSuResult.Failed -> result
            is LiteWebSuResult.Ok -> {
                val safe = LiteWebSuLogRedaction.redact(result.value)
                LiteWebSuResult.Ok(LiteWebSuLog(safe.takeLast(MAX_LOG_CHARS), safe.length > MAX_LOG_CHARS))
            }
        }
    }

    override fun clearLog(): LiteWebSuResult<Unit> = synchronized(mutationLock) {
        val result = sdk.clearLog()
        if (result is LiteWebSuResult.Failed) return@synchronized result
        when (val readback = sdk.log()) {
            is LiteWebSuResult.Failed -> LiteWebSuResult.Failed("SU_LOG_READBACK_FAILED")
            is LiteWebSuResult.Ok -> if (readback.value.isBlank()) LiteWebSuResult.Ok(Unit)
                else LiteWebSuResult.Failed("SU_LOG_READBACK_FAILED")
        }
    }

    override fun setLogging(enabled: Boolean): LiteWebSuResult<Boolean> = synchronized(mutationLock) {
        val before = sdk.loggingEnabled()
        if (before is LiteWebSuResult.Failed) return@synchronized before
        val old = (before as LiteWebSuResult.Ok).value
        if (old == enabled) return@synchronized LiteWebSuResult.Ok(enabled)
        val result = sdk.setLogging(enabled)
        val after = sdk.loggingEnabled()
        if (result is LiteWebSuResult.Ok && after is LiteWebSuResult.Ok && after.value == enabled) {
            return@synchronized LiteWebSuResult.Ok(enabled)
        }
        val rollback = if (after is LiteWebSuResult.Ok && after.value == old) "not-needed" else {
            sdk.setLogging(old)
            when (val restored = sdk.loggingEnabled()) {
                is LiteWebSuResult.Ok -> if (restored.value == old) "verified" else "failed"
                is LiteWebSuResult.Failed -> "unverified"
            }
        }
        LiteWebSuResult.Failed(if (result is LiteWebSuResult.Failed) result.code else "SU_LOGGING_READBACK_FAILED", rollback = rollback)
    }

    private fun protection(): Set<String>? = runCatching(protectedPackages).getOrNull()
    private fun protectionFailure() = LiteWebSuResult.Failed("SU_AUTH_PROTECTION_UNAVAILABLE", unavailable = true)

    companion object {
        const val MAX_LOG_CHARS = 128 * 1024
        fun validPackage(value: String): Boolean = value == "android" || (value.length <= 255 &&
            value.matches(Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")))
    }
}
