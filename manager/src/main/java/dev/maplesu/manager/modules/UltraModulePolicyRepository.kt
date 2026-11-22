package dev.maplesu.manager.modules

import android.content.Context
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.runtime.ultra.UltraSdkCredentials
import org.json.JSONObject

/** One snapshot per settings refresh; reads never initialize or change the backend. */
object UltraModulePolicyRepository {
    @Volatile private var cached: UltraModulePolicyState? = null
    fun peek(): UltraModulePolicyState = cached ?: UltraModulePolicyState()

    /** Explicit late-boot preparation, before any module policy transaction. */
    @Synchronized
    fun prepareHook(context: Context) {
        if (UltraEnvironmentProbe.usesUltraBackend(context)) return
        prepareHookState(context)
    }

    /** Explicit current-session preparation. It never replays module scripts or SDK boot work. */
    @Synchronized
    fun prepareSession(context: Context): UltraModulePolicyState =
        (if (UltraEnvironmentProbe.usesUltraBackend(context)) query(context, -1)
         else prepareHookState(context)).also { cached = it }

    private fun prepareHookState(context: Context): UltraModulePolicyState = try {
        val saved = runCatching { hook(context, "config") }.getOrNull()
        // A loader failure is retained for the UI. prepare-hook still performs
        // its confirmed ordinary-load fallback so module startup can continue.
        val loadError = if (saved?.optInt("requested") == 3)
            runCatching { HookPolicyBackend.ensure(context) }.exceptionOrNull() else null
        candidate(context, decode(hook(context, "prepare-hook"), UltraModulePolicyBackend.HOOK))
            .also { if (loadError != null) android.util.Log.w("MapleSUModulePolicy", "Temporary backend load failed", loadError) }
            .let { if (loadError == null) it else it.copy(hideFailed = true) }
    } catch (error: Exception) {
        if (Thread.currentThread().isInterrupted || error is kotlinx.coroutines.CancellationException) throw error
        // An existing current-boot gate may belong to the SDK or an older
        // standalone backend. Do not adopt it, replay module work or suppress
        // module startup merely because hot configuration is unavailable.
        val existing = runCatching { decode(hook(context, "config"), UltraModulePolicyBackend.HOOK) }.getOrNull()
        if (existing?.effective == null) throw error
        existing.copy(error = error.message ?: "MODULE_POLICY_HOOK_PREPARE_FAILED")
    }

    private fun hook(context: Context, arguments: String): JSONObject {
        val tool = ModuleToolDeployment.policySource(context).absolutePath.replace("'", "'\\''")
        val result = RootExecModuleScriptRunner.runHook(context, "'$tool' $arguments")
        check(result.isSuccess) { "MODULE_POLICY_HOOK:${result.code}:${result.err.take(256)}" }
        return JSONObject(result.out.trim())
    }

    @Synchronized
    fun read(context: Context): UltraModulePolicyState = query(context, -1).also { cached = it }

    @Synchronized
    fun save(context: Context, requested: Int, allowUnverified: Boolean = false): UltraModulePolicyState {
        require(requested in setOf(0, 1, 3))
        require(!allowUnverified || requested == 3)
        return query(context, if (allowUnverified) 7 else requested).also { cached = it }
    }

    private fun query(context: Context, requested: Int): UltraModulePolicyState {
        val sdk = UltraEnvironmentProbe.usesUltraBackend(context)
        val data = if (sdk) {
            val receipt = UltraSdkCredentials.client(context).modulePolicySettings(requested)
            check(receipt.succeeded) { receipt.reason ?: receipt.sdkError }
            requireNotNull(receipt.data) { "MODULE_POLICY_MISSING_DATA" }
        } else {
            if (requested in setOf(3, 7)) HookPolicyBackend.ensure(context)
            hook(context, if (requested == -1) "config" else "config-hook $requested")
        }
        val state = decode(data, if (sdk) UltraModulePolicyBackend.SDK else UltraModulePolicyBackend.HOOK)
        return if (sdk) state else candidate(context, state)
    }

    private fun candidate(context: Context, state: UltraModulePolicyState): UltraModulePolicyState =
        if (state.loaded && !state.hideFailed && state.capabilities and 2 == 0 && HookPolicyBackend.canAttempt(context))
            state.copy(canTryUnverified = true) else state

    private fun decode(data: JSONObject, backend: UltraModulePolicyBackend): UltraModulePolicyState {
        fun integer(name: String): Int {
            val value = data.opt(name) as? Number ?: error("MODULE_POLICY_INVALID_$name")
            check(value.toDouble() == value.toInt().toDouble()) { "MODULE_POLICY_INVALID_$name" }
            return value.toInt()
        }
        check(data.has("effective")) { "MODULE_POLICY_MISSING_EFFECTIVE" }
        fun optionalBoolean(name: String): Boolean = if (!data.has(name)) false else
            data.opt(name) as? Boolean ?: error("MODULE_POLICY_INVALID_$name")
        return UltraModulePolicyState.fromBackend(integer("requested"),
            if (data.isNull("effective")) null else integer("effective"), integer("capabilities"),
            optionalBoolean("unverifiedHide"), optionalBoolean("canTryUnverified"), optionalBoolean("hideFailed"), backend)
    }

    private const val WARNING_PREFS = "ultra_module_policy_notice"
    private const val SUPPRESSED = "suppressed_v1"
    fun warningSuppressed(context: Context): Boolean =
        context.getSharedPreferences(WARNING_PREFS, Context.MODE_PRIVATE).getBoolean(SUPPRESSED, false)

    /** Called only by the notice's affirmative button, never by its checkbox. */
    fun suppressWarning(context: Context) {
        check(context.getSharedPreferences(WARNING_PREFS, Context.MODE_PRIVATE).edit()
            .putBoolean(SUPPRESSED, true).commit()) { "MODULE_POLICY_NOTICE_SAVE_FAILED" }
    }
}
