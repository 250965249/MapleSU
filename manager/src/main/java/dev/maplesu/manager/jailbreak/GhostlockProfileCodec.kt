package dev.maplesu.manager.jailbreak

import com.ghostlock.app.data.HoconSupport
import com.ghostlock.app.data.asValueMap
import com.ghostlock.app.data.NativeProfileDocument
import com.ghostlock.app.data.ValueMap
import com.ghostlock.app.data.profile.CpuPairView
import com.ghostlock.app.data.profile.ProfileMerger
import com.ghostlock.app.data.profile.ProfileResolver
import com.ghostlock.app.data.route.RouteKind
import java.io.IOException

/**
 * Turns one pinned Ghostlock HOCON profile into the typed wire v2 document the
 * native decoder accepts.
 *
 * S02 (review 2026-10-26): the product used to hand the *text* of the resolved
 * profile straight to `GhostlockWire`, which rejects anything without the
 * `0x0d000721` header - so even a matching target failed before the provider
 * started. The conversion is not invented here: it is the upstream recipe
 * (`ProfileExporter`): parse -> merge with defaults -> validate -> project the
 * typed document. The vendored upstream sources are byte-for-byte copies
 * (`jailbreak-providers/ghostlock/profile-core/vendored.json`).
 *
 * Pure JVM: no Android, no I/O - host tests exercise the same code the device
 * runs.
 */
object GhostlockProfileCodec {
    /** Route tokens the resolver understands, in the order the exporter uses. */
    private val ROUTES = RouteKind.entries.map { it.token }

    /**
     * @param resolvedHocon profile text with every `include` already expanded
     * @param release the exact `uname -r` this profile was selected for
     */
    @JvmOverloads
    fun toWire(
        resolvedHocon: String,
        release: String,
        /*
         * The upstream exporter always merges the packaged execution tuning and the
         * per-route presets into the profile. Leaving them null made every native
         * tuning value zero, so the attack loops never ran (G-1 in the static parity
         * report). Callers pass the packaged documents; host tests may omit them.
         */
        tuningExecution: ValueMap? = null,
        routePresets: Map<String, ValueMap> = emptyMap(),
    ): ByteArray {
        if (resolvedHocon.isBlank()) throw IOException("GHOSTLOCK_PROFILE_EMPTY")
        val parsed = try {
            HoconSupport.parseValue(resolvedHocon).asValueMap()
                ?: throw IOException("GHOSTLOCK_PROFILE_NOT_AN_OBJECT")
        } catch (error: IOException) {
            throw error
        } catch (error: RuntimeException) {
            throw IOException("GHOSTLOCK_PROFILE_PARSE_FAILED: " + (error.message ?: error.javaClass.simpleName), error)
        }
        val declared = parsed["release"] as? String ?: ""
        if (declared != release) throw IOException("GHOSTLOCK_PROFILE_RELEASE_MISMATCH_TEXT:" + declared)
        val route = routeNameOf(parsed)
        val fallback = fallbackOf(parsed)
        val merged = try {
            ProfileMerger.resolveMerged(
                deviceRelease = release,
                builtin = parsed,
                imported = null,
                overrides = null,
                tuningExecution = tuningExecution,
                pair = CpuPairView(0, 1),
                routePresets = routePresets,
            )
        } catch (error: RuntimeException) {
            throw IOException("GHOSTLOCK_PROFILE_MERGE_FAILED", error)
        }
        val errors = ProfileResolver.validateMerged(merged, route, fallback)
        if (errors.isNotEmpty()) {
            throw IOException("GHOSTLOCK_PROFILE_INVALID:" + errors.first().fieldPath +
                ":" + errors.first().message)
        }
        return try {
            NativeProfileDocument.from(release, route, fallback) { path ->
                ProfileResolver.nativeValue(merged, route, fallback, path)
            }.toBinary()
        } catch (error: RuntimeException) {
            throw IOException("GHOSTLOCK_PROFILE_SERIALIZE_FAILED", error)
        }
    }

    /** The active route is the single route block the document actually carries. */
    fun routeNameOf(profile: Map<*, *>): String? = when (val route = profile["route"]) {
        is String -> route.takeIf { it.isNotEmpty() && it != "null" && it in ROUTES }
        is Map<*, *> -> route.keys.filterIsInstance<String>().firstOrNull { it in ROUTES }
        else -> null
    }

    fun fallbackOf(profile: Map<*, *>): String? {
        val to = ((profile["fallback"] as? Map<*, *>)?.get("to") as? String)
            ?.takeIf { it.isNotEmpty() && it != "null" }
        if (to != null) return to
        return (profile["fallback_to"] as? String)?.takeIf { it.isNotEmpty() && it != "null" }
    }

    /** Convenience for the profile resolver: wire bytes for a resolved document. */
    @JvmOverloads
    fun toWire(
        profile: GhostlockProfiles.Profile,
        release: String,
        tuningExecution: ValueMap? = null,
        routePresets: Map<String, ValueMap> = emptyMap(),
    ): ByteArray = toWire(String(profile.document(), Charsets.UTF_8), release,
        tuningExecution, routePresets)
}
