package dev.maplesu.ghostlock.extract

import com.ghostlock.app.data.HoconSupport
import com.ghostlock.app.data.NativeProfileDocument
import com.ghostlock.app.data.ValueMap
import com.ghostlock.app.data.asValueMap
import com.ghostlock.app.data.profile.CpuPairView
import com.ghostlock.app.data.profile.ProfileMerger
import com.ghostlock.app.data.profile.ProfileResolver
import com.ghostlock.app.data.route.RouteKind
import com.ghostlock.app.data.valueMapOf

/**
 * Result of handing a generated/imported HOCON document through the exact
 * pipeline the app uses before an attempt: parse -> merge -> fail-closed
 * validation -> typed wire v2.
 */
class ProfileValidation(
    /** Invalid field paths, exactly as `ProfileResolver.validateMerged` reports them. */
    val invalidFields: List<String>,
    /** The typed wire document, present only when validation passed. */
    val wire: ByteArray?,
) {
    val complete: Boolean get() = invalidFields.isEmpty() && wire != null
}

/** Encodes and validates one profile document for a release. */
fun interface ProfileValidator {
    fun validate(document: String, release: String): ProfileValidation
}

/**
 * Default validator, independent of Android: it is the vendored upstream
 * recipe `GhostlockProfileCodec` uses (parse -> merge with the execution
 * defaults -> `ProfileResolver.validateMerged` -> `NativeProfileDocument`).
 *
 * Callers on the device pass the packaged execution tuning and route presets so
 * the validation matches the executor's conversion byte for byte; the defaults
 * here (empty tuning, no presets) still validate every *required* geometry
 * field because those never come from the tuning documents.
 */
class HoconProfileValidator(
    private val tuningExecution: ValueMap? = valueMapOf(),
    private val routePresets: Map<String, ValueMap> = emptyMap(),
) : ProfileValidator {
    private val routes = RouteKind.entries.map { it.token }

    override fun validate(document: String, release: String): ProfileValidation {
        val parsed = try {
            HoconSupport.parseValue(document).asValueMap()
                ?: return ProfileValidation(listOf("<document>"), null)
        } catch (error: RuntimeException) {
            return ProfileValidation(listOf("<document>"), null)
        }
        val declared = parsed["release"] as? String
        if (declared != release) return ProfileValidation(listOf("release"), null)
        val route = routeOf(parsed)
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
            return ProfileValidation(listOf("<merge>"), null)
        }
        val errors = ProfileResolver.validateMerged(merged, route, fallback)
        if (errors.isNotEmpty()) {
            return ProfileValidation(errors.map { it.fieldPath }.distinct(), null)
        }
        val wire = try {
            NativeProfileDocument.from(release, route, fallback) { path ->
                ProfileResolver.nativeValue(merged, route, fallback, path)
            }.toBinary()
        } catch (error: RuntimeException) {
            return ProfileValidation(listOf("<serialize>"), null)
        }
        return ProfileValidation(emptyList(), wire)
    }

    /** The active route is the single route block the document actually carries. */
    fun routeOf(profile: Map<*, *>): String? = when (val route = profile["route"]) {
        is String -> route.takeIf { it.isNotEmpty() && it != "null" && it in routes }
        is Map<*, *> -> route.keys.filterIsInstance<String>().firstOrNull { it in routes }
        else -> null
    }

    fun fallbackOf(profile: Map<*, *>): String? {
        val to = ((profile["fallback"] as? Map<*, *>)?.get("to") as? String)
            ?.takeIf { it.isNotEmpty() && it != "null" }
        if (to != null) return to
        return (profile["fallback_to"] as? String)?.takeIf { it.isNotEmpty() && it != "null" }
    }
}
