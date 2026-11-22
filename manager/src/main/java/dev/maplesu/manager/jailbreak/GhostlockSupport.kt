package dev.maplesu.manager.jailbreak

import android.content.Context
import java.io.IOException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

/**
 * The Ghostlock support list, exactly as published by the GhostLock-App project
 * (`docs/kernel_profiles/SUPPORTED_DEVICES_ZH.md`).
 *
 * [isSupported] answers one question and only one: does this device's complete
 * `uname -r` string appear in that table? The comparison is exact string
 * equality against the packaged list. There is deliberately no prefix, suffix,
 * KMI-family, case-insensitive or "close enough" matching: the upstream
 * document is a per-build allowlist, and a build that is one `g`-hash away is a
 * different kernel with different offsets.
 *
 * Fail-closed is a property of the type, not of the caller. An absent asset, an
 * unparseable one, one whose provenance header is missing, one whose declared
 * counts disagree with its rows, and an empty table all produce an instance for
 * which every release reads [Support.UNSUPPORTED]. There is no "unknown" state
 * a caller could mistake for permission.
 *
 * The list is a *capability* statement about upstream Ghostlock only. It never
 * claims this APK can root the device: `JailbreakAdmission` still decides
 * whether an attempt may start, and the provider still fails with its own code.
 */
class GhostlockSupport private constructor(
    private val devices: Map<String, Device>,
    private val listProblem: Problem?,
    val provenance: Provenance?,
    private val rows: Int = devices.size,
) {
    /** One row of the upstream table. [note] is upstream's own annotation, or empty. */
    data class Device(val unameRelease: String, val device: String, val note: String)

    /** Where the packaged table came from. A list without this is not usable. */
    data class Provenance(
        val sourceUrl: String,
        val fetchedAt: String,
        val sourceSha256: String,
        val commit: String,
    )

    /** Why a list could not be used. Each names a condition that was observed. */
    data class Problem(val reason: Reason, val detail: String)

    sealed interface Support {
        /** The complete release string is a row of the packaged upstream table. */
        data object SUPPORTED : Support

        /** Not usable. [detail] is diagnostics, never user-facing text. */
        data class UNSUPPORTED(val reason: Reason, val detail: String = "") : Support
    }

    enum class Reason {
        /** A well-formed list, and this release is simply not in it. */
        NOT_IN_SUPPORTED_LIST,

        /** The measured release is empty; there is nothing to match. */
        KERNEL_RELEASE_EMPTY,

        /** No packaged list at all (asset absent or unreadable). */
        LIST_MISSING,

        /** The packaged list exists but cannot be trusted (malformed/edited). */
        LIST_UNPARSEABLE,
    }

    /** Numeric rows in the packaged table (upstream lists one release twice). */
    val rowCount: Int get() = rows

    /** Distinct releases the table can match. */
    val releaseCount: Int get() = devices.size

    /** False when the packaged list is unusable; every verdict is then UNSUPPORTED. */
    val isUsable: Boolean get() = listProblem == null

    /**
     * The one decision this type exists for.
     *
     * Exact match only: [unameRelease] is looked up verbatim, so a different
     * `g`-hash, a trailing suffix, a differing case or a prefix all miss.
     */
    fun isSupported(unameRelease: String): Support {
        listProblem?.let { return Support.UNSUPPORTED(it.reason, it.detail) }
        if (unameRelease.isEmpty()) return Support.UNSUPPORTED(Reason.KERNEL_RELEASE_EMPTY)
        devices[unameRelease] ?: return Support.UNSUPPORTED(
            Reason.NOT_IN_SUPPORTED_LIST, unameRelease)
        return Support.SUPPORTED
    }

    /** The matching row, for display. Null when the release is not listed. */
    fun device(unameRelease: String): Device? = devices[unameRelease]

    companion object {
        /** Packaged asset path, relative to `assets/`. */
        const val ASSET = "ghostlock/supported-devices.json"

        private val json = Json { isLenient = false }

        /** The header digest is required to be a real sha256, not a placeholder. */
        private val DIGEST = Regex("^[0-9a-f]{64}$")

        /** Fail-closed instance for a build or a call that has no usable list. */
        @JvmStatic
        fun unavailable(reason: Reason, detail: String = ""): GhostlockSupport =
            GhostlockSupport(emptyMap(), Problem(reason, detail), null)

        /** Read the packaged table. Never throws: an unreadable asset is LIST_MISSING. */
        @JvmStatic
        fun from(context: Context): GhostlockSupport = try {
            val text = context.assets.open(ASSET).use { it.readBytes().toString(Charsets.UTF_8) }
            fromJson(text)
        } catch (error: IOException) {
            unavailable(Reason.LIST_MISSING, error.message ?: error.javaClass.simpleName)
        } catch (error: SecurityException) {
            unavailable(Reason.LIST_MISSING, error.message ?: error.javaClass.simpleName)
        } catch (error: RuntimeException) {
            // An AssetManager that fails in an unexpected way is still "no list".
            unavailable(Reason.LIST_MISSING, error.message ?: error.javaClass.simpleName)
        }

        /**
         * Pure parser, so the host tests can assert the packaged bytes without an
         * Android Context. A malformed table is a fail-closed instance, never an
         * exception and never a partial list.
         */
        @JvmStatic
        fun fromJson(text: String): GhostlockSupport = try {
            parse(text)
        } catch (error: Exception) {
            unavailable(Reason.LIST_UNPARSEABLE, error.message ?: error.javaClass.simpleName)
        }

        private fun parse(text: String): GhostlockSupport {
            val root = json.parseToJsonElement(text).jsonObject
            /*
             * Provenance is part of the contract: an asset whose header does not
             * name the document and the digest it was generated from cannot be
             * distinguished from a hand-edited allowlist, so it is not used.
             */
            val sourceUrl = root.string("sourceUrl") ?: throw IOException("provenance-missing:sourceUrl")
            val sourceSha256 = root.string("sourceSha256")
                ?: throw IOException("provenance-missing:sourceSha256")
            if (!DIGEST.matches(sourceSha256)) throw IOException("provenance-invalid:sourceSha256")
            val fetchedAt = root.string("fetchedAt") ?: ""
            val commit = root.string("sourceCommit") ?: ""
            val array = root["devices"]?.let { runCatching { it.jsonArray }.getOrNull() }
                ?: throw IOException("devices-missing")

            val parsed = LinkedHashMap<String, Device>()
            var rows = 0
            for (element in array) {
                val entry = element.jsonObject
                val release = entry.string("unameRelease")
                    ?: throw IOException("release-missing:$rows")
                if (release.isBlank()) throw IOException("release-empty:$rows")
                // A release is one `uname -r` token. Whitespace means the generator
                // or an editor produced something that can never match a device.
                if (release.any { it.isWhitespace() }) throw IOException("release-whitespace:$rows")
                val device = entry.string("device") ?: ""
                val note = entry.string("note") ?: ""
                rows++
                parsed.putIfAbsent(release, Device(release, device, note))
            }
            if (parsed.isEmpty()) throw IOException("devices-empty")

            /*
             * The header counts are an integrity check over the body: a truncated
             * or hand-trimmed asset would otherwise silently disable devices that
             * upstream does support.
             */
            root.int("entryCount")?.let {
                if (it != rows) throw IOException("entry-count-mismatch:$it!=$rows")
            }
            root.int("uniqueReleaseCount")?.let {
                if (it != parsed.size) throw IOException("unique-count-mismatch:$it!=${parsed.size}")
            }
            return GhostlockSupport(parsed, null,
                Provenance(sourceUrl, fetchedAt, sourceSha256, commit), rows)
        }

        private fun JsonObject.string(key: String): String? =
            (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

        private fun JsonObject.int(key: String): Int? =
            (this[key] as? JsonPrimitive)?.takeIf { !it.isString }?.intOrNull
    }
}
