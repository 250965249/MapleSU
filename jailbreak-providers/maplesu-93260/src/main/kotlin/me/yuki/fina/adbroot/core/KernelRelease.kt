package me.yuki.fina.adbroot.core

/**
 * One running kernel release (`uname -r`), parsed without assuming a vendor.
 *
 * The 98260 source binds part of its kernel work to link-time addresses, so the
 * exact release string is the identity that decides which packaged profile may
 * run. This type only *describes* the string: it never decides that a release is
 * supported, never relaxes a match and never invents a missing part.
 *
 * Accepted inputs are the raw `uname -r` value, a `/proc/version` line
 * (`Linux version 6.12.58-... (builder@host) ...`) or a bare version string.
 * Observed formats include:
 * ```
 * 6.12.58-android16-6-gdd6fd5c98918-abogki543627742-4k
 * 6.12.69-android16-6-g242e1a07f878-ab15865446-4k
 * 6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k
 * 5.10.209-android13-8-g1234567890ab-ab1234567-4k
 * 4.19.157-perf
 * ```
 *
 * The parsed `raw` is always the release token itself (not the whole
 * `/proc/version` line), so it can be compared with `uname -r` byte-for-byte.
 */
data class KernelRelease(
    /** The release token, exactly as the kernel reported it. */
    val raw: String,
    /** `major.minor` or `major.minor.patch` when it parsed, otherwise null. */
    val version: String?,
    val major: Int?,
    val minor: Int?,
    val patch: Int?,
    /** Platform release from `androidNN` (for example 16), when the build carries it. */
    val androidRelease: Int?,
    /** The KMI generation segment that follows `androidNN` (for example 6), when present. */
    val generation: Int?,
    /** Upstream commit id without the leading `g`, when the build carries one. */
    val gitHash: String?,
    /** Build id token (`abogki543627742`, `ab15865446`), when present. */
    val buildId: String?,
    /** Numeric part of an `abogkiNNNN` vendor build id. */
    val vendorBuildId: Long?,
    /** Page size suffix (`4k`, `16k`, `64k`), when present. */
    val pageSize: String?,
    /** Every `-` separated segment after the version, in order. */
    val segments: List<String>,
) {
    val valid: Boolean get() = version != null

    /** Kernel branch identity (`6.12.58`), or null when the version did not parse. */
    val family: String? get() = version

    /**
     * KMI name in the usual `androidNN-M.m` form. Prefers the build's own
     * `androidNN` tag; without one, a standard GKI mapping is used. A kernel
     * that matches no known KMI stays null instead of being guessed.
     */
    val kmi: String? = when {
        major == null || minor == null -> null
        androidRelease != null -> "android$androidRelease-$major.$minor"
        else -> GKI_ANDROID[major to minor]?.let { "android$it-$major.$minor" }
    }

    /** True when this release is an exact build (has a commit or a build id). */
    val pinned: Boolean get() = gitHash != null || buildId != null

    /**
     * Stable short form for logs and notes: the release itself when it parsed,
     * otherwise a quoted form that makes the failure obvious.
     */
    override fun toString(): String = if (valid) raw else "unparsed(${raw.take(64)})"

    companion object {
        /** Standard GKI kernel branch to platform release mapping. */
        private val GKI_ANDROID: Map<Pair<Int, Int>, Int> = mapOf(
            (5 to 4) to 11,
            (5 to 10) to 12,
            (5 to 15) to 13,
            (6 to 1) to 14,
            (6 to 6) to 15,
            (6 to 12) to 16,
            (6 to 18) to 17,
        )

        private val BANNER = Regex("""Linux version\s+(\S+)""")
        private val VERSION = Regex("""^(\d+)\.(\d+)(?:\.(\d+))?(.*)$""")
        private val ANDROID = Regex("""^android(\d+)$""")
        private val GIT = Regex("""^g([0-9a-f]{7,40})$""")
        private val VENDOR_BUILD = Regex("""^ab([a-z]+)(\d+)$""")
        private val AOSP_BUILD = Regex("""^ab(\d+)$""")
        private val PAGE = Regex("""^(\d+)k$""")

        /** A release that could not be read at all; never matches a profile. */
        val UNKNOWN = KernelRelease("", null, null, null, null, null, null,
            null, null, null, null, emptyList())

        fun parse(value: String?): KernelRelease {
            val text = value?.trim().orEmpty()
            if (text.isEmpty()) return UNKNOWN
            val token = (BANNER.find(text)?.groupValues?.get(1)
                ?: text.split(Regex("""\s+""")).firstOrNull().orEmpty()).trim()
            if (token.isEmpty()) return UNKNOWN
            val match = VERSION.matchEntire(token)
                ?: return UNKNOWN.copy(raw = token)
            val major = match.groupValues[1].toIntOrNull()
            val minor = match.groupValues[2].toIntOrNull()
            val patch = match.groupValues[3].toIntOrNull()
            val tail = match.groupValues[4]
            val segments = tail.split('-').filter { it.isNotEmpty() }
            var androidRelease: Int? = null
            var generation: Int? = null
            var gitHash: String? = null
            var buildId: String? = null
            var vendorBuildId: Long? = null
            var pageSize: String? = null
            for ((index, segment) in segments.withIndex()) {
                ANDROID.matchEntire(segment)?.let {
                    androidRelease = it.groupValues[1].toIntOrNull()
                    return@let
                }
                // The generation number only counts directly after `androidNN`.
                if (index > 0 && segments[index - 1].matches(ANDROID) &&
                    segment.isNotEmpty() && segment.all { it.isDigit() }) {
                    generation = segment.toIntOrNull()
                    continue
                }
                GIT.matchEntire(segment)?.let {
                    gitHash = it.groupValues[1]
                    return@let
                }
                VENDOR_BUILD.matchEntire(segment)?.let {
                    buildId = segment
                    vendorBuildId = it.groupValues[2].toLongOrNull()
                    return@let
                }
                AOSP_BUILD.matchEntire(segment)?.let {
                    buildId = segment
                    return@let
                }
                PAGE.matchEntire(segment)?.let {
                    pageSize = segment
                }
            }
            val version = when {
                major == null || minor == null -> null
                patch != null -> "$major.$minor.$patch"
                else -> "$major.$minor"
            }
            return KernelRelease(
                raw = token,
                version = version,
                major = major,
                minor = minor,
                patch = patch,
                androidRelease = androidRelease,
                generation = generation,
                gitHash = gitHash,
                buildId = buildId,
                vendorBuildId = vendorBuildId,
                pageSize = pageSize,
                segments = segments,
            )
        }
    }
}
