package dev.maplesu.manager.ultrakernel

/**
 * The kernel **series** of a `Linux version` release: its `major.minor` prefix.
 *
 * Product rule (2026-11-01, user's own words): 「6.6.89 匹配 6.6，只要是 6.6 前缀就可以修补刷写；
 * 失败再不刷就好了；不需要校验。」 A release string therefore matches a patch asset when the two
 * *series* are equal - `6.6.50-android15-…` and `6.6.89-android15-…` are both `6.6` - and never
 * because the full release happens to be byte-identical.
 *
 * Two things this deliberately is **not**:
 *
 *  - it is not a support level: [TIERS] lists the legacy catalogue's render tiers (the six
 *    covered by `UltraKernelCrossReleaseTest`). Target generation resolves its own semantics and
 *    does not consult this list. The list carries no "verified"/"experimental" meaning;
 *  - it is not a rewrite: every evidence field, receipt and plan keeps the **real** release
 *    (`6.6.50-android15-…`), because "matched by series" and "recorded as 6.6" are different facts.
 *
 * Parsing is fail-closed: [of] returns `null` for anything that does not start with
 * `digits.digits` (an unreadable banner, `AMBIGUOUS`, `%s`, `v6.6.1`), and every gate treats
 * `null` as a mismatch instead of guessing a series.
 */
internal object KernelSeries {

    /** Stable error for a series outside the legacy catalogue's tiers. */
    const val CODE_MISMATCH = "ULTRA_KERNEL_SERIES_MISMATCH"

    /** Placeholder used in a mismatch message when a side does not parse as a release. */
    const val NONE = "?"

    /** Placeholder used when a release string is empty (an unreadable kernel banner). */
    const val UNREADABLE = "unreadable"

    /**
     * Legacy catalogue render tiers.
     *
     * `UltraKernelCrossReleaseTest` covers these real boot sample series. The list is retained for
     * legacy catalogue selection, not target generation or verification levels. Shipped assets
     * are matched by [same] on their own release.
     */
    val TIERS: List<String> = listOf("5.10", "5.15", "6.1", "6.6", "6.12", "6.18")

    /** `^([0-9]+)\.([0-9]+)` - the series is a prefix parse, never a substring search. */
    private val PREFIX = Regex("^([0-9]+)\\.([0-9]+)")

    /**
     * `6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k` -> `6.6`;
     * `6.12.23-…` -> `6.12`; `""` / `AMBIGUOUS` / `v6.6.1` / `6` -> `null`.
     */
    fun of(release: String): String? {
        val match = PREFIX.find(release.trim()) ?: return null
        val major = match.groupValues[1].normalise()
        val minor = match.groupValues[2].normalise()
        return "$major.$minor"
    }

    /** True only when both sides parse **and** their series are equal. */
    fun same(left: String, right: String): Boolean {
        val series = of(left) ?: return false
        return series == of(right)
    }

    /** True when [release] belongs to a legacy catalogue tier. */
    fun supported(release: String): Boolean = of(release)?.let { it in TIERS } == true

    /**
     * Reports a legacy catalogue selection whose series has no tier.
     *
     * @throws IllegalStateException `ULTRA_KERNEL_SERIES_MISMATCH:<release>:known=[5.10,…]`.
     *         Target generation does not use this catalogue prerequisite.
     */
    fun requireSupported(release: String) {
        if (supported(release)) return
        throw IllegalStateException(tierFailure(release))
    }

    /** `ULTRA_KERNEL_SERIES_MISMATCH:<release>:known=[…]`. */
    fun tierFailure(release: String): String = "$CODE_MISMATCH:${tierDetail(release)}"

    /** `<release>:known=[…]` used by the legacy catalogue error. */
    fun tierDetail(release: String): String =
        "${label(release)}:known=[${TIERS.joinToString(",")}]"


    /**
     * Detail of a pairwise series mismatch: `<seriesLeft>:<seriesRight>:<releaseLeft>:<releaseRight>`.
     *
     * The series pair comes first because that is what every gate now compares; the real releases
     * follow so a log or receipt still names the two builds. Unparseable/empty sides keep their
     * [NONE]/[UNREADABLE] marker instead of being replaced by a plausible-looking series.
     */
    fun detail(left: String, right: String): String =
        "${of(left) ?: NONE}:${of(right) ?: NONE}:${label(left)}:${label(right)}"

    /** True when both sides parse as a release **and** are different releases of one series. */
    fun isCrossRelease(left: String, right: String): Boolean =
        left.trim() != right.trim() && same(left, right)

    /**
     * Ascending release order: numeric component by component (`6.6.9 < 6.6.89 < 6.6.100`), then
     * the raw string as a deterministic tie-break. Unparseable input sorts as `0.0…`.
     */
    fun compare(left: String, right: String): Int {
        val a = numbers(left)
        val b = numbers(right)
        for (index in 0 until maxOf(a.size, b.size)) {
            val first = a.getOrElse(index) { 0L }
            val second = b.getOrElse(index) { 0L }
            if (first != second) return if (first < second) -1 else 1
        }
        return left.compareTo(right)
    }

    /** Newest release of [releases], or `null` for an empty collection. */
    fun newest(releases: Collection<String>): String? =
        releases.maxWithOrNull { a, b -> compare(a, b) }

    /** `-android15…` / `_generic` and every further component are dropped before the numeric scan. */
    private fun numbers(release: String): List<Long> =
        release.trim().substringBefore('-').substringBefore('_').split('.')
            .map { it.toLongOrNull() ?: 0L }

    private fun String.normalise(): String = trimStart('0').ifEmpty { "0" }

    private fun label(release: String): String = release.trim().ifEmpty { UNREADABLE }
}

/**
 * Asset order inside one kernel series: the catalogue's recommended asset first, then the newest
 * release, then the id (so two assets of one release keep a stable order).
 *
 * This is the ordering the user asked for: 「若同一系列有多个资产，优选取 isDefault，其次取系列内
 * 最新」. It decides only *which* asset is attempted first; an asset that fails a byte gate is
 * reported, never silently replaced by one of another series.
 */
internal object UltraKernelAssetOrder : Comparator<UltraKernelPatchAsset> {
    override fun compare(left: UltraKernelPatchAsset, right: UltraKernelPatchAsset): Int {
        if (left.isDefault != right.isDefault) return if (left.isDefault) -1 else 1
        val byRelease = KernelSeries.compare(right.kernelRelease, left.kernelRelease)
        if (byRelease != 0) return byRelease
        return left.id.compareTo(right.id)
    }
}
