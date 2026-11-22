package dev.maplesu.manager.ultrakernel

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull

/**
 * Release-indexed kernel patch asset: `assets/ultra-kernels/releases/<release>/meta.json` plus the
 * spec file it pins.
 *
 * The catalogue is the runtime answer to "this boot says `6.6.89-…`; which patch set may I apply
 * and what exactly must come out?". A release directory is the unit of review: the spec digest,
 * record count, kernel release, expected kernel digest, expected image size and (optional) base
 * kernel/stock-image digests are all pinned inside it.
 *
 * A **series** without any directory is still refused with
 * `ULTRA_KERNEL_RELEASE_UNSUPPORTED:<release>:known=[…]` (the on-device generator may then render a
 * plan instead - see `UltraKernelSpecGenerator`), and a series that *is* shipped is matched by
 * `major.minor` only: `6.6.50` is answered by the `6.6.89` directory, newest release first, with
 * every byte-level gate still deciding whether the records fit that kernel.

 *
 * Two meta shapes are accepted:
 *
 *  1. multi-asset (used by 6.6.89, which must keep the k22/k21 delivery fallback):
 *     `{"kernelRelease": "...", "source": "...", "verification": "...", "assets": [ … ]}`
 *  2. single-asset (the minimal form described by the release-catalogue contract):
 *     the same fields as one `assets[]` entry, directly at the top level; the spec defaults to
 *     `<release>.spec`.
 *
 * The spec format is the vendor `offset|original|replacement` grammar (see [UltraKernelSpec]) and
 * only that grammar is accepted in this round. `KernelSymbolOffset.json`/`.ir.spec` artefacts are
 * analysis inputs, not delivery specs: IR specs describe the module-loading patch set, while a
 * delivery asset must reproduce the pinned Ultra kernel byte-for-byte. New releases therefore ship
 * a flat spec generated from the analysis chain (see the design doc); `specFormat` exists so that
 * a future format can be rejected explicitly instead of being half-understood.
 */
internal data class UltraKernelReleaseAsset(
    override val id: String,
    override val label: String,
    override val summary: String,
    override val specAsset: String,
    override val specSha256: String,
    override val patches: Int,
    override val kernelRelease: String,
    override val baseKernelSha256: String,
    override val expectedKernelSha256: String,
    override val knownBaseImageSha256: String,
    override val knownBaseImageBootSha256: String,
    override val imageSizeBytes: Long,
    override val ramdiskSize: Long,
    override val source: String,
    override val verification: String,
    val default: Boolean = false,
    override val debugOnly: Boolean = false,
    override val debugReason: String = "",
    override val status: String = "ready",
) : UltraKernelPatchAsset {
    override val ready: Boolean get() = status == "ready"
    override val isDefault: Boolean get() = default
}

internal class UltraKernelReleaseCatalog private constructor(
    private val byRelease: Map<String, List<UltraKernelReleaseAsset>>,
    /** Directories that exist but were refused; the release name maps to the stable reason. */
    val rejected: Map<String, String>,
) {
    /**
     * Assets of [release]'s kernel **series**, default first then newest; empty when the series has
     * no directory at all.
     *
     * Series - not release - is the key, exactly as the user asked: `6.6.50-android15-…` is answered
     * by whatever this build ships for `6.6` (today `6.6.89`). Whether the records then fit the
     * kernel is the builder's byte gate, not a version comparison; a failure is reported, never
     * papered over by silently trying another series.
     */
    fun assetsFor(release: String): List<UltraKernelReleaseAsset> {
        val series = KernelSeries.of(release) ?: return emptyList()
        val matching = byRelease.values.flatten()
            .filter { KernelSeries.of(it.kernelRelease) == series }
        return if (matching.isEmpty()) emptyList() else matching.sortedWith(UltraKernelAssetOrder)
    }

    fun rejection(release: String): String? = rejected[release]

    /** Every release this catalogue can answer for, sorted; used by the unsupported error. */
    fun knownReleases(): List<String> = (byRelease.keys + rejected.keys).sorted()

    /** Assets of the same series as [release], so `id` keeps its meaning across patch levels. */
    fun asset(release: String, id: String?): UltraKernelReleaseAsset? {
        val assets = assetsFor(release)
        return if (id == null) assets.firstOrNull() else assets.firstOrNull { it.id == id }
    }


    companion object {
        const val ROOT = "ultra-kernels/releases"
        const val META = "meta.json"
        private const val SCHEMA = 1
        private const val MAX_RELEASES = 64
        private const val MAX_ASSETS_PER_RELEASE = 4
        internal const val MAX_META_BYTES = 64L * 1024
        internal const val SPEC_FORMAT_OFFSET = "offset"

        private val RELEASE = Regex("[A-Za-z0-9][A-Za-z0-9._+-]{0,159}")
        private val ID = Regex("[a-z0-9]{2,16}")
        private val SPEC_FILE = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,95}\\.spec")
        private val SHA256 = Regex("[0-9a-f]{64}")

        /**
         * Parses every directory under `releases`. A malformed directory is not silently dropped: it
         * is recorded in [rejected] so an install attempt for that release fails with the reason
         * instead of pretending the release is unsupported (or, worse, falling back to an older
         * asset).
         */
        fun load(source: UltraKernelAssetSource): UltraKernelReleaseCatalog {
            val names = try {
                source.list(ROOT)
            } catch (error: Exception) {
                emptyList()
            }
            val byRelease = LinkedHashMap<String, List<UltraKernelReleaseAsset>>()
            val rejected = LinkedHashMap<String, String>()
            var counted = 0
            for (name in names.sorted()) {
                // `releases/` may also contain notes/licenses; only directories are releases.
                val directory = try {
                    source.list("$ROOT/$name").isNotEmpty()
                } catch (error: Exception) {
                    false
                }
                if (!directory) continue
                if (!RELEASE.matches(name)) {
                    rejected[name] = "ULTRA_KERNEL_RELEASE_DIR_INVALID"
                    continue
                }
                counted++
                check(counted <= MAX_RELEASES) { "ULTRA_KERNEL_RELEASE_CATALOG_TOO_MANY" }
                try {
                    val bytes = try {
                        source.read("$ROOT/$name/$META")
                    } catch (error: java.io.FileNotFoundException) {
                        throw IllegalStateException("ULTRA_KERNEL_RELEASE_META_MISSING")
                    }
                    check(bytes.size.toLong() <= MAX_META_BYTES) { "ULTRA_KERNEL_RELEASE_META_TOO_LARGE" }
                    val assets = parseMeta(name, bytes)
                    check(!byRelease.containsKey(name)) { "ULTRA_KERNEL_RELEASE_DUPLICATE:$name" }
                    byRelease[name] = assets
                } catch (error: Exception) {
                    rejected[name] = error.message ?: error.javaClass.simpleName
                }
            }
            return UltraKernelReleaseCatalog(byRelease, rejected)
        }

        /** Convenience for the app; host tests use an in-memory/filesystem source instead. */
        fun load(context: android.content.Context): UltraKernelReleaseCatalog =
            load(UltraKernelContextAssets(context))

        private fun parseMeta(directory: String, bytes: ByteArray): List<UltraKernelReleaseAsset> {
            val root = try {
                Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)) as JsonObject
            } catch (error: Exception) {
                throw IllegalStateException("ULTRA_KERNEL_RELEASE_META_INVALID:$directory")
            }
            check(root.int("schema") == SCHEMA) { "ULTRA_KERNEL_RELEASE_META_SCHEMA:$directory" }
            val release = root.requiredString("kernelRelease", "ULTRA_KERNEL_RELEASE_META_RELEASE")
            check(RELEASE.matches(release) && release == directory) {
                "ULTRA_KERNEL_RELEASE_META_MISMATCH:$directory:$release"
            }
            val defaultSource = root.optString("source") ?: UltraKernelPatchAsset.SOURCE_SAMPLE
            val defaultVerification =
                root.optString("verification") ?: UltraKernelPatchAsset.VERIFICATION_VERIFIED
            check(UltraKernelPatchAsset.validSource(defaultSource)) {
                "ULTRA_KERNEL_RELEASE_META_SOURCE:$directory"
            }
            check(UltraKernelPatchAsset.validVerification(defaultVerification)) {
                "ULTRA_KERNEL_RELEASE_META_VERIFICATION:$directory"
            }
            val format = root.optString("specFormat") ?: SPEC_FORMAT_OFFSET
            check(format == SPEC_FORMAT_OFFSET) {
                "ULTRA_KERNEL_RELEASE_SPEC_FORMAT_UNSUPPORTED:$directory:$format"
            }

            val single = root["assets"] == null
            val rows: List<JsonObject> = root["assets"]?.let { element ->
                val array = element as? JsonArray
                    ?: throw IllegalStateException("ULTRA_KERNEL_RELEASE_META_INVALID:$directory")
                check(array.size in 1..MAX_ASSETS_PER_RELEASE) {
                    "ULTRA_KERNEL_RELEASE_META_ASSETS:$directory"
                }
                array.map {
                    it as? JsonObject
                        ?: throw IllegalStateException("ULTRA_KERNEL_RELEASE_META_INVALID:$directory")
                }
            } ?: listOf(root)

            val defaultId = root.optString("defaultAsset")
            val assets = rows.map { row ->
                parseAsset(directory, release, row, defaultSource, defaultVerification, defaultId, single)
            }
            check(assets.map { it.id }.toSet().size == assets.size) {
                "ULTRA_KERNEL_RELEASE_ASSET_DUPLICATE:$directory"
            }
            check(assets.count { it.default } <= 1) {
                "ULTRA_KERNEL_RELEASE_ASSET_DEFAULT_DUPLICATE:$directory"
            }
            check(defaultId == null || assets.any { it.id == defaultId }) {
                "ULTRA_KERNEL_RELEASE_ASSET_DEFAULT_UNKNOWN:$directory:$defaultId"
            }
            return assets
        }

        private fun parseAsset(
            directory: String,
            release: String,
            row: JsonObject,
            defaultSource: String,
            defaultVerification: String,
            defaultId: String?,
            single: Boolean,
        ): UltraKernelReleaseAsset {
            val id = row.requiredString("id", "ULTRA_KERNEL_RELEASE_ASSET_ID:$directory")
            check(ID.matches(id)) { "ULTRA_KERNEL_RELEASE_ASSET_ID:$directory:$id" }
            val specFile = row.optString("spec") ?: if (single) "$release.spec" else "$id.spec"
            check(SPEC_FILE.matches(specFile)) {
                "ULTRA_KERNEL_RELEASE_ASSET_SPEC_PATH:$directory:$specFile"
            }
            val specSha = row.requiredString("specSha256", "ULTRA_KERNEL_RELEASE_ASSET_SPEC_HASH:$id")
            check(SHA256.matches(specSha)) { "ULTRA_KERNEL_RELEASE_ASSET_SPEC_HASH:$id" }
            val patches = row.int("patchCount")
                ?: throw IllegalStateException("ULTRA_KERNEL_RELEASE_ASSET_PATCH_COUNT:$id")
            check(patches in 1..UltraKernelSpec.MAX_PATCHES) {
                "ULTRA_KERNEL_RELEASE_ASSET_PATCH_COUNT:$id:$patches"
            }
            val expectedKernel = row.requiredString(
                "expectedKernelSha256", "ULTRA_KERNEL_RELEASE_ASSET_KERNEL_HASH:$id")
            check(SHA256.matches(expectedKernel)) { "ULTRA_KERNEL_RELEASE_ASSET_KERNEL_HASH:$id" }
            val baseKernel = row.optString("baseKernelSha256") ?: ""
            check(baseKernel.isEmpty() || SHA256.matches(baseKernel)) {
                "ULTRA_KERNEL_RELEASE_ASSET_BASE_HASH:$id"
            }
            val imageSize = row.long("expectedImageSize")
                ?: throw IllegalStateException("ULTRA_KERNEL_RELEASE_ASSET_IMAGE_SIZE:$id")
            check(imageSize in 1..UltraKernelCatalog.MAX_IMAGE_BYTES) {
                "ULTRA_KERNEL_RELEASE_ASSET_IMAGE_SIZE:$id:$imageSize"
            }
            val ramdiskSize = row.long("ramdiskSize") ?: 0L
            check(ramdiskSize in 0..imageSize) { "ULTRA_KERNEL_RELEASE_ASSET_RAMDISK:$id" }
            val knownBase = row.optString("knownBaseImageSha256") ?: ""
            check(knownBase.isEmpty() || SHA256.matches(knownBase)) {
                "ULTRA_KERNEL_RELEASE_ASSET_KNOWN_BASE:$id"
            }
            val expectedBoot = row.optString("expectedBootSha256") ?: ""
            check(expectedBoot.isEmpty() || SHA256.matches(expectedBoot)) {
                "ULTRA_KERNEL_RELEASE_ASSET_EXPECTED_BOOT:$id"
            }
            check(knownBase.isEmpty() || expectedBoot.isNotEmpty()) {
                "ULTRA_KERNEL_RELEASE_ASSET_EXPECTED_BOOT_MISSING:$id"
            }
            val source = row.optString("source") ?: defaultSource
            check(UltraKernelPatchAsset.validSource(source)) { "ULTRA_KERNEL_RELEASE_ASSET_SOURCE:$id" }
            val verification = row.optString("verification") ?: defaultVerification
            check(UltraKernelPatchAsset.validVerification(verification)) {
                "ULTRA_KERNEL_RELEASE_ASSET_VERIFICATION:$id"
            }
            val isDefault = row.boolean("default") ?: (single || defaultId == id)
            return UltraKernelReleaseAsset(
                id = id,
                label = row.optString("label") ?: id,
                summary = row.optString("summary") ?: "",
                specAsset = "$ROOT/$directory/$specFile",
                specSha256 = specSha,
                patches = patches,
                kernelRelease = release,
                baseKernelSha256 = baseKernel,
                expectedKernelSha256 = expectedKernel,
                knownBaseImageSha256 = knownBase,
                knownBaseImageBootSha256 = expectedBoot,
                imageSizeBytes = imageSize,
                ramdiskSize = ramdiskSize,
                source = source,
                verification = verification,
                default = isDefault,
                debugOnly = row.boolean("debugOnly") ?: false,
                debugReason = row.optString("debugReason") ?: "",
            )
        }

        private fun JsonObject.requiredString(key: String, code: String): String =
            optString(key) ?: throw IllegalStateException(code)

        private fun JsonObject.optString(key: String): String? =
            (this[key] as? JsonPrimitive)?.contentOrNull

        private fun JsonObject.int(key: String): Int? =
            (this[key] as? JsonPrimitive)?.intOrNull

        private fun JsonObject.long(key: String): Long? =
            (this[key] as? JsonPrimitive)?.longOrNull

        private fun JsonObject.boolean(key: String): Boolean? =
            (this[key] as? JsonPrimitive)?.booleanOrNull
    }
}

/**
 * Loads and gates one release asset's spec: digest, record count and kernel **series** must match
 * the catalogue's pinned values before a single byte is written.
 *
 * The series - not the full release - is the version gate: the spec of the `6.6.89` asset is what a
 * `6.6.50` boot is allowed to try, and whether its records fit is decided by `UltraKernelSpec.apply`
 * on the real kernel bytes. The code name is unchanged (`ULTRA_KERNEL_ASSET_SPEC_RELEASE`, still
 * prefixed with the asset id) so existing callers keep matching on it.
 */
internal fun loadReleaseSpec(
    assets: UltraKernelAssetSource,
    asset: UltraKernelReleaseAsset,
): UltraKernelSpec {
    check(asset.ready) { "ULTRA_KERNEL_ASSET_UNAVAILABLE:${asset.id}" }
    val bytes = try {
        assets.read(asset.specAsset)
    } catch (error: java.io.FileNotFoundException) {
        throw IllegalStateException("ULTRA_KERNEL_ASSET_SPEC_MISSING:${asset.id}")
    }
    check(bytes.size.toLong() <= UltraKernelSpec.MAX_SPEC_BYTES) {
        "ULTRA_KERNEL_ASSET_SPEC_TOO_LARGE:${asset.id}"
    }
    val digest = sha256Hex(bytes)
    check(digest == asset.specSha256) { "ULTRA_KERNEL_ASSET_SPEC_DIGEST:${asset.id}:$digest" }
    val spec = UltraKernelSpec.parse(bytes.toString(Charsets.UTF_8))
    check(spec.patches.size == asset.patches) {
        "ULTRA_KERNEL_ASSET_SPEC_COUNT:${asset.id}:${spec.patches.size}"
    }
    check(KernelSeries.same(spec.kernelRelease, asset.kernelRelease)) {
        "ULTRA_KERNEL_ASSET_SPEC_RELEASE:${asset.id}:" +
            KernelSeries.detail(spec.kernelRelease, asset.kernelRelease)
    }
    return spec
}

