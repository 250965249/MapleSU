package dev.maplesu.manager.ultrakernel

import android.content.Context
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull

/**
 * The legacy pinned kernel catalogue (`assets/ultra-kernels/manifest.json`).
 *
 * This is the pre-release-index delivery path: the manifest lists the k21/k22 variants for the
 * single 6.6.89 firmware that was device-verified. It is kept byte-for-byte so devices that
 * already carry that firmware keep the same verified fallback, while [UltraKernelReleaseCatalog]
 * becomes the runtime default for every release that has a `releases/<release>/` directory.
 *
 * Everything that authorises a write lives in the asset tree: the spec digest, the pristine base
 * kernel digest and the digest the patched kernel must produce. The app never derives these at
 * runtime, so a corrupted or swapped asset cannot reach a partition write - [load] and [spec]
 * both re-verify the digest they were given.
 *
 * Product policy (2026-10-29): [k22] is the delivery default ("MapleSU 内核（推荐）"), [k21]
 * stays as the compatibility fallback ("兼容内核（回退）"). A variant whose `status` is not
 * `ready` stays visible so a gap is honest, but cannot be built or flashed.
 */
internal data class UltraKernelVariant(
    override val id: String,
    override val label: String,
    override val summary: String,
    override val status: String,
    val reason: String,
    override val debugOnly: Boolean,
    override val debugReason: String,
    val default: Boolean,
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
    override val source: String = UltraKernelPatchAsset.SOURCE_SAMPLE,
    override val verification: String = UltraKernelPatchAsset.VERIFICATION_VERIFIED,
) : UltraKernelPatchAsset {
    override val ready: Boolean get() = status == "ready"
    override val isDefault: Boolean get() = default
}

/**
 * Variants usable on one kernel **series**, default first then newest; empty when no variant
 * belongs to that series.
 *
 * The match is [KernelSeries.same] - `6.6.50-android15-…` selects the shipped `6.6.89` variants,
 * because the product rule is a `major.minor` prefix match, not a release equality. Ordering is
 * [UltraKernelAssetOrder]: the manifest's `default` first, then the newest release of the series.
 */
internal fun orderForRelease(
    variants: List<UltraKernelVariant>,
    release: String,
): List<UltraKernelVariant> =
    variants.filter { it.ready && KernelSeries.same(it.kernelRelease, release) }
        .sortedWith(UltraKernelAssetOrder)


/**
 * Result of pre-validating an ordered candidate list.
 *
 * [rejected] keeps the exact `ULTRA_KERNEL_*` reason for every asset that failed, so a fallback
 * is never silent and a total failure can be reported verbatim. [fellBack] is true only when the
 * catalogue default itself was rejected and a later asset is being used instead.
 */
internal data class UltraKernelSelection(
    val usable: List<UltraKernelPatchAsset>,
    val rejected: List<String>,
    val defaultId: String?,
) {
    val primary: UltraKernelPatchAsset get() = usable.first()
    val fellBack: Boolean get() = defaultId != null && usable.isNotEmpty() && primary.id != defaultId

    /** Warnings (currently only the experimental-level notice) for every usable asset. */
    val warnings: List<String> get() = usable.mapNotNull { it.warning }
}

/**
 * Validates [ordered] in order, keeping every asset for which [validate] returns `null`.
 * The validator must only inspect the pinned catalogue/spec - it must not touch a partition.
 */
internal fun <T : UltraKernelPatchAsset> selectUsable(
    ordered: List<T>,
    validate: (T) -> String?,
): UltraKernelSelection {
    val usable = ArrayList<UltraKernelPatchAsset>(ordered.size)
    val rejected = ArrayList<String>()
    for (asset in ordered) {
        val failure = validate(asset)
        if (failure == null) usable += asset else rejected += "${asset.id}:$failure"
    }
    return UltraKernelSelection(usable, rejected, ordered.firstOrNull()?.id)
}

internal class UltraKernelCatalog private constructor(val variants: List<UltraKernelVariant>) {
    fun variant(id: String?): UltraKernelVariant? = variants.firstOrNull { it.id == id }

    /** Catalogue default (k22), falling back to the first ready row for older manifests. */
    fun defaultVariant(): UltraKernelVariant? =
        variants.firstOrNull { it.ready && it.default } ?: variants.firstOrNull { it.ready }

    fun orderedForRelease(release: String): List<UltraKernelVariant> = orderForRelease(variants, release)

    /** Ready releases in this legacy manifest; used by the unsupported-release diagnostic. */
    fun knownReleases(): List<String> =
        variants.filter { it.ready && it.kernelRelease.isNotEmpty() }
            .map { it.kernelRelease }.distinct().sorted()

    companion object {
        const val ASSET = "ultra-kernels/manifest.json"
        private const val SCHEMA = 1
        internal const val MAX_ASSET_BYTES = 1L * 1024 * 1024
        private const val MAX_MANIFEST_BYTES = 256L * 1024
        private val SHA256 = Regex("[0-9a-f]{64}")

        fun load(context: Context): UltraKernelCatalog = load(UltraKernelContextAssets(context))

        /**
         * Loads the legacy manifest from an abstract asset source (host tests use an in-memory
         * source). A missing manifest yields the empty catalogue; a malformed one throws.
         */
        fun load(source: UltraKernelAssetSource): UltraKernelCatalog {
            val bytes = source.read(ASSET)
            check(bytes.size.toLong() <= MAX_MANIFEST_BYTES) { "ULTRA_KERNEL_ASSET_TOO_LARGE" }
            val root = try {
                Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)) as JsonObject
            } catch (error: Exception) {
                throw IllegalStateException("ULTRA_KERNEL_MANIFEST_INVALID")
            }
            check(root.int("schema") == SCHEMA) { "ULTRA_KERNEL_MANIFEST_SCHEMA" }
            val rows = root["variants"] as? JsonArray
                ?: throw IllegalStateException("ULTRA_KERNEL_MANIFEST_VARIANTS")
            val variants = rows.mapIndexed { index, element ->
                val row = element as? JsonObject
                    ?: throw IllegalStateException("ULTRA_KERNEL_MANIFEST_ROW:$index")
                val ready = row.optString("status") == "ready"
                UltraKernelVariant(
                    id = row.getString("id").also { id ->
                        check(id.matches(Regex("[a-z0-9]{2,16}"))) { "ULTRA_KERNEL_MANIFEST_ID" }
                    },
                    label = row.optString("label") ?: row.getString("id"),
                    summary = row.optString("summary") ?: "",
                    status = row.optString("status") ?: "unavailable",
                    reason = row.optString("reason") ?: "",
                    debugOnly = row.boolean("debugOnly") ?: false,
                    debugReason = row.optString("debugReason") ?: "",
                    default = row.boolean("default") ?: false,
                    specAsset = if (ready) row.getString("specAsset") else "",
                    specSha256 = if (ready) row.getString("specSha256") else "",
                    patches = row.int("patches") ?: 0,
                    kernelRelease = row.optString("kernelRelease") ?: "",
                    baseKernelSha256 = row.optString("baseKernelSha256") ?: "",
                    expectedKernelSha256 = row.optString("expectedKernelSha256") ?: "",
                    knownBaseImageSha256 = row.optString("knownBaseImageSha256") ?: "",
                    knownBaseImageBootSha256 = row.optString("knownBaseImageBootSha256") ?: "",
                    imageSizeBytes = row.long("imageSizeBytes") ?: 0,
                    ramdiskSize = row.long("ramdiskSize") ?: 0,
                    source = row.optString("source") ?: UltraKernelPatchAsset.SOURCE_SAMPLE,
                    verification = row.optString("verification")
                        ?: UltraKernelPatchAsset.VERIFICATION_VERIFIED,
                ).also { variant ->
                    if (!variant.ready) return@also
                    check(UltraKernelPatchAsset.validSource(variant.source)) {
                        "ULTRA_KERNEL_MANIFEST_SOURCE"
                    }
                    check(UltraKernelPatchAsset.validVerification(variant.verification)) {
                        "ULTRA_KERNEL_MANIFEST_VERIFICATION"
                    }
                    check(variant.specAsset.isNotEmpty()) { "ULTRA_KERNEL_MANIFEST_SPEC_ASSET" }
                    check(variant.specSha256.matches(SHA256)) { "ULTRA_KERNEL_MANIFEST_SPEC_HASH" }
                    check(variant.expectedKernelSha256.matches(SHA256)) {
                        "ULTRA_KERNEL_MANIFEST_KERNEL_HASH"
                    }
                    check(variant.baseKernelSha256.matches(SHA256)) {
                        "ULTRA_KERNEL_MANIFEST_BASE_HASH"
                    }
                    // The delivery variants must pin both the stock input boot and its exact
                    // output boot; a variant without them cannot prove what it will write.
                    check(variant.knownBaseImageSha256.matches(SHA256)) {
                        "ULTRA_KERNEL_MANIFEST_BASE_IMAGE_HASH"
                    }
                    check(variant.knownBaseImageBootSha256.matches(SHA256)) {
                        "ULTRA_KERNEL_MANIFEST_BASE_BOOT_HASH"
                    }
                    check(variant.patches in 1..UltraKernelSpec.MAX_PATCHES) {
                        "ULTRA_KERNEL_MANIFEST_PATCHES"
                    }
                    check(variant.imageSizeBytes in 1..MAX_IMAGE_BYTES) { "ULTRA_KERNEL_MANIFEST_IMAGE_SIZE" }
                }
            }
            check(variants.map { it.id }.toSet().size == variants.size) { "ULTRA_KERNEL_MANIFEST_DUPLICATE" }
            val defaults = variants.filter { it.default }
            check(defaults.size <= 1) { "ULTRA_KERNEL_MANIFEST_DEFAULT_DUPLICATE" }
            check(defaults.none { !it.ready }) { "ULTRA_KERNEL_MANIFEST_DEFAULT_NOT_READY" }
            check(variants.any { it.ready }) { "ULTRA_KERNEL_MANIFEST_NO_READY_VARIANT" }
            return UltraKernelCatalog(variants)
        }

        /** Legacy manifest when present; empty for a build that only ships `releases/`. */
        fun loadOrEmpty(source: UltraKernelAssetSource): UltraKernelCatalog =
            try {
                load(source)
            } catch (error: java.io.FileNotFoundException) {
                UltraKernelCatalog(emptyList())
            }

        /** Reads the spec asset and refuses it unless its digest is the pinned one. */
        fun spec(context: Context, variant: UltraKernelVariant): UltraKernelSpec =
            spec(UltraKernelContextAssets(context), variant)

        fun spec(assets: UltraKernelAssetSource, variant: UltraKernelVariant): UltraKernelSpec {
            check(variant.ready) { "ULTRA_KERNEL_VARIANT_UNAVAILABLE:${variant.id}" }
            val bytes = assets.read(variant.specAsset)
            check(bytes.size.toLong() <= UltraKernelSpec.MAX_SPEC_BYTES) { "ULTRA_KERNEL_ASSET_TOO_LARGE" }
            val digest = sha256Hex(bytes)
            check(digest == variant.specSha256) { "ULTRA_KERNEL_SPEC_DIGEST_MISMATCH:${variant.id}:$digest" }
            val spec = UltraKernelSpec.parse(bytes.toString(Charsets.UTF_8))
            check(spec.patches.size == variant.patches) {
                "ULTRA_KERNEL_SPEC_RECORD_COUNT:${spec.patches.size}"
            }
            // Series equality, not release equality: a spec written for `6.6.89` is the patch set a
            // `6.6.50` boot gets to try. The code name is unchanged so existing catch points keep
            // working; the payload now names both series and both real releases.
            check(KernelSeries.same(spec.kernelRelease, variant.kernelRelease)) {
                "ULTRA_KERNEL_SPEC_RELEASE_MISMATCH:${KernelSeries.detail(spec.kernelRelease, variant.kernelRelease)}"
            }

            return spec
        }

        const val MAX_IMAGE_BYTES = 512L * 1024 * 1024

        private fun JsonObject.getString(key: String): String =
            optString(key) ?: throw IllegalStateException("ULTRA_KERNEL_MANIFEST_FIELD:$key")

        private fun JsonObject.optString(key: String): String? =
            (this[key] as? JsonPrimitive)?.contentOrNull

        private fun JsonObject.int(key: String): Int? = (this[key] as? JsonPrimitive)?.intOrNull

        private fun JsonObject.long(key: String): Long? = (this[key] as? JsonPrimitive)?.longOrNull

        private fun JsonObject.boolean(key: String): Boolean? =
            (this[key] as? JsonPrimitive)?.booleanOrNull
    }
}
