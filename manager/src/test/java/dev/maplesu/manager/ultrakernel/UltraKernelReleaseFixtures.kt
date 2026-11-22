package dev.maplesu.manager.ultrakernel

import java.io.File
import java.nio.file.Files
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray

/**
 * Fixtures shared by the release-catalogue host tests. Everything is built from the *shipped*
 * assets, so a digest pinned in a test cannot drift from the asset the app actually reads.
 */
internal object UltraKernelReleaseFixtures {
    const val RELEASE = "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k"
    const val OTHER_RELEASE = "6.1.25-android14-11-o-gf12b379cb280"

    const val BASE_KERNEL = "346d51ea1f63413ffa5d99c5c426806291af3573f0a1d66a7621c388e835880e"
    const val K22_KERNEL = "3a601ef90eab78594ece64767de5cb1176e4ec471729372af08b02c6b04477ab"
    const val K21_KERNEL = "6e6a2faa4d6fe0faef98d4cfe5d050a70155e25d1ba4a8127d07b9b534d63602"
    const val K21_BOOT = "57e7a3537cc1bf8723070c6bf182d9649b0edae58f0756717528367b9aefa822"
    const val K22_BOOT = "3180b35c65bff6f2b6d91437899c9e1e54fff7431347334128d8816a0eff13e6"
    const val KNOWN_BASE_IMAGE = "c07fd486b563c370d2294f580be02fb5b24feaf4966932d3111d6a61b219f243"
    const val IMAGE_SIZE = 100663296L

    const val K22_SPEC = "k22-ultra-6.6.89.spec"
    const val K21_SPEC = "k21-ultra-6.6.89.spec"

    val assetRoot: File = File("src/main/assets/ultra-kernels")

    fun k22Bytes(): ByteArray = File(assetRoot, K22_SPEC).readBytes()
    fun k21Bytes(): ByteArray = File(assetRoot, K21_SPEC).readBytes()
    fun specSha(bytes: ByteArray): String = UltraKernelSpec.sha256(bytes)
    fun manifestText(): String = File(assetRoot, "manifest.json").readText()

    private fun asset(
        id: String,
        spec: String,
        specSha: String,
        patchCount: Int,
        baseKernel: String?,
        expectedKernel: String,
        knownBase: String?,
        expectedBoot: String?,
        default: Boolean = false,
        verification: String? = null,
    ): JsonObject = buildJsonObject {
        put("id", id)
        put("label", id)
        put("summary", "")
        put("spec", spec)
        put("specSha256", specSha)
        put("patchCount", patchCount)
        if (baseKernel != null) put("baseKernelSha256", baseKernel)
        put("expectedKernelSha256", expectedKernel)
        put("expectedImageSize", IMAGE_SIZE)
        if (knownBase != null) put("knownBaseImageSha256", knownBase)
        if (expectedBoot != null) put("expectedBootSha256", expectedBoot)
        put("ramdiskSize", 0)
        if (default) put("default", true)
        if (verification != null) put("verification", verification)
    }

    /** Multi-asset meta, normally identical to the shipped 6.6.89 release. */
    fun meta(
        release: String = RELEASE,
        k22Sha: String = specSha(k22Bytes()),
        k22Patches: Int = 16,
        k22Base: String? = BASE_KERNEL,
        k22ExpectedKernel: String = K22_KERNEL,
        k22KnownBase: String? = KNOWN_BASE_IMAGE,
        k22ExpectedBoot: String? = K22_BOOT,
        k22Spec: String = K22_SPEC,
        includeK21: Boolean = true,
        verification: String = "verified",
        source: String = "sample",
    ): String = buildJsonObject {
        put("schema", 1)
        put("kernelRelease", release)
        put("source", source)
        put("verification", verification)
        put("defaultAsset", "k22")
        putJsonArray("assets") {
            add(asset(
                "k22", k22Spec, k22Sha, k22Patches, k22Base, k22ExpectedKernel,
                k22KnownBase, k22ExpectedBoot, default = true,
            ))
            if (includeK21) {
                add(asset(
                    "k21", K21_SPEC, specSha(k21Bytes()), 15, BASE_KERNEL, K21_KERNEL,
                    KNOWN_BASE_IMAGE, K21_BOOT,
                ))
            }
        }
    }.toString()

    /** Single-asset form: the asset fields sit directly at the top level. */
    fun singleMeta(
        specSha: String = specSha(k22Bytes()),
        verification: String = "verified",
    ): String = buildJsonObject {
        put("schema", 1)
        put("kernelRelease", RELEASE)
        put("source", "model")
        put("verification", verification)
        put("id", "one")
        put("label", "single")
        put("spec", "$RELEASE.spec")
        put("specSha256", specSha)
        put("patchCount", 15)
        put("baseKernelSha256", BASE_KERNEL)
        put("expectedKernelSha256", K22_KERNEL)
        put("expectedImageSize", IMAGE_SIZE)
    }.toString()

    fun releaseAssets(
        metaText: String,
        directory: String = RELEASE,
        specs: Map<String, ByteArray> = mapOf(
            K22_SPEC to k22Bytes(),
            K21_SPEC to k21Bytes(),
        ),
    ): UltraKernelAssetSource {
        val files = LinkedHashMap<String, ByteArray>()
        files["ultra-kernels/releases/$directory/meta.json"] = metaText.toByteArray()
        for ((name, bytes) in specs) {
            files["ultra-kernels/releases/$directory/$name"] = bytes
        }
        return UltraKernelMemoryAssets(files)
    }

    fun legacyAssets(
        manifest: String = manifestText(),
        k22: ByteArray = k22Bytes(),
        k21: ByteArray = k21Bytes(),
    ): UltraKernelAssetSource = UltraKernelMemoryAssets(
        mapOf(
            UltraKernelCatalog.ASSET to manifest.toByteArray(),
            "ultra-kernels/$K22_SPEC" to k22,
            "ultra-kernels/$K21_SPEC" to k21,
        ),
    )

    /** Legacy manifest plus one release directory, for the compatibility-order tests. */
    fun combinedAssets(
        releaseMeta: String,
        directory: String = RELEASE,
        specs: Map<String, ByteArray> = mapOf(
            K22_SPEC to k22Bytes(),
            K21_SPEC to k21Bytes(),
        ),
    ): UltraKernelAssetSource {
        val files = LinkedHashMap<String, ByteArray>()
        files[UltraKernelCatalog.ASSET] = manifestText().toByteArray()
        files["ultra-kernels/$K22_SPEC"] = k22Bytes()
        files["ultra-kernels/$K21_SPEC"] = k21Bytes()
        files["ultra-kernels/releases/$directory/meta.json"] = releaseMeta.toByteArray()
        for ((name, bytes) in specs) {
            files["ultra-kernels/releases/$directory/$name"] = bytes
        }
        return UltraKernelMemoryAssets(files)
    }

    fun tempWorkspace(prefix: String): File =
        Files.createTempDirectory(prefix).toFile().also { it.mkdirs() }

    /**
     * Minimal AOSP boot v4 container whose raw kernel carries [release] and the `ARMd` marker
     * [BootImageInspector] needs to classify it as an uncompressed arm64 Image. It is enough for
     * release identification and for the unsupported/gating paths; it is not a patchable kernel.
     */
    fun syntheticBoot(release: String): ByteArray {
        val page = 4096
        val kernel = ByteArray(8192)
        "ARMd".toByteArray(Charsets.US_ASCII).copyInto(kernel, 56)
        "Linux version $release (build-host) (Android clang)".toByteArray(Charsets.US_ASCII)
            .copyInto(kernel, 128)
        val file = ByteArray(page + kernel.size)
        "ANDROID!".toByteArray(Charsets.US_ASCII).copyInto(file, 0)
        putU32(file, 8, kernel.size)
        putU32(file, 12, 0)
        putU32(file, 20, 1584)
        putU32(file, 40, 4)
        putU32(file, 1580, 0)
        kernel.copyInto(file, page)
        return file
    }

    private fun putU32(target: ByteArray, offset: Int, value: Int) {
        for (index in 0 until 4) target[offset + index] = (value ushr (index * 8)).toByte()
    }
}
