package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.ultrakernel.UltraKernelAssetSource
import dev.maplesu.manager.ultrakernel.UltraKernelCatalog
import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import dev.maplesu.manager.ultrakernel.UltraKernelFlow
import dev.maplesu.manager.ultrakernel.UltraKernelReleaseAsset
import dev.maplesu.manager.ultrakernel.UltraKernelSpec
import dev.maplesu.manager.ultrakernel.UltraKernelVariant
import dev.maplesu.manager.ultrakernel.loadReleaseSpec
import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull

/** Local install evidence can restore a pending key; only the SDK can verify that identity. */
internal class UltraInstallCredentialHandoff(private val assets: UltraKernelAssetSource) {
    enum class Outcome { Recovered, KeyPresent, Suspended, NotUltraInstall, NoVerifiedCandidate, AmbiguousCandidate }

    fun recover(
        workspace: File,
        targetMode: String?,
        existingKey: String?,
        suspended: Boolean,
        storeRecoveredKey: (String) -> Boolean,
    ): Outcome {
        if (!existingKey.isNullOrBlank()) return Outcome.KeyPresent
        if (suspended) return Outcome.Suspended
        if (targetMode != "ultra") return Outcome.NotUltraInstall
        val receipts = workspace.listFiles { file ->
            file.isFile && file.name.startsWith("candidate-") && file.name.endsWith(".json")
        } ?: return Outcome.NoVerifiedCandidate
        if (receipts.isEmpty()) return Outcome.NoVerifiedCandidate
        val keys = receipts.mapNotNull { receipt ->
            runCatching { credentialFromReceipt(workspace, receipt) }.getOrNull()
        }.distinct()
        if (keys.isEmpty()) return Outcome.NoVerifiedCandidate
        if (keys.size != 1) return Outcome.AmbiguousCandidate
        return if (storeRecoveredKey(keys.single())) Outcome.Recovered else Outcome.KeyPresent
    }

    private fun credentialFromReceipt(workspace: File, receipt: File): String? {
        if (receipt.length() !in 1..65_536 || receipt.canonicalFile.parentFile != workspace.canonicalFile) return null
        val record = Json.parseToJsonElement(receipt.readText()) as? JsonObject ?: return null
        fun field(name: String) = record[name] as? JsonPrimitive
        fun text(name: String) = field(name)?.contentOrNull
        if (field("schemaVersion")?.intOrNull != 2 || dev.maplesu.manager.compat.StoredInputs.operation(text("operation").orEmpty()) != "ULTRA_KERNEL_GENERATE" ||
            field("readbackVerified")?.booleanOrNull != true || !text("planOrigin").isNullOrBlank()) return null
        val id = text("asset")?.takeIf { it.matches(Regex("[a-z0-9]{2,16}")) } ?: return null
        if (receipt.name != "candidate-$id.json") return null
        val release = text("assetKernelRelease") ?: return null
        val specSha = text("specSha256")?.takeIf(SHA256::matches) ?: return null
        val imageSha = text("candidateBootSha256")?.takeIf(SHA256::matches) ?: return null
        val kernelSha = text("patchedKernelSha256")?.takeIf(SHA256::matches) ?: return null
        val size = field("candidateImageBytes")?.longOrNull
            ?.takeIf { it in 1..UltraKernelCatalog.MAX_IMAGE_BYTES } ?: return null
        val image = File(workspace, "candidate-$id-${kernelSha.take(12)}.img")
        if (!image.isFile || image.canonicalFile.parentFile != workspace.canonicalFile ||
            image.length() != size || UltraKernelSpec.sha256(image) != imageSha) return null
        val asset = UltraKernelFlow(workspace, assets).selectForRelease(release)?.usable
            ?.singleOrNull { it.id == id && it.kernelRelease == release && it.specSha256 == specSha } ?: return null
        val spec = when (asset) {
            is UltraKernelReleaseAsset -> loadReleaseSpec(assets, asset)
            is UltraKernelVariant -> UltraKernelCatalog.spec(assets, asset)
            else -> return null
        }
        return spec.key.takeIf(UltraKernelCredential::isValid)
    }

    private companion object {
        val SHA256 = Regex("[0-9a-f]{64}")
    }
}
