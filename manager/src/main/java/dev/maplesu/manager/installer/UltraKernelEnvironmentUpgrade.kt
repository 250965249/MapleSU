package dev.maplesu.manager.installer

import android.content.Context
import android.os.Build
import android.os.Bundle
import dev.maplesu.manager.modules.UltraRootKeyStore
import dev.maplesu.manager.ultrakernel.UltraKernelContextAssets
import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import dev.maplesu.manager.ultrakernel.UltraKernelOriginalRecovery
import dev.maplesu.manager.ultrakernel.UltraKernelPlan
import dev.maplesu.manager.ultrakernel.UltraKernelSpec
import dev.maplesu.manager.ultrakernel.UltraKernelUpdateRequirement
import dev.maplesu.manager.ultrakernel.UltraKernelVivoFilter
import java.io.File

/** Invoked by explicit repair/upgrade only; startup never opens the boot partition here. */
internal object UltraKernelEnvironmentUpgrade {
    fun required(context: Context): Boolean {
        val key = UltraRootKeyStore.read(context)?.takeIf(UltraKernelCredential::isValid) ?: return false
        val (partition, snapshot) = InstallerServiceClient.analyzeCurrentCarrier(context)
        if (partition == "init_boot") {
            val boot = snapshot.partitions["boot"] ?: error("ULTRA_INIT_PAIRED_BOOT_REQUIRED")
            val paired = InstallerServiceClient.capturePairedBoot(context, snapshot,
                File(context.filesDir, "ultra-init-paired-${boot.sha256}.img"))
            val artifact = dev.maplesu.manager.ultrakernel.UltraKernelFlow.initBootArtifact(context, paired)
                ?: error("ULTRA_KERNEL_INIT_BOOT_ARTIFACT_REQUIRED:bridge.ko,handoff,target-kernel-loading-contract")
            check(artifact.targetBootSha256 == boot.sha256) {
                "ULTRA_KERNEL_INIT_BOOT_TARGET_CHANGED"
            }
            val image = File(context.filesDir, "images/imported.img")
            return dev.maplesu.manager.ultrakernel.UltraKernelFlow.initBootUpdateRequired(
                image, artifact, UltraKernelCredential.of(key))
        }
        val image = File(context.filesDir, "images/imported.img")
        if (dev.maplesu.image.UltraInitBootProducer.recognizes(image)) {
            val artifact = dev.maplesu.manager.ultrakernel.UltraKernelFlow.initBootArtifact(context, image)
                ?: error("ULTRA_KERNEL_MODULE_CARRIER_ARTIFACT_MISSING")
            return dev.maplesu.manager.ultrakernel.UltraKernelFlow.initBootUpdateRequired(
                image, artifact, UltraKernelCredential.of(key))
        }
        val recovery = UltraKernelOriginalRecovery(UltraKernelContextAssets(context))
        val receipts = dev.maplesu.manager.compat.UltraStateStorage.flash(context.filesDir)
        var spec = recovery.installedSpec(image, receipts)
        if (spec == null && installedRecord(context, UltraKernelSpec.sha256(image))
                ?.getString("signingMode") in setOf("CHAINED", "AOSP") &&
            recovery.retainPreviouslySignedCandidate(image, receipts)) {
            spec = recovery.installedSpec(image, receipts)
        }
        if (spec == null && recovery.archivedKernelUpdateRequired(image)) return true
        if (UltraKernelUpdateRequirement.required(spec, UltraKernelCredential.of(key))) return true
        return VivoCompatibility.deviceSupported() && !UltraKernelVivoFilter.present(UltraKernelPlan.readKernel(image))
    }

    fun signingOptions(context: Context): LenovoSigningOptions {
        val (partition, snapshot) = InstallerServiceClient.analyzeCurrentCarrier(context)
        val currentSha = snapshot.partitions.getValue(partition).sha256
        return kernelUpdateSigningOptions(Build.FINGERPRINT,
            installedRecord(context, currentSha, partition, snapshot.slotSuffix)?.getString("signingMode"))
    }

    private fun installedRecord(context: Context, currentSha: String, partition: String = "boot",
                                slot: String? = null): Bundle? {
        val status = InstallerServiceClient.installationStatus(context)
        val installed = status.getString("operation") == "INSTALL" &&
            status.getString("partition") == partition && status.getString("targetMode") == "LITE" &&
            status.getString("state") in setOf("REBOOT_REQUIRED", "REBOOT_REQUESTED", "BOOT_IMAGE_VERIFIED", "VERIFIED", "BOOT_VERIFIED") &&
            (slot == null || status.getString("slotSuffix") == slot) &&
            !status.getBoolean("operationActive") && status.getString("partitionSha256") == currentSha
        return status.takeIf { installed }
    }
}

/** A matching installed receipt keeps its choice; otherwise use the install page's default. */
internal fun kernelUpdateSigningOptions(fingerprint: String?, installedMode: String?): LenovoSigningOptions =
    when (installedMode) {
        null -> LenovoSigningOptions(enabled = lenovoFingerprint(fingerprint))
        "" -> LenovoSigningOptions()
        "CHAINED" -> LenovoSigningOptions(enabled = true)
        "AOSP" -> LenovoSigningOptions(enabled = true, aosp = true)
        "NON_CHAINED" -> LenovoSigningOptions(enabled = true)
        else -> error("LENOVO_AVB_INSTALLED_MODE_INVALID")
    }
