package dev.maplesu.manager.installer

import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.WallClock
import dev.maplesu.manager.ultrakernel.UltraKernelCatalog
import dev.maplesu.manager.workmode.switch.BaselineErrors
import dev.maplesu.manager.workmode.switch.BaselineResult
import dev.maplesu.manager.workmode.switch.DeviceBootFacts
import dev.maplesu.manager.workmode.switch.FileBaselineStore
import java.io.File
import java.util.UUID

/** Read-only live capture plus a receipt-bound proof, followed by the existing baseline importer. */
internal class RecoveredOriginalBaselineProvisioner(
    private val bridge: BaselineControlPlaneBridge,
    private val capture: BaselineLiveCapturePort,
    private val stagingRoot: File,
    private val deviceFacts: () -> DeviceBootFacts,
    private val recoverOriginal: (currentBoot: File, output: File) -> File?,
    private val freeBytes: () -> Long,
    private val requiredPartitions: Set<String>? = null,
    private val clock: Clock = WallClock,
) : BaselineProvisioner {
    override fun ensureBaseline(): BaselineProvisionOutcome {
        val device = deviceFacts()
        val probe = capture.probe() ?: return failure("partition topology unavailable")
        if (probe.slot != device.slot || probe.firmware != device.firmware || probe.kernelRelease != device.kernelRelease) {
            return failure("device changed before original reconstruction")
        }
        val required = requiredPartitions ?: probe.devices.keys
        if ("boot" !in required || required.any { it !in BaselineIdentity.PARTITIONS } ||
            !probe.devices.keys.containsAll(required)) return failure("partition topology incomplete")
        if (required.any { (probe.sizes[it] ?: 0L) !in 1..UltraKernelCatalog.MAX_IMAGE_BYTES }) {
            return failure("partition sizes unavailable")
        }
        val existing = bridge.probe() ?: return failure("baseline control plane unreadable")
        reusableBaselineEntry(existing, device, BaselineIdentity.fromDevice(device), "init_boot" in required)
            ?.let { return BaselineProvisionOutcome.Ready(it.first.id, true, it.second.provenance) }
        // The importer temporarily holds source, verification and published copies. Budget their
        // full partition sizes plus the bounded kernel rebuild, rather than a fixed 256 MiB.
        val stagingBytes = 4 * probe.sizes.getValue("boot") +
            3 * (if ("init_boot" in required) probe.sizes.getValue("init_boot") else 0L) +
            128L * 1024 * 1024
        if (freeBytes() < maxOf(RootPublishingBaselineProvisioner.MIN_FREE_BYTES, stagingBytes)) {
            return failure("insufficient recovery staging space")
        }
        val staging = File(stagingRoot, "original-${UUID.randomUUID()}")
        try {
            if (!staging.mkdirs()) return failure("recovery staging unavailable")
            val current = capture.copy("boot", File(staging, "current-boot.img"))
            if (current.size != probe.sizes["boot"] || current.file.length() != current.size) {
                return failure("boot partition size changed")
            }
            val original = recoverOriginal(current.file, File(staging, "proof"))
                ?: return failure("no exact original/candidate roundtrip; import the original factory image")
            if (original.length() != probe.sizes["boot"]) return failure("original partition size mismatch")
            val imports = File(staging, "originals").apply { mkdirs() }
            original.copyTo(File(imports, "boot.img"))
            val facts = linkedMapOf("boot" to BaselinePartitionFacts("boot", original.length(), BaselineAtomicFiles.sha256(original)))
            current.file.delete()
            File(staging, "proof").deleteRecursively()
            if ("init_boot" in required) {
                val initBoot = capture.copy("init_boot", File(imports, "init_boot.img"))
                if (initBoot.size != probe.sizes["init_boot"]) return failure("init_boot partition size changed")
                facts["init_boot"] = BaselinePartitionFacts("init_boot", initBoot.size, initBoot.sha256)
            }
            val after = capture.probe()
            if (after != probe) return failure("device changed during original reconstruction")
            val snapshot = BaselineDeviceSnapshot(device.slot, device.firmware, device.kernelRelease, probe.selinux, facts)
            val source = object : BaselinePartitionSourcePort {
                override fun snapshot() = snapshot
                override fun readPartition(name: String, destination: File): BaselinePartitionRead = error("import-only recovery")
            }
            val store = FileBaselineStore(staging, { device }, clock,
                InstallerBaselineMaterializer(source, RamdiskBaselineCleanliness(),
                    BaselinePatchEvidencePort { BaselinePatchEvidence(true, false, null, "exact-preimage-roundtrip") }, clock))
            val id = BaselineIdentity.fromSnapshot(snapshot)
            val imported = BaselineCaptureService(store, source, clock).import(
                id, imports, provenance = BaselineSources.CAPTURED_PRE_WRITE)
            if (imported is BaselineResult.Failed) return BaselineProvisionOutcome.Failed(imported.code, imported.detail)
            val manifest = (imported as BaselineResult.Ok).manifest
            val expected = manifest.partitions.associate { it.name to it.sha256 }
            if (!bridge.publish(id, File(staging, "boot/baseline/$id"), expected)) return failure("recovery publication failed")
            val verified = bridge.probe()?.let { reusableBaselineEntry(it, device, id, "init_boot" in required) }
                ?.takeIf { it.first.id == id } ?: return failure("recovery baseline readback mismatch")
            return BaselineProvisionOutcome.Ready(id, false, verified.second.provenance)
        } catch (error: Exception) {
            return failure("original reconstruction failed: ${error.javaClass.simpleName}")
        } finally {
            staging.deleteRecursively()
        }
    }
    private fun failure(detail: String) = BaselineProvisionOutcome.Failed(BaselineErrors.BASELINE_PROVENANCE_UNKNOWN, detail)
}
