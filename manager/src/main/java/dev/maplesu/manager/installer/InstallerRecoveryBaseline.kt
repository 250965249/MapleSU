package dev.maplesu.manager.installer

import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.WallClock
import dev.maplesu.manager.workmode.superuser.LiteImplantScripts
import dev.maplesu.manager.workmode.superuser.RootScriptRunner
import dev.maplesu.manager.workmode.switch.BaselineErrors
import dev.maplesu.manager.workmode.switch.BaselineResult
import dev.maplesu.manager.workmode.switch.DeviceBootFacts
import dev.maplesu.manager.workmode.switch.FileBaselineStore
import kotlinx.serialization.Serializable
import java.io.File
import java.util.Base64
import java.util.UUID

@Serializable
internal data class InstallerRecoveryPartition(
    val resolvedPath: String,
    val size: Long,
    val sha256: String,
)

@Serializable
internal data class InstallerRecoveryRecord(
    val schema: Int,
    val taskId: String,
    val state: String,
    val kernelRelease: String,
    val firmware: String,
    val slotSuffix: String,
    val partitions: Map<String, InstallerRecoveryPartition>,
) {
    fun matches(device: DeviceBootFacts, required: Set<String>): Boolean =
        schema == 1 && validTaskId(taskId) && state in COMPLETED_STATES &&
            slotSuffix == device.slot &&
            "boot" in required && partitions.keys.containsAll(required) && required.all { name ->
                val partition = partitions.getValue(name)
                partition.size in 1..InstallerSnapshotParser.maxPartitionBytes &&
                    Regex("[0-9a-f]{64}").matches(partition.sha256) &&
                    partition.resolvedPath.startsWith("/dev/block/") &&
                    partition.resolvedPath.split('/').none { it == ".." || it == "." }
            }

    companion object {
        private val COMPLETED_STATES = setOf("REBOOT_REQUIRED", "REBOOT_REQUESTED", "BOOT_IMAGE_VERIFIED", "RESTORED")
        fun validTaskId(value: String): Boolean = runCatching {
            UUID.fromString(value).toString() == value
        }.getOrDefault(false)
    }
}

internal interface InstallerRecoverySource {
    fun records(): List<InstallerRecoveryRecord>?
    fun copyBoot(record: InstallerRecoveryRecord, destination: File): BaselineCapturedImage
}

/** Reads only the installer's own private task directory, never unrelated backup directories. */
internal class RootInstallerRecoverySource(
    private val runner: RootScriptRunner,
    private val appUid: Int,
    private val root: String = "/data/adb/maplesu/installer",
) : InstallerRecoverySource {
    override fun records(): List<InstallerRecoveryRecord>? = runCatching {
        val result = runner.run(recordsScript())
        if (result.code != 0 || result.out.lineSequence().none { it == "RECOVERY_LISTED" }) return null
        result.out.lineSequence().filter { it.startsWith("REC:") }.mapNotNull { line ->
            val parts = line.split(':', limit = 3)
            if (parts.size != 3 || !InstallerRecoveryRecord.validTaskId(parts[1])) return@mapNotNull null
            val json = String(Base64.getDecoder().decode(parts[2]), Charsets.UTF_8)
            ControlJsonCodec.decodeOrNull(json, InstallerRecoveryRecord.serializer())
                ?.takeIf { it.taskId == parts[1] }
        }.toList()
    }.getOrNull()

    override fun copyBoot(record: InstallerRecoveryRecord, destination: File): BaselineCapturedImage {
        require(InstallerRecoveryRecord.validTaskId(record.taskId))
        val original = record.partitions.getValue("boot")
        destination.parentFile?.mkdirs()
        val result = runner.run(copyScript(record.taskId, destination))
        if (result.code != 0 || !destination.isFile || destination.length() != original.size) {
            throw BaselineCaptureFault(BaselineCaptureCodes.CAPTURE_READ_FAILED, "installer recovery unavailable")
        }
        val actual = BaselineAtomicFiles.sha256(destination)
        if (actual != original.sha256) {
            throw BaselineCaptureFault(BaselineCaptureCodes.CAPTURE_SHA_MISMATCH, "installer recovery differs from record")
        }
        return BaselineCapturedImage("boot", destination, destination.length(), actual)
    }

    internal fun recordsScript(): String = buildString {
        appendLine("set -eu")
        appendLine("[ \"\$(/system/bin/id -u)\" = 0 ] || exit 2")
        appendLine("R=${LiteImplantScripts.quote(root)}")
        appendLine(privateCheckFunction())
        appendLine("if [ -e \"\$R\" ]; then")
        appendLine("private_path \"\$R\" 700 || exit 3")
        appendLine("for d in \"\$R\"/*; do")
        appendLine("[ -d \"\$d\" ] || continue")
        appendLine("private_path \"\$d\" 700 || continue")
        appendLine("[ -f \"\$d/record.json\" ] && [ -f \"\$d/recovery.img\" ] || continue")
        appendLine("private_path \"\$d/record.json\" 600 || continue")
        appendLine("private_path \"\$d/recovery.img\" 600 || continue")
        appendLine("z=\$(/system/bin/stat -c %s \"\$d/record.json\")")
        appendLine("[ \"\$z\" -gt 0 ] && [ \"\$z\" -le 65536 ] || continue")
        appendLine("n=\${d##*/}")
        appendLine("printf 'REC:%s:' \"\$n\"")
        appendLine("/system/bin/base64 \"\$d/record.json\" | /system/bin/tr -d '\\r\\n'; printf '\\n'")
        appendLine("done")
        appendLine("fi")
        appendLine("echo RECOVERY_LISTED")
    }

    internal fun copyScript(taskId: String, destination: File): String = buildString {
        require(InstallerRecoveryRecord.validTaskId(taskId))
        appendLine("set -eu")
        appendLine("[ \"\$(/system/bin/id -u)\" = 0 ] || exit 2")
        appendLine("R=${LiteImplantScripts.quote(root)}")
        appendLine("D=${LiteImplantScripts.quote("$root/$taskId")}")
        appendLine("T=${LiteImplantScripts.quote(destination.absolutePath)}")
        appendLine(privateCheckFunction())
        appendLine("private_path \"\$R\" 700 && private_path \"\$D\" 700 || exit 3")
        appendLine("[ -f \"\$D/record.json\" ] && [ -f \"\$D/recovery.img\" ] || exit 4")
        appendLine("private_path \"\$D/record.json\" 600 && private_path \"\$D/recovery.img\" 600 || exit 4")
        appendLine("/system/bin/cp \"\$D/recovery.img\" \"\$T\"")
        appendLine("/system/bin/chmod 0600 \"\$T\"")
        appendLine("/system/bin/chown $appUid:$appUid \"\$T\"")
        appendLine("/system/bin/restorecon \"\$T\" 2>/dev/null || true")
    }

    private fun privateCheckFunction(): String =
        "private_path() { [ ! -L \"\$1\" ] && [ \"\$(/system/bin/stat -c '%u:%a' \"\$1\" 2>/dev/null)\" = \"0:\$2\" ]; }"
}

/**
 * Imports a historical original only with independent trusted stock pins. A transaction digest
 * alone proves integrity, not cleanliness: a second installation may back up an already-patched
 * boot. init_boot bytes were never stored by the old installer, so the live partition is usable
 * only when it still equals the original record's full-partition digest.
 */
internal class InstallerRecoveryBaselineProvisioner(
    private val bridge: BaselineControlPlaneBridge,
    private val recovery: InstallerRecoverySource,
    private val capture: BaselineLiveCapturePort,
    private val stagingRoot: File,
    private val deviceFacts: () -> DeviceBootFacts,
    private val trustedOriginalBoot: (File, String) -> Boolean,
    private val freeBytes: () -> Long,
    private val requiredPartitions: Set<String>? = null,
    private val clock: Clock = WallClock,
) : BaselineProvisioner {
    override fun ensureBaseline(): BaselineProvisionOutcome {
        val device = deviceFacts()
        val probe = capture.probe() ?: return failure("partition topology unavailable")
        if (probe.slot != device.slot || probe.firmware != device.firmware || probe.kernelRelease != device.kernelRelease) {
            return failure("live device changed before recovery import")
        }
        val required = requiredPartitions ?: probe.devices.keys
        if ("boot" !in required || required.any { it !in BaselineIdentity.PARTITIONS } ||
            !probe.devices.keys.containsAll(required)
        ) return failure("recovery partition topology incomplete")
        val existing = bridge.probe() ?: return failure("baseline control plane unreadable")
        reusableBaselineEntry(existing, device, BaselineIdentity.fromDevice(device), "init_boot" in required)
            ?.let { return BaselineProvisionOutcome.Ready(it.first.id, true, it.second.provenance) }
        if (freeBytes() < RootPublishingBaselineProvisioner.MIN_FREE_BYTES) return failure("insufficient recovery staging space")
        val records = recovery.records() ?: return failure("installer recovery records unreadable")
        val candidates = records.filter { it.matches(device, required) }.sortedBy { it.taskId }
        if (candidates.isEmpty()) return failure("no matching private installer recovery record")
        var lastFailure = "no independently pinned original boot"
        for (record in candidates) {
            val staging = File(stagingRoot, "recovery-${record.taskId}")
            try {
                if (!staging.mkdirs() && !staging.isDirectory) return failure("recovery staging unavailable")
                val imports = File(staging, "originals").apply { mkdirs() }
                val boot = recovery.copyBoot(record, File(imports, "boot.img"))
                // 校验用的是**这份恢复记录当时的发布号**（= 原厂内核），不是正在跑的
                // release：Ultra/Normal 切换后运行的可能是另一颗内核，用 device.kernelRelease
                // 会把"换了内核但原厂 boot 没变"误判成不可信（反之也会漏判旧记录）。
                if (!trustedOriginalBoot(boot.file, record.kernelRelease)) {
                    lastFailure = "installer recovery boot has no matching trusted stock pin"
                    continue
                }
                val facts = linkedMapOf("boot" to BaselinePartitionFacts("boot", boot.size, boot.sha256))
                if ("init_boot" in required) {
                    val expected = record.partitions.getValue("init_boot")
                    val initBoot = capture.copy("init_boot", File(imports, "init_boot.img"))
                    if (initBoot.size != expected.size || initBoot.sha256 != expected.sha256 ||
                        probe.sizes["init_boot"] != expected.size
                    ) {
                        lastFailure = "original init_boot bytes missing: current partition differs from installer record"
                        continue
                    }
                    facts["init_boot"] = BaselinePartitionFacts("init_boot", initBoot.size, initBoot.sha256)
                }
                val snapshot = BaselineDeviceSnapshot(
                    device.slot, device.firmware, device.kernelRelease, probe.selinux, facts,
                )
                val source = object : BaselinePartitionSourcePort {
                    override fun snapshot(): BaselineDeviceSnapshot = snapshot
                    override fun readPartition(name: String, destination: File): BaselinePartitionRead =
                        error("recovery source is import-only")
                }
                val store = FileBaselineStore(
                    root = staging,
                    deviceFacts = { device },
                    clock = clock,
                    materializer = InstallerBaselineMaterializer(
                        source, RamdiskBaselineCleanliness(),
                        BaselinePatchEvidencePort { BaselinePatchEvidence(false, null, null) }, clock,
                    ),
                )
                val id = BaselineIdentity.fromSnapshot(snapshot)
                val imported = BaselineCaptureService(store, source, clock).import(
                    id, imports, provenance = BaselineSources.CAPTURED_PRE_WRITE,
                )
                if (imported is BaselineResult.Failed) {
                    lastFailure = "${imported.code}: ${imported.detail}"
                    continue
                }
                val manifest = (imported as BaselineResult.Ok).manifest
                val expected = manifest.partitions.associate { it.name to it.sha256 }
                if (!bridge.publish(id, File(staging, "boot/baseline/$id"), expected)) {
                    return failure("recovery baseline publication failed")
                }
                val after = bridge.probe() ?: return failure("recovery baseline readback unavailable")
                val verified = reusableBaselineEntry(after, device, id, "init_boot" in required)
                    ?.takeIf { it.first.id == id } ?: return failure("recovery baseline readback mismatch")
                return BaselineProvisionOutcome.Ready(id, false, verified.second.provenance)
            } catch (error: Exception) {
                lastFailure = error.message.orEmpty()
            } finally {
                staging.deleteRecursively()
            }
        }
        return failure(lastFailure)
    }

    private fun failure(detail: String) =
        BaselineProvisionOutcome.Failed(BaselineErrors.BASELINE_PROVENANCE_UNKNOWN, detail)
}
