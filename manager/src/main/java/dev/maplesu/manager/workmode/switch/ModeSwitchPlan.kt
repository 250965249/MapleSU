package dev.maplesu.manager.workmode.switch

import dev.maplesu.installer.StepRole
import dev.maplesu.installer.SwitchFailure
import dev.maplesu.installer.SwitchPlan
import dev.maplesu.installer.SwitchStep
import dev.maplesu.installer.WorkMode as InstallerWorkMode
import dev.maplesu.manager.workmode.WorkMode

/**
 * 把 S2/S3 的产物组装成 `installer-core` 的不可变 [SwitchPlan]（02 §4.3）。
 *
 * 输入全部来自**已持久化**的服务端观测与本地导出镜像：
 * - `partitions`：`snapshot` 返回的每分区 size/preSha256；
 * - `preImages`/`baseImages`：从服务端导出的满长只读副本；
 * - `candidate`：producer 产出并已校验（满长 + 摘要）。
 *
 * 本函数不触碰分区，也不做任何写入；所有形态校验在 `InstallerMultiPartitionTransaction.prepare`
 * 里由 installer-core 再做一遍（主机可测 + 服务端复算 planSha）。
 */
object ModeSwitchPlanBuilder {

    data class CandidateImage(
        val partition: String,
        val file: java.io.File,
        val sha256: String,
    )

    /** 组装计划；失败抛 installer-core 的 [SwitchFailure]（错误码即契约码）。 */
    fun build(
        request: ModeSwitchRequest,
        startBootId: String,
        device: SwitchDeviceFacts,
        baseline: BaselineVerification?,
        partitions: List<SwitchPartitionStatus>,
        preImages: Map<String, ExportedImage>,
        baseImages: Map<String, ExportedImage>,
        candidate: CandidateImage,
        recoveredBaseShas: Map<String, String> = emptyMap(),
    ): SwitchPlan {
        if (baseline == null && request.baselineId.isNotEmpty()) {
            throw SwitchFailure(BaselineErrors.BASELINE_CORRUPT, "explicit baseline has no proof")
        }
        val byName = partitions.associateBy { it.name }
        val toInstaller = InstallerWorkMode.valueOf(request.toMode.name)
        val order = request.plannedPartitions(byName.keys)
        if (candidate.partition != request.resolvedTarget || request.resolvedTarget !in byName) {
            throw SwitchFailure(ModeSwitchCodes.PLAN_INVALID, "candidate partition")
        }
        val steps = mutableListOf<SwitchStep>()
        for (name in order) {
            val status = byName[name] ?: continue
            val pre = preImages[name]?.takeIf { it.size == status.size }
                ?: throw SwitchFailure(ModeSwitchCodes.PRE_IMAGE_INVALID, "missing pre $name")
            if (!pre.sha256.equals(status.preSha256, ignoreCase = true)) {
                throw SwitchFailure(ModeSwitchCodes.PRE_IMAGE_CHANGED, "$name pre")
            }
            val preSha = status.preSha256
            val candidatePartition = name == request.resolvedTarget
            if (candidatePartition) {
                if (candidate.partition != name) {
                    throw SwitchFailure(ModeSwitchCodes.PLAN_INVALID, "candidate partition")
                }
                if (candidate.file.length() != status.size) {
                    throw SwitchFailure(ModeSwitchCodes.PRODUCE_OUTPUT_SIZE_INVALID, name)
                }
                val imageSha = candidate.sha256
                if (imageSha.equals(preSha, ignoreCase = true)) continue // no-op 步不进计划
                steps += SwitchStep(
                    name,
                    StepRole.WRITE_CANDIDATE,
                    status.size,
                    candidate.file.toPath(),
                    imageSha,
                    pre.file.toPath(),
                    preSha,
                    ModeSwitchHashes.tailSha256(candidate.file),
                )
            } else {
                val base = baseImages[name]?.takeIf { it.size == status.size }
                    ?: throw SwitchFailure(BaselineErrors.BASELINE_CORRUPT, "missing base $name")
                val baselineSha = (if (baseline == null && request.baselineId.isEmpty())
                    recoveredBaseShas[name]?.takeIf(ModeSwitchHashes::isHash) else baselineSha(baseline, name))
                    ?: throw SwitchFailure(BaselineErrors.BASELINE_CORRUPT, "no baseline $name")
                if (!base.sha256.equals(baselineSha, ignoreCase = true)) {
                    throw SwitchFailure(BaselineErrors.BASELINE_CORRUPT, "$name base sha")
                }
                if (baselineSha.equals(preSha, ignoreCase = true)) continue // No source write is needed.
                steps += SwitchStep(
                    name,
                    StepRole.RESTORE_BASELINE,
                    status.size,
                    base.file.toPath(),
                    baselineSha,
                    pre.file.toPath(),
                    preSha,
                    ModeSwitchHashes.tailSha256(base.file),
                )
            }
        }
        if (steps.isEmpty()) throw SwitchFailure("SWITCH_STEP_NO_OP", "plan has no effective step")
        val deviceFields = linkedMapOf(
            SwitchPlan.DEVICE_SLOT to device.slot,
            SwitchPlan.DEVICE_FIRMWARE to device.firmware,
            SwitchPlan.DEVICE_KERNEL to device.kernelRelease,
            SwitchPlan.DEVICE_SELINUX to device.selinux,
        )
        val planRequest = SwitchPlan.Request(
            SwitchPlan.SCHEMA,
            request.switchId,
            InstallerWorkMode.valueOf(request.fromMode.name),
            toInstaller,
            request.baselineId,
            startBootId,
            deviceFields,
            steps,
        )
        return SwitchPlan.create(planRequest)
    }

    fun baselineSha(baseline: BaselineVerification?, partition: String): String? {
        val check = baseline?.check ?: return null
        return when (partition) {
            "boot" -> check.bootSha256.ifBlank { null }
            "init_boot" -> check.initBootSha256.ifBlank { null }
            else -> null
        }
    }

    fun installerMode(mode: WorkMode): InstallerWorkMode = InstallerWorkMode.valueOf(mode.name)

    fun deviceFields(device: SwitchDeviceFacts): Map<String, String> = linkedMapOf(
        SwitchPlan.DEVICE_SLOT to device.slot,
        SwitchPlan.DEVICE_FIRMWARE to device.firmware,
        SwitchPlan.DEVICE_KERNEL to device.kernelRelease,
        SwitchPlan.DEVICE_SELINUX to device.selinux,
    )
}
