package dev.maplesu.manager.workmode.switch

import dev.maplesu.manager.workmode.WorkMode

/**
 * 恢复 UI / 可观测性所需的数据投影（02 §7.1 / §7.4 / §7.5）。
 *
 * UI 只消费本文件的纯数据；本文件不缓存推断，所有值都来自 `switch.json` 与只读观测。
 */
data class ModeSwitchPartitionRow(
    val name: String,
    val size: Long,
    val preSha256: String,
    val targetSha256: String,
    val observedSha256: String,
    val state: String,
)

/** 外部恢复指引（`RECOVERY_REQUIRED` 时唯一给用户的内容）。 */
data class ExternalRecoveryGuide(
    val switchId: String,
    val stage: String,
    val step: String,
    val code: String,
    val detail: String,
    val partitions: List<ModeSwitchPartitionRow>,
    /** 恢复顺序 = 写序逆序（先目标后源），由 switch.json 的 partitions 顺序反推。 */
    val recoveryOrder: List<String>,
    /** `路径 sha256`，含 pre/base 镜像（由 artifacts 提供）。 */
    val images: List<String>,
    val device: Map<String, String>,
    /** 可直接复制的 `dd`/`fastboot` 说明。 */
    val instructions: String,
    /** 恒 false：产品在该状态下不自动重启/不自动重试。 */
    val autoRetry: Boolean = false,
)

/** 恢复页数据（02 §7.1）。 */
data class ModeSwitchRecoveryUiState(
    val switchId: String,
    val fromMode: WorkMode?,
    val toMode: WorkMode?,
    val state: String,
    val stage: String,
    val step: String,
    val code: String,
    val detail: String,
    val pending: Boolean,
    val canRollback: Boolean,
    val canResumeReboot: Boolean,
    val canExport: Boolean,
    val requiresExternalRecovery: Boolean,
    val verifyFailures: Int,
    val partitions: List<ModeSwitchPartitionRow>,
    val externalRecovery: ExternalRecoveryGuide?,
)

/** 服务端 status 投影（供 AIDL `getModeSwitch` 与恢复页共用）。 */
data class ModeSwitchStatus(
    val switchId: String,
    val state: String,
    val stage: String,
    val step: String,
    val fromMode: WorkMode?,
    val toMode: WorkMode?,
    val code: String,
    val detail: String,
    val pending: Boolean,
    val rebootRequired: Boolean,
    val bootObserved: Boolean,
    val operationActive: Boolean = false,
    val canRollback: Boolean,
    val canResumeReboot: Boolean,
    val canExport: Boolean,
    val requiresExternalRecovery: Boolean,
    val verifyFailures: Int,
    val partitions: List<ModeSwitchPartitionRow>,
    val externalRecovery: ExternalRecoveryGuide?,
)

object ModeSwitchStatusProjector {

    /** 允许回滚的状态（02 §3.2：COMMIT/REBOOT_REQUIRED/VERIFYING/RECOVERY_REQUIRED）。 */
    val ROLLBACK_ALLOWED = setOf(
        SwitchStateNames.COMMIT, SwitchStateNames.REBOOT_REQUIRED,
        SwitchStateNames.VERIFYING, SwitchStateNames.RECOVERY_REQUIRED,
        SwitchStateNames.ROLLING_BACK,
    )

    fun project(record: SwitchRecord?, bootIdChanged: Boolean = false): ModeSwitchStatus? {
        record ?: return null
        val from = WorkMode.fromWire(record.fromMode)
        val to = WorkMode.fromWire(record.toMode)
        val rows = record.partitions.map { partition ->
            ModeSwitchPartitionRow(
                name = partition.name,
                size = partition.size,
                preSha256 = partition.preSha256,
                targetSha256 = partition.targetSha256,
                observedSha256 = partition.observedSha256,
                state = partition.state,
            )
        }
        val requiresRecovery = record.state == SwitchStateNames.RECOVERY_REQUIRED ||
            record.error.code == ModeSwitchCodes.WRITE_ROLLBACK_FAILED
        val rebootObserved = bootIdChanged && record.startBootId.isNotEmpty()
        val canRollback = record.state in ROLLBACK_ALLOWED
        val canResumeReboot = record.state == SwitchStateNames.REBOOT_REQUIRED && !rebootObserved
        return ModeSwitchStatus(
            switchId = record.switchId,
            state = record.state,
            stage = record.stage,
            step = record.step,
            fromMode = from,
            toMode = to,
            code = record.error.code,
            detail = record.error.detail,
            pending = record.pending,
            rebootRequired = record.state == SwitchStateNames.REBOOT_REQUIRED,
            bootObserved = rebootObserved,
            canRollback = canRollback,
            canResumeReboot = canResumeReboot,
            canExport = true,
            requiresExternalRecovery = requiresRecovery,
            verifyFailures = record.attempts.bootVerifyFailures,
            partitions = rows,
            externalRecovery = if (requiresRecovery) externalGuide(record) else null,
        )
    }

    /** 02 §7.4：外部恢复指引必须自包含、可复制、不含凭据。 */
    fun externalGuide(record: SwitchRecord): ExternalRecoveryGuide {
        val rows = record.partitions.map { partition ->
            ModeSwitchPartitionRow(
                partition.name, partition.size, partition.preSha256, partition.targetSha256,
                partition.observedSha256, partition.state,
            )
        }
        val order = record.partitions.map { it.name }.reversed()
        val images = buildList {
            record.artifacts.forEach { (key, value) -> if (value.isNotBlank()) add("$key=$value") }
        }
        val instructions = buildString {
            appendLine("switchId=${record.switchId}")
            appendLine("stage=${record.stage} step=${record.step} code=${record.error.code}")
            appendLine("from=${record.fromMode} to=${record.toMode} baseline=${record.baselineId}")
            rows.forEach { row ->
                appendLine(
                    "partition ${row.name} size=${row.size} pre=${row.preSha256} " +
                        "target=${row.targetSha256} observed=${row.observedSha256}",
                )
            }
            appendLine("device slot=${record.device.slotSuffix} firmware=${record.device.firmware} " +
                "kernel=${record.device.kernelRelease} kmi=${record.device.kmi}")
            appendLine("recovery order (reverse write order): ${order.joinToString(" -> ")}")
            appendLine("dd: dd if=<image> of=/dev/block/by-name/<partition><slot> bs=1M")
            appendLine("fastboot: fastboot flash <partition> <image>")
            appendLine("本产品在该状态下不自动重启、不自动重试；请按上述镜像与摘要人工恢复。")
        }
        return ExternalRecoveryGuide(
            switchId = record.switchId,
            stage = record.stage,
            step = record.step,
            code = record.error.code,
            detail = record.error.detail,
            partitions = rows,
            recoveryOrder = order,
            images = images,
            device = mapOf(
                "slotSuffix" to record.device.slotSuffix,
                "firmware" to record.device.firmware,
                "kernelRelease" to record.device.kernelRelease,
                "kmi" to record.device.kmi,
            ),
            instructions = instructions,
        )
    }

    /** 02 §7.1 恢复页投影；无记录时返回 null（UI 显示空态）。 */
    fun recoveryUiState(record: SwitchRecord?, bootIdChanged: Boolean = false): ModeSwitchRecoveryUiState? {
        val status = project(record, bootIdChanged) ?: return null
        return ModeSwitchRecoveryUiState(
            switchId = status.switchId,
            fromMode = status.fromMode,
            toMode = status.toMode,
            state = status.state,
            stage = status.stage,
            step = status.step,
            code = status.code,
            detail = status.detail,
            pending = status.pending,
            canRollback = status.canRollback,
            canResumeReboot = status.canResumeReboot,
            canExport = status.canExport,
            requiresExternalRecovery = status.requiresExternalRecovery,
            verifyFailures = status.verifyFailures,
            partitions = status.partitions,
            externalRecovery = status.externalRecovery,
        )
    }
}
