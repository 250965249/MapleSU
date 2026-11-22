package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.workmode.snapshot.SnapshotReason
import dev.maplesu.manager.workmode.snapshot.SnapshotRequest
import dev.maplesu.manager.workmode.snapshot.SnapshotResult
import dev.maplesu.manager.workmode.snapshot.SnapshotService
import dev.maplesu.manager.workmode.switch.GatewayOutcome
import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import dev.maplesu.manager.workmode.switch.ModeSwitchRequest
import dev.maplesu.manager.workmode.switch.ModeSwitchSnapshots

/**
 * `SnapshotService`（W02）→ [ModeSwitchSnapshots] 的适配器。
 *
 * PRE_SWITCH 快照缺根/非活动模式（`Skipped`）在切换语义下**不是**成功：S4 的回滚依赖
 * App 侧快照，因此按失败处理（fail closed）。
 */
class SnapshotServiceModeSwitchSnapshots(
    private val snapshots: SnapshotService,
) : ModeSwitchSnapshots {

    override suspend fun preSwitchSnapshot(request: ModeSwitchRequest): GatewayOutcome =
        when (val result = snapshots.create(
            SnapshotRequest(
                mode = request.fromMode,
                switchId = request.switchId,
                reason = SnapshotReason.PRE_SWITCH,
                includeSecrets = false,
            ),
        )) {
            is SnapshotResult.Ok -> GatewayOutcome(true, "")
            is SnapshotResult.Skipped -> GatewayOutcome(
                false, "", ModeSwitchCodes.SNAPSHOT_FAILED, "SNAPSHOT_SKIPPED:${result.reason}",
            )
            is SnapshotResult.Failed -> GatewayOutcome(
                false, "", result.code.ifEmpty { ModeSwitchCodes.SNAPSHOT_FAILED }, result.detail,
            )
        }

    override suspend fun restoreAfterRollback(request: ModeSwitchRequest): GatewayOutcome =
        GatewayOutcome(true, "", detail = "SNAPSHOT_RESTORE_DEFERRED")
}

/** 未接线快照：S1 前硬失败（不写分区）。 */
object UnavailableModeSwitchSnapshots : ModeSwitchSnapshots {
    override suspend fun preSwitchSnapshot(request: ModeSwitchRequest): GatewayOutcome =
        GatewayOutcome(false, "", ModeSwitchCodes.SNAPSHOT_FAILED, "snapshot service not wired")

    override suspend fun restoreAfterRollback(request: ModeSwitchRequest): GatewayOutcome =
        GatewayOutcome(false, "", ModeSwitchCodes.SNAPSHOT_FAILED, "snapshot service not wired")
}
