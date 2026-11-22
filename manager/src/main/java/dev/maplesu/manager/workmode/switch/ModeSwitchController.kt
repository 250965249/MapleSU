package dev.maplesu.manager.workmode.switch

import dev.maplesu.installer.SwitchFailure
import dev.maplesu.installer.SwitchPlan
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.control.ControlPaths
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.ProcBootIdSource
import dev.maplesu.manager.workmode.detect.WallClock
import dev.maplesu.manager.workmode.detect.activeMode
import java.io.File

/** journal 按 switchId 打开（路径 `boot/work/<switchId>/journal.jsonl`，02 §3.3）。 */
fun interface SwitchJournalFactory {
    fun open(switchId: String): SwitchJournal
}

/** S0→S4g 的编排结果（S5/S6 由调用方继续驱动）。 */
sealed interface ModeSwitchRun {
    /** 分区已全写（4g），等待设备重启。 */
    data class AwaitingReboot(val status: ModeSwitchStatus?, val planSha256: String) : ModeSwitchRun

    /** S6 全过。 */
    data class Verified(val status: ModeSwitchStatus?) : ModeSwitchRun

    /** 未到终态/需要用户动作（重试、重启、恢复页）。 */
    data class Incomplete(val state: String, val code: String, val detail: String, val status: ModeSwitchStatus?) :
        ModeSwitchRun

    /**
     * 失败终态或恢复态。`state` ∈ {FAILED_PRE_WRITE, ROLLED_BACK, RECOVERY_REQUIRED, VERIFYING}；
     * 只有 RECOVERY_REQUIRED 需要外部恢复。
     */
    data class Failed(
        val state: String,
        val code: String,
        val detail: String,
        val stage: String,
        val step: String,
        val status: ModeSwitchStatus?,
    ) : ModeSwitchRun
}

/** 启动/手动恢复入口的结果。 */
sealed interface RecoveryRun {
    data object NothingToDo : RecoveryRun

    /** 继续向前（可能已进入 verify）。 */
    data class Resumed(val run: ModeSwitchRun) : RecoveryRun

    data class RolledBack(val status: ModeSwitchStatus?) : RecoveryRun

    data class RequiresRecovery(val code: String, val detail: String, val status: ModeSwitchStatus?) : RecoveryRun
}

/**
 * W08 切换编排控制器（S0–S6；02 §3/§5/§6）。
 *
 * 职责边界：
 * - **只做编排与持久化**：分区字节永远由 `installer` 侧的 `InstallerMultiPartitionTransaction` /
 *   `BlockDeviceTransaction` 写；本类经 [InstallerGateway] 调用，不持有任何写原语（红线 4）。
 * - 所有外部副作用（root、分区、快照、producer、W19 钩子、时钟、bootId）都经端口注入，
 *   因此主机单测可用 Fake 完整复现失败/掉电语义（`ModeSwitchControllerTest`）。
 * - 失败分类固定：S1–S3 失败 = [SwitchStateNames.FAILED_PRE_WRITE]（分区未动）；
 *   S4 失败 = 逆序回滚 → ROLLED_BACK / RECOVERY_REQUIRED；S6 失败 = 回滚或 RECOVERY_REQUIRED。
 *
 * 已知接线缺口（见交付报告/§12）：真正的 S1/S2/S4 动作在 root 服务内；本类的
 * [InstallerGateway] 真实实现把请求转成 AIDL（`workmode/service/ServiceClientInstallerGateway.kt`）。
 * 在服务端 W08b 接线完成前，真实调用会得到 `SWITCH_SERVICE_NOT_READY` 并走失败路径——不会写分区。
 */
class ModeSwitchController(
    private val gateway: InstallerGateway,
    private val journalFactory: SwitchJournalFactory,
    private val authority: SwitchAuthority,
    private val baselines: BaselineStore,
    private val snapshots: ModeSwitchSnapshots,
    private val producer: SwitchCandidateProducer,
    private val hooks: SwitchQuiesceHooks,
    /** S4 配置交换（4b/4e/4f）；null = 仅分区（兼容旧测试）。生产装配必须传入。 */
    private val moveStage: SwitchMoveStage? = null,
    private val environment: SwitchEnvironment,
    private val consumer: ModeConsumerVerifier = ModeConsumerVerifier { _, _ -> HookResult.OK },
    private val superuser: SuperuserReconciler = SuperuserReconciler { HookResult.OK },
    private val modeCommit: ModeCommitSink = ModeCommitSink { _, _, _, _ -> },
    private val clock: Clock = WallClock,
    private val bootIds: BootIdSource = ProcBootIdSource,
    private val workRoot: File = File(ControlPaths.WORK),
) {

    // ------------------------------------------------------------------ 公共入口

    /** S0：只读预检（本地 S0a + root 服务 S0b 合并）。 */
    fun preflight(request: ModeSwitchRequest): S0Report = preflightResolved(request.resolve(
        environment.partitionInventory().present, environment.deviceFacts().kernelRelease))

    private fun preflightResolved(request: ModeSwitchRequest): S0Report {
        val modeState = environment.modeState()
        val current = environment.currentMode() ?: modeState?.activeMode
        val baseline = baselines.verify(request.baselineId)
        val inventory = environment.partitionInventory()
        val planned = plannedPartitions(request, baseline, inventory)
        val pending = adjustedPending(request)
        val inputs = S0Inputs(
            switchId = request.switchId,
            fromMode = request.fromMode,
            toMode = request.toMode,
            currentMode = current,
            modeState = modeState,
            planned = planned,
            baseline = baseline,
            device = environment.deviceFacts(),
            battery = environment.battery(),
            pending = pending,
            rootRefusal = environment.rootRefusal(),
            controlWritable = environment.controlWritable(),
            implantRestoreReady = environment.implantRestoreReady(),
            exportReceipt = environment.exportReceipt(),
            inventory = inventory,
            avb = environment.avb(),
            freeBytes = environment.freeBytes(),
        )
        val local = ModeSwitchPreflight.evaluate(inputs)
        val service = runCatching { gateway.preflight(request) }.getOrElse { error ->
            GatewayPreflight(false, ModeSwitchCodes.ROOT_UNAVAILABLE, error.message.orEmpty())
        }
        val merged = local.merge(service.checks)
        return if (!service.ok && service.checks.isEmpty()) {
            merged.copy(checks = merged.checks + S0Check("S0b", false, service.code, service.detail))
        } else {
            merged
        }
    }

    /** S0→S4g：开始/继续一次切换（同 switchId 幂等续跑）。 */
    suspend fun begin(request: ModeSwitchRequest): ModeSwitchRun {
        return guardedRun(request) {
            val existing = authority.read()
            val record = when (existing) {
                is AuthorityRead.Corrupt -> return@guardedRun failWithoutRecord(
                    ModeSwitchCodes.RECOVERY_REQUIRED, existing.detail, "S0", "S0-07",
                )
                is AuthorityRead.Missing -> null
                is AuthorityRead.Ok -> existing.record
            }
            if (record != null && record.switchId != request.switchId) {
                return@guardedRun ModeSwitchRun.Failed(
                    SwitchStateNames.FAILED_PRE_WRITE, ModeSwitchCodes.PENDING,
                    "another switch pending: ${record.switchId}", "S0", "S0-07",
                    ModeSwitchStatusProjector.project(record),
                )
            }
            if (record != null && (record.fromMode != request.fromMode.name || record.toMode != request.toMode.name)) {
                return@guardedRun ModeSwitchRun.Failed(
                    SwitchStateNames.FAILED_PRE_WRITE, ModeSwitchCodes.PLAN_CONFLICT,
                    "pending switch mode mismatch", "S0", "S0-01",
                    ModeSwitchStatusProjector.project(record),
                )
            }
            if (record != null && record.state !in setOf(
                    SwitchStateNames.BEGIN, SwitchStateNames.SNAPSHOT, SwitchStateNames.PRODUCE,
                )
            ) {
                // 已过 S3 的切换不允许"重头开始"；只能续跑/回滚/验证（02 §3.5 幂等键）。
                return@guardedRun ModeSwitchRun.Incomplete(
                    record.state, ModeSwitchCodes.PENDING, "switch already advanced",
                    ModeSwitchStatusProjector.project(record),
                )
            }
            val resolved = if (record == null) {
                request.resolve(environment.partitionInventory().present, environment.deviceFacts().kernelRelease)
            } else requestOf(record) ?: return@guardedRun badRecord(record, "S0", "S0-01")
            if (request.targetPartition != null && request.targetPartition != resolved.resolvedTarget ||
                request.sourcePartition != null && request.sourcePartition != resolved.sourcePartition) {
                return@guardedRun ModeSwitchRun.Failed(
                    SwitchStateNames.FAILED_PRE_WRITE, ModeSwitchCodes.PLAN_CONFLICT,
                    "pending switch partition mismatch", "S0", "S0-01",
                    record?.let { ModeSwitchStatusProjector.project(it) },
                )
            }
            val report = preflightResolved(resolved)
            if (!report.ok) {
                val failure = report.failure()!!
                return@guardedRun ModeSwitchRun.Failed(
                    SwitchStateNames.FAILED_PRE_WRITE, failure.code,
                    "${failure.id}: ${failure.detail}", "S0", failure.id, null,
                )
            }
            execute(resolved, record)
        }
    }

    /** S5：固定重启（先落 REBOOT_REQUESTED，再 `svc power reboot`）。 */
    suspend fun requestReboot(switchId: String): ModeSwitchRun {
        val record = (authority.read(switchId)) ?: return failWithoutRecord(
            ModeSwitchCodes.PLAN_INVALID, "no switch record", "S5", SwitchSteps.REBOOT,
        )
        if (record.state != SwitchStateNames.REBOOT_REQUIRED) {
            return ModeSwitchRun.Incomplete(record.state, ModeSwitchCodes.REBOOT_NOT_OBSERVED,
                "not waiting for reboot", ModeSwitchStatusProjector.project(record))
        }
        val journal = runCatching { journalFactory.open(switchId) }.getOrElse { return journalFailure(record, it) }
        val request = requestOf(record) ?: return badRecord(record, "S5", SwitchSteps.REBOOT)
        val now = clock.nowMillis()
        val rebooted = record.copy(
            rebootRequestedAtUptimeMs = now,
            attempts = record.attempts.copy(rebootRequests = record.attempts.rebootRequests + 1),
            updatedAtUptimeMs = now,
        )
        authority.write(rebooted)
        runCatching { append(journal, rebooted, "S5", SwitchSteps.REBOOT, SwitchOp.REBOOT_PENDING) }
        val accepted = runCatching { gateway.reboot(request) }.getOrDefault(false)
        if (!accepted) {
            val failed = rebooted.withError(ModeSwitchCodes.REBOOT_NOT_OBSERVED, "S5", SwitchSteps.REBOOT,
                "reboot command failed", clock.nowMillis())
            authority.write(failed)
            append(journal, failed, "S5", SwitchSteps.REBOOT, SwitchOp.FAIL, code = ModeSwitchCodes.REBOOT_NOT_OBSERVED)
            return ModeSwitchRun.Incomplete(SwitchStateNames.REBOOT_REQUIRED,
                ModeSwitchCodes.REBOOT_NOT_OBSERVED, "reboot command failed",
                ModeSwitchStatusProjector.project(failed))
        }
        val bootChanged = bootIds.read().isNotEmpty() && bootIds.read() != rebooted.startBootId
        val status = ModeSwitchStatusProjector.project(rebooted, bootChanged)
        return if (bootChanged) ModeSwitchRun.AwaitingReboot(status, rebooted.planSha256)
        else ModeSwitchRun.Incomplete(SwitchStateNames.REBOOT_REQUIRED,
            ModeSwitchCodes.REBOOT_NOT_OBSERVED, "boot id unchanged after reboot request", status)
    }

    /** S6：重启后验证与收敛（6.1–6.4）。 */
    suspend fun verifyAfterBoot(switchId: String): ModeSwitchRun {
        val record = authority.read(switchId) ?: return failWithoutRecord(
            ModeSwitchCodes.PLAN_INVALID, "no switch record", "S6", SwitchSteps.VERIFY_PARTITIONS,
        )
        if (record.state == SwitchStateNames.VERIFIED) {
            return ModeSwitchRun.Verified(ModeSwitchStatusProjector.project(record))
        }
        if (record.state in setOf(SwitchStateNames.ROLLED_BACK, SwitchStateNames.CANCELLED, SwitchStateNames.FAILED_PRE_WRITE)) {
            return ModeSwitchRun.Failed(record.state, record.error.code, record.error.detail,
                record.stage, record.step, ModeSwitchStatusProjector.project(record))
        }
        val journal = runCatching { journalFactory.open(switchId) }.getOrElse { return journalFailure(record, it) }
        val request = requestOf(record) ?: return badRecord(record, "S6", SwitchSteps.VERIFY_PARTITIONS)
        val currentBoot = bootIds.read()
        val bootChanged = currentBoot.isNotEmpty() && currentBoot != record.startBootId
        if (!bootChanged) {
            return ModeSwitchRun.Incomplete(record.state, ModeSwitchCodes.VERIFY_BOOT_NOT_OBSERVED,
                "boot id not changed", ModeSwitchStatusProjector.project(record, false))
        }
        var updating = record.transition(SwitchStateNames.VERIFYING, "S6", SwitchSteps.VERIFY_PARTITIONS,
            clock.nowMillis()).copy(currentBootId = currentBoot, rebootObservedBootId = currentBoot)
        authority.write(updating)
        append(journal, updating, "S6", SwitchSteps.VERIFY_PARTITIONS, SwitchOp.INTENT)

        val server = runCatching { gateway.verify(request) }.getOrElse { error ->
            GatewayOutcome(false, "", ModeSwitchCodes.WRITE_IO_FAILED, error.message.orEmpty())
        }
        if (!server.ok) {
            val code = server.code.ifEmpty { ModeSwitchCodes.VERIFY_PARTITION_MISMATCH }
            append(journal, updating, "S6", SwitchSteps.VERIFY_PARTITIONS, SwitchOp.FAIL, code = code)
            return verifyFailure(updating, request, code, server.detail, journal, server.status)
        }
        append(journal, updating, "S6", SwitchSteps.VERIFY_PARTITIONS, SwitchOp.DONE)

        // 6.3 mode consumer（App 进程；失败可重试，连续 2 次强制 RECOVERY_REQUIRED）。
        val consumerResult = runCatching { consumer.verify(request.toMode, currentBoot) }
            .getOrElse { HookResult.failed(ModeSwitchCodes.VERIFY_CONSUMER_FAILED, it.message.orEmpty()) }
        if (!consumerResult.ok) {
            val failures = updating.attempts.bootVerifyFailures + 1
            updating = updating.copy(attempts = updating.attempts.copy(bootVerifyFailures = failures))
                .withError(ModeSwitchCodes.VERIFY_CONSUMER_FAILED, "S6", SwitchSteps.VERIFY_CONSUMER,
                    consumerResult.detail, clock.nowMillis())
            append(journal, updating, "S6", SwitchSteps.VERIFY_CONSUMER, SwitchOp.FAIL,
                code = ModeSwitchCodes.VERIFY_CONSUMER_FAILED)
            if (failures >= 2) {
                return markRecoveryRequired(updating, request, ModeSwitchCodes.VERIFY_CONSUMER_FAILED,
                    consumerResult.detail, journal)
            }
            authority.write(updating)
            return ModeSwitchRun.Incomplete(SwitchStateNames.VERIFYING,
                ModeSwitchCodes.VERIFY_CONSUMER_FAILED, consumerResult.detail,
                ModeSwitchStatusProjector.project(updating, true))
        }

        // 6.4 授权 reconcile：失败不阻断 VERIFIED，但必须落 pending 并告警（红线 8）。
        val syncResult = runCatching { superuser.reconcileAfterBoot(request.toMode) }
            .getOrElse { HookResult.failed(ModeSwitchCodes.VERIFY_SUPERUSER_FAILED, it.message.orEmpty()) }
        val syncCode = if (syncResult.ok) "" else ModeSwitchCodes.VERIFY_SUPERUSER_FAILED
        append(journal, updating, "S6", SwitchSteps.VERIFY_SUPERUSER,
            if (syncResult.ok) SwitchOp.DONE else SwitchOp.FAIL, code = syncCode)

        // modes.json.current=to（成功后唯一提交点）。
        val bootSha = updating.partitions.firstOrNull { it.name == "boot" }?.targetSha256.orEmpty()
        val initBootSha = updating.partitions.firstOrNull { it.name == "init_boot" }?.targetSha256.orEmpty()
        runCatching { modeCommit.commit(request.toMode, currentBoot, bootSha, initBootSha) }.onFailure { error ->
            return ModeSwitchRun.Incomplete(SwitchStateNames.VERIFYING, "CONTROL_WRITE_FAILED",
                error.message.orEmpty(), ModeSwitchStatusProjector.project(updating, true))
        }

        val verified = updating.copy(
            state = SwitchStateNames.VERIFIED,
            stage = "S6",
            step = SwitchSteps.VERIFY_SUPERUSER,
            updatedAtUptimeMs = clock.nowMillis(),
            error = if (syncCode.isEmpty()) SwitchRecordError()
            else SwitchRecordError(syncCode, "S6", SwitchSteps.VERIFY_SUPERUSER, syncResult.detail, clock.nowMillis()),
        )
        authority.write(verified)
        append(journal, verified, "S6", SwitchSteps.VERIFY_PARTITIONS, SwitchOp.VERIFIED)
        return ModeSwitchRun.Verified(ModeSwitchStatusProjector.project(verified, true))
    }

    /** 启动/手动恢复：journal 重放 + 分区读回 → RESUME / ROLLBACK / RECOVERY_REQUIRED。 */
    suspend fun recover(switchId: String? = null): RecoveryRun {
        val record = when (val read = authority.read()) {
            is AuthorityRead.Missing -> return RecoveryRun.NothingToDo
            is AuthorityRead.Corrupt -> return RecoveryRun.RequiresRecovery(
                ModeSwitchCodes.RECOVERY_REQUIRED, "${read.code}: ${read.detail}", null,
            )
            is AuthorityRead.Ok -> read.record
        }
        if (switchId != null && record.switchId != switchId) return RecoveryRun.NothingToDo
        if (!record.pending) {
            // 终态（含 VERIFIED）= 恢复判定 NOTHING_TO_DO（02 §6.2）；不得把终态报告成"续跑"。
            return RecoveryRun.NothingToDo
        }
        val request = requestOf(record) ?: return RecoveryRun.RequiresRecovery(
            ModeSwitchCodes.RECOVERY_REQUIRED, "record mode unknown", ModeSwitchStatusProjector.project(record),
        )
        val journal = runCatching { journalFactory.open(record.switchId) }.getOrNull()
        val journalCorrupt = when (val replay = journal?.replay(record.switchId)) {
            is JournalReplay.Degraded -> true
            else -> false
        }
        val live = runCatching {
            gateway.observePartitions(request, record.partitions.map { it.name })
        }.getOrElse { emptyList() }
        val observation = ModeSwitchReconciler.observe(
            record = record,
            liveSha = live.associate { it.name to it.sha256 },
            bootIdChanged = bootIds.read().isNotEmpty() && bootIds.read() != record.startBootId,
            journalCorrupt = journalCorrupt,
        )
        return when (val decision = ModeSwitchReconciler.decide(observation)) {
            RecoveryDecision.NOTHING_TO_DO -> RecoveryRun.NothingToDo
            RecoveryDecision.RECOVERY_REQUIRED -> {
                val marked = if (journal != null) {
                    markRecoveryRequired(record, request, ModeSwitchCodes.RECOVERY_REQUIRED,
                        "recovery decision", journal)
                } else {
                    val copy = record.withError(ModeSwitchCodes.RECOVERY_REQUIRED, record.stage,
                        record.step, "recovery decision", clock.nowMillis())
                        .transition(SwitchStateNames.RECOVERY_REQUIRED, record.stage, record.step, clock.nowMillis())
                    authority.write(copy)
                    ModeSwitchRun.Failed(SwitchStateNames.RECOVERY_REQUIRED,
                        ModeSwitchCodes.RECOVERY_REQUIRED, "recovery decision", record.stage,
                        record.step, ModeSwitchStatusProjector.project(copy))
                }
                RecoveryRun.RequiresRecovery(ModeSwitchCodes.RECOVERY_REQUIRED,
                    "recovery decision", marked.status)
            }
            RecoveryDecision.ROLLBACK -> RecoveryRun.RolledBack(
                (rollback(record.switchId) as? ModeSwitchRun.Failed)?.status,
            )
            RecoveryDecision.RESUME_FORWARD -> RecoveryRun.Resumed(resumeForward(request, record, observation))
        }
    }

    /** 用户显式回滚（02 §3.2：COMMIT/REBOOT_REQUIRED/VERIFYING/RECOVERY_REQUIRED 允许）。 */
    suspend fun rollback(switchId: String): ModeSwitchRun {
        val record = authority.read(switchId) ?: return failWithoutRecord(
            ModeSwitchCodes.PLAN_INVALID, "no switch record", "S4", SwitchSteps.COMMIT_PENDING,
        )
        if (record.state !in ModeSwitchStatusProjector.ROLLBACK_ALLOWED) {
            return ModeSwitchRun.Failed(record.state, ModeSwitchCodes.PLAN_INVALID,
                "rollback not allowed in ${record.state}", record.stage, record.step,
                ModeSwitchStatusProjector.project(record))
        }
        val request = requestOf(record) ?: return badRecord(record, record.stage, record.step)
        val journal = runCatching { journalFactory.open(switchId) }.getOrElse { return journalFailure(record, it) }
        val rolling = record.transition(SwitchStateNames.ROLLING_BACK, "RB", record.step, clock.nowMillis())
        authority.write(rolling)
        append(journal, rolling, "RB", record.step, SwitchOp.ROLLBACK_INTENT)
        hooks.restoreAfterFailure(request.fromMode)
        val outcome = runCatching { gateway.rollback(request) }.getOrElse { error ->
            GatewayOutcome(false, GatewayState.RECOVERY_REQUIRED, ModeSwitchCodes.ROLLBACK_FAILED,
                error.message.orEmpty())
        }
        return when (outcome.state) {
            GatewayState.ROLLED_BACK -> {
                val rolled = rolling.transition(SwitchStateNames.ROLLED_BACK, "RB", record.step, clock.nowMillis())
                    .withError("", "", "", "", 0)
                authority.write(rolled)
                append(journal, rolled, "RB", record.step, SwitchOp.ROLLBACK_DONE)
                runCatching { snapshots.restoreAfterRollback(request) }
                ModeSwitchRun.Failed(SwitchStateNames.ROLLED_BACK, outcome.code, outcome.detail,
                    "RB", record.step, ModeSwitchStatusProjector.project(rolled))
            }
            else -> {
                val code = outcome.code.ifEmpty { ModeSwitchCodes.ROLLBACK_FAILED }
                val failed = rolling.transition(SwitchStateNames.RECOVERY_REQUIRED, "RB", record.step,
                    clock.nowMillis())
                    .withError(code, "RB", record.step, outcome.detail, clock.nowMillis())
                authority.write(failed)
                append(journal, failed, "RB", record.step, SwitchOp.RECOVERY_REQUIRED, code = code)
                ModeSwitchRun.Failed(SwitchStateNames.RECOVERY_REQUIRED, code, outcome.detail,
                    "RB", record.step, ModeSwitchStatusProjector.project(failed))
            }
        }
    }

    /** 预写阶段中止（仅 BEGIN/SNAPSHOT/PRODUCE；02 §3.2）。 */
    suspend fun abort(switchId: String): ModeSwitchRun {
        val record = authority.read(switchId) ?: return failWithoutRecord(
            ModeSwitchCodes.PLAN_INVALID, "no switch record", "S0", "",
        )
        if (record.state !in setOf(SwitchStateNames.BEGIN, SwitchStateNames.SNAPSHOT, SwitchStateNames.PRODUCE)) {
            return ModeSwitchRun.Failed(record.state, ModeSwitchCodes.PLAN_INVALID,
                "abort not allowed in ${record.state}", record.stage, record.step,
                ModeSwitchStatusProjector.project(record))
        }
        val request = requestOf(record) ?: return badRecord(record, record.stage, record.step)
        val journal = runCatching { journalFactory.open(switchId) }.getOrNull()
        runCatching { gateway.abort(request) }
        hooks.restoreAfterFailure(request.fromMode)
        val cancelled = record.transition(SwitchStateNames.CANCELLED, record.stage, record.step,
            clock.nowMillis()).withError(ModeSwitchCodes.ABORTED, record.stage, record.step, "", clock.nowMillis())
        authority.write(cancelled)
        journal?.let { append(it, cancelled, record.stage, record.step, SwitchOp.FAIL, code = ModeSwitchCodes.ABORTED) }
        return ModeSwitchRun.Failed(SwitchStateNames.CANCELLED, ModeSwitchCodes.ABORTED,
            "aborted by user", record.stage, record.step, ModeSwitchStatusProjector.project(cancelled))
    }

    fun status(switchId: String? = null): ModeSwitchStatus? {
        val record = authority.read(switchId) ?: return null
        val changed = bootIds.read().isNotEmpty() && bootIds.read() != record.startBootId
        return ModeSwitchStatusProjector.project(record, changed)
    }

    fun recoveryUiState(switchId: String? = null): ModeSwitchRecoveryUiState? {
        val record = authority.read(switchId) ?: return null
        val changed = bootIds.read().isNotEmpty() && bootIds.read() != record.startBootId
        return ModeSwitchStatusProjector.recoveryUiState(record, changed)
    }

    /** 诊断导出（`openSwitchLog`）；无记录时 null。 */
    fun exportDiagnostics(switchId: String, destination: File): File? {
        val record = authority.read(switchId) ?: return null
        val request = requestOf(record) ?: return null
        return runCatching { gateway.exportDiagnostics(request, destination) }.getOrNull()
    }

    // ------------------------------------------------------------------ S1–S4

    private suspend fun execute(request: ModeSwitchRequest, existing: SwitchRecord?): ModeSwitchRun {
        var record = existing ?: SwitchRecord(
            switchId = request.switchId,
            state = SwitchStateNames.BEGIN,
            stage = "S1",
            step = SwitchSteps.BEGIN,
            fromMode = request.fromMode.name,
            toMode = request.toMode.name,
            fromBuild = request.fromBuild,
            toBuild = request.toBuild,
            baselineId = request.baselineId,
            targetPartition = request.resolvedTarget,
            sourcePartition = request.sourcePartition,
            startBootId = bootIds.read(),
            currentBootId = bootIds.read(),
            createdAtUptimeMs = clock.nowMillis(),
            updatedAtUptimeMs = clock.nowMillis(),
            device = SwitchRecordDevice(
                slotSuffix = environment.deviceFacts().slot,
                firmware = environment.deviceFacts().firmware,
                kernelRelease = environment.deviceFacts().kernelRelease,
                kmi = ModeSwitchKmi.parse(environment.deviceFacts().kernelRelease).orEmpty(),
                selinux = environment.deviceFacts().selinux,
            ),
        )
        val journal = runCatching { journalFactory.open(request.switchId) }
            .getOrElse { return journalFailure(record, it) }
        val workDir = File(workRoot, request.switchId)
        if (!workDir.isDirectory && !workDir.mkdirs() && !workDir.isDirectory) {
            return failWithoutRecord(ModeSwitchCodes.CONTROL_DIR_INVALID, "work dir", "S1", SwitchSteps.BEGIN)
        }
        val resumeState = existing?.state
        var preImages = emptyMap<String, ExportedImage>()
        var baseImages = emptyMap<String, ExportedImage>()
        try {
            if (resumeState == null || resumeState == SwitchStateNames.BEGIN) {
                record = beginPhase(request, record, journal)
            }
            if (resumeState == null || resumeState in setOf(
                    SwitchStateNames.BEGIN, SwitchStateNames.SNAPSHOT, SwitchStateNames.PRODUCE,
                )
            ) {
                // 续跑时 snapshot 幂等重放：重新导出 pre/base 工作镜像，避免把上一进程的
                // 临时文件当作可信输入（02 §3.5 幂等键；服务端 snapshot 本身幂等）。
                val snapshot = snapshotPhase(request, record, journal, workDir)
                record = snapshot.record
                preImages = snapshot.preImages
                baseImages = snapshot.baseImages
            }
            val produced = producePhase(request, record, journal, workDir, preImages, baseImages)
            record = produced.record
            return commitPhase(request, produced.record, journal)
        } catch (failure: SwitchFailure) {
            return finalizeFailure(request, record, journal, failure.code, failure.detail)
        } catch (error: Throwable) {
            if (error is Error) throw error
            return finalizeFailure(request, record, journal, ModeSwitchCodes.WRITE_FAILED, error.message.orEmpty())
        }
    }

    private suspend fun beginPhase(
        request: ModeSwitchRequest,
        initial: SwitchRecord,
        journal: SwitchJournal,
    ): SwitchRecord {
        val inputs = environment.beginInputs()
        if (inputs.error.isNotEmpty()) throw SwitchFailure(ModeSwitchCodes.PREPARE_EXPORT_FAILED, inputs.error)
        if (inputs.superuserJson == null || !inputs.superuserJson.isFile) {
            throw SwitchFailure(ModeSwitchCodes.PREPARE_EXPORT_FAILED, "superuser mirror missing")
        }
        if (inputs.settingsMirrorJson == null || !inputs.settingsMirrorJson.isFile) {
            throw SwitchFailure(ModeSwitchCodes.PREPARE_EXPORT_FAILED, "settings mirror missing")
        }
        val started = initial.transition(SwitchStateNames.BEGIN, "S1", SwitchSteps.BEGIN, clock.nowMillis())
        authority.write(started)
        append(journal, started, "S1", SwitchSteps.BEGIN, SwitchOp.INTENT)
        val snapshot = snapshotsRun { snapshots.preSwitchSnapshot(request) }
        if (!snapshot.ok) {
            throw SwitchFailure(snapshot.code.ifEmpty { ModeSwitchCodes.SNAPSHOT_FAILED }, snapshot.detail)
        }
        val outcome = runCatching { gateway.begin(request, inputs) }.getOrElse { error ->
            GatewayOutcome(false, "", ModeSwitchCodes.ROOT_UNAVAILABLE, error.message.orEmpty())
        }
        if (!outcome.ok) {
            throw SwitchFailure(outcome.code.ifEmpty { ModeSwitchCodes.ROOT_UNAVAILABLE }, outcome.detail)
        }
        append(journal, started, "S1", SwitchSteps.BEGIN, SwitchOp.DONE)
        val next = started.transition(SwitchStateNames.SNAPSHOT, "S2", SwitchSteps.SNAPSHOT, clock.nowMillis())
        authority.write(next)
        return next
    }

    private suspend fun snapshotsRun(action: suspend () -> GatewayOutcome): GatewayOutcome =
        runCatching { action() }.getOrElse { error ->
            GatewayOutcome(false, "", ModeSwitchCodes.SNAPSHOT_FAILED, error.message.orEmpty())
        }

    private data class SnapshotPhaseResult(
        val record: SwitchRecord,
        val preImages: Map<String, ExportedImage>,
        val baseImages: Map<String, ExportedImage>,
    )

    private fun snapshotPhase(
        request: ModeSwitchRequest,
        record: SwitchRecord,
        journal: SwitchJournal,
        workDir: File,
    ): SnapshotPhaseResult {
        append(journal, record, "S2", SwitchSteps.SNAPSHOT, SwitchOp.INTENT)
        val outcome = runCatching { gateway.snapshot(request) }.getOrElse { error ->
            GatewayOutcome(false, "", ModeSwitchCodes.SNAPSHOT_FAILED, error.message.orEmpty())
        }
        if (!outcome.ok) throw SwitchFailure(outcome.code.ifEmpty { ModeSwitchCodes.SNAPSHOT_FAILED }, outcome.detail)
        val status = outcome.status ?: throw SwitchFailure(ModeSwitchCodes.SNAPSHOT_FAILED, "no status")
        if (status.partitions.isEmpty()) throw SwitchFailure(ModeSwitchCodes.SNAPSHOT_FAILED, "no partitions")
        val baseline = baselines.verify(request.baselineId)
        val pre = LinkedHashMap<String, ExportedImage>()
        val base = LinkedHashMap<String, ExportedImage>()
        val planned = request.plannedPartitions(status.partitions.map { it.name }.toSet())
        val missing = planned.filter { name -> status.partitions.none { it.name == name } }
        if (missing.isNotEmpty()) {
            throw SwitchFailure(ModeSwitchCodes.LAYOUT_UNSUPPORTED, missing.joinToString(","))
        }
        for (partition in status.partitions.filter { it.name in planned }) {
            val preFile = export(request, "PRE", partition.name, File(workDir, "pre-${partition.name}.img"))
            if (preFile.size != partition.size) {
                throw SwitchFailure(ModeSwitchCodes.PRE_IMAGE_INVALID, partition.name)
            }
            if (!preFile.sha256.equals(partition.preSha256, ignoreCase = true)) {
                throw SwitchFailure(ModeSwitchCodes.PRE_IMAGE_CHANGED, partition.name)
            }
            pre[partition.name] = preFile
            val expectedBase = ModeSwitchPlanBuilder.baselineSha(baseline, partition.name)
            if (expectedBase != null) {
                // baseline 副本缺失/读失败属于 baseline 不可用（不是"写前镜像"问题）。
                val baseFile = try {
                    export(request, "BASE", partition.name, File(workDir, "base-${partition.name}.img"))
                } catch (failure: SwitchFailure) {
                    throw SwitchFailure(BaselineErrors.BASELINE_CORRUPT, failure.detail)
                }
                if (baseFile.size != partition.size) {
                    throw SwitchFailure(BaselineErrors.BASELINE_CORRUPT, partition.name)
                }
                if (!baseFile.sha256.equals(expectedBase, ignoreCase = true)) {
                    throw SwitchFailure(BaselineErrors.BASELINE_CORRUPT, "${partition.name} sha")
                }
                base[partition.name] = baseFile
            }
        }
        val artifacts = record.artifacts.toMutableMap()
        pre.forEach { (name, image) -> artifacts["pre-$name"] = image.file.absolutePath }
        base.forEach { (name, image) -> artifacts["base-$name"] = image.file.absolutePath }
        val updated = record.copy(
            partitions = status.partitions.filter { it.name in planned }.map {
                SwitchRecordPartition(
                    name = it.name,
                    role = if (it.name == request.resolvedTarget) "WRITE_CANDIDATE" else "RESTORE_BASELINE",
                    size = it.size,
                    preSha256 = it.preSha256, targetSha256 = it.targetSha256,
                    tailSha256 = it.tailSha256, state = it.state.ifEmpty { "PENDING" },
                    observedSha256 = it.observedSha256,
                )
            },
            artifacts = artifacts,
            stage = "S3",
            step = SwitchSteps.PRODUCE,
            state = SwitchStateNames.PRODUCE,
            updatedAtUptimeMs = clock.nowMillis(),
        )
        authority.write(updated)
        append(journal, updated, "S2", SwitchSteps.SNAPSHOT, SwitchOp.DONE)
        return SnapshotPhaseResult(updated, pre, base)
    }

    private fun export(
        request: ModeSwitchRequest,
        kind: String,
        partition: String,
        destination: File,
    ): ExportedImage = runCatching {
        gateway.exportImage(request, kind, partition, destination)
    }.getOrElse { error ->
        throw SwitchFailure(ModeSwitchCodes.PRE_IMAGE_INVALID, "${kind}/${partition}: ${error.message}")
    }

    private data class ProducePhaseResult(val record: SwitchRecord, val plan: SwitchPlan, val planSha256: String)

    private fun producePhase(
        request: ModeSwitchRequest,
        record: SwitchRecord,
        journal: SwitchJournal,
        workDir: File,
        preImages: Map<String, ExportedImage>,
        baseImages: Map<String, ExportedImage>,
    ): ProducePhaseResult {
        append(journal, record, "S3", SwitchSteps.PRODUCE, SwitchOp.INTENT)
        val target = request.resolvedTarget
        val status = record.partitions.firstOrNull { it.name == target }
            ?: throw SwitchFailure(ModeSwitchCodes.PLAN_INVALID, "no target partition $target")
        val baseImage = baseImages[target]
            ?: throw SwitchFailure(BaselineErrors.BASELINE_CORRUPT, "no base image $target")
        val baseline = baselines.verify(request.baselineId)
        val baselineSha = ModeSwitchPlanBuilder.baselineSha(baseline, target)
            ?: throw SwitchFailure(BaselineErrors.BASELINE_CORRUPT, "no baseline $target")
        val candidate = runCatching {
            producer.produce(
                CandidateInput(
                    switchId = request.switchId,
                    toMode = request.toMode,
                    partition = target,
                    baselineImage = baseImage.file,
                    baselineSha256 = baselineSha,
                    workDir = workDir,
                    kmi = ModeSwitchKmi.parse(environment.deviceFacts().kernelRelease).orEmpty(),
                    kernelRelease = environment.deviceFacts().kernelRelease,
                ),
            )
        }.getOrElse { error ->
            CandidateResult(null, "", 0, ModeSwitchCodes.PRODUCE_FAILED, error.message.orEmpty())
        }
        if (!candidate.ok) {
            hooks.restoreProducerSideEffects()
            throw SwitchFailure(candidate.code.ifEmpty { ModeSwitchCodes.PRODUCE_FAILED }, candidate.detail)
        }
        val image = candidate.image!!
        if (!image.isFile || image.length() != status.size) {
            hooks.restoreProducerSideEffects()
            throw SwitchFailure(ModeSwitchCodes.PRODUCE_OUTPUT_SIZE_INVALID, target)
        }
        val sha = ModeSwitchHashes.sha256(image)
        if (!sha.equals(candidate.sha256, ignoreCase = true) || !ModeSwitchHashes.isHash(sha)) {
            hooks.restoreProducerSideEffects()
            throw SwitchFailure(ModeSwitchCodes.PRODUCE_CANDIDATE_CHANGED, target)
        }
        val exported = ExportedImage(image, image.length(), sha)
        val submitted = runCatching { gateway.submitCandidate(request, target, exported) }
            .getOrElse { error ->
                GatewayOutcome(false, "", ModeSwitchCodes.PRODUCE_FAILED, error.message.orEmpty())
            }
        if (!submitted.ok) {
            hooks.restoreProducerSideEffects()
            throw SwitchFailure(submitted.code.ifEmpty { ModeSwitchCodes.PRODUCE_FAILED }, submitted.detail)
        }
        val plan = try {
            ModeSwitchPlanBuilder.build(
                request = request,
                startBootId = record.startBootId,
                device = environment.deviceFacts(),
                baseline = baseline,
                partitions = record.partitions.map {
                    SwitchPartitionStatus(it.name, it.role, it.size, it.preSha256, it.targetSha256,
                        it.tailSha256, it.observedSha256, it.state)
                },
                preImages = preImages,
                baseImages = baseImages,
                candidate = ModeSwitchPlanBuilder.CandidateImage(target, image, sha),
            )
        } catch (failure: SwitchFailure) {
            hooks.restoreProducerSideEffects()
            throw failure
        }
        val prepared = runCatching { gateway.preparePlan(request, plan.flatFields()) }
            .getOrElse { error ->
                GatewayOutcome(false, "", ModeSwitchCodes.PLAN_INVALID, error.message.orEmpty())
            }
        if (!prepared.ok) {
            throw SwitchFailure(prepared.code.ifEmpty { ModeSwitchCodes.PLAN_INVALID }, prepared.detail)
        }
        val withPlan = record.copy(
            planSha256 = plan.planSha256,
            state = SwitchStateNames.COMMIT,
            stage = "S4",
            step = SwitchSteps.QUIESCE,
            updatedAtUptimeMs = clock.nowMillis(),
            partitions = record.partitions.map {
                if (it.name == target) {
                    it.copy(targetSha256 = sha, tailSha256 = ModeSwitchHashes.tailSha256(image),
                        role = "WRITE_CANDIDATE", state = "PENDING")
                } else {
                    it.copy(role = "RESTORE_BASELINE", state = "PENDING")
                }
            },
            artifacts = record.artifacts + mapOf(
                "candidate-$target" to image.absolutePath,
                "journal" to File(workDir, "journal.jsonl").absolutePath,
            ),
        )
        authority.write(withPlan)
        append(journal, withPlan, "S3", SwitchSteps.PRODUCE, SwitchOp.PREPARED)
        return ProducePhaseResult(withPlan, plan, plan.planSha256)
    }

    private suspend fun commitPhase(
        request: ModeSwitchRequest,
        record: SwitchRecord,
        journal: SwitchJournal,
    ): ModeSwitchRun {
        var current = record.transition(SwitchStateNames.COMMIT, "S4", SwitchSteps.QUIESCE, clock.nowMillis())
        authority.write(current)
        append(journal, current, "S4", SwitchSteps.QUIESCE, SwitchOp.MOVE_INTENT)
        if (request.fromMode == WorkMode.LITE) {
            val withdrawn = hooks.withdrawLiteImplants()
            if (!withdrawn.ok) {
                return commitFailure(request, current, journal,
                    GatewayOutcome(false, "", withdrawn.code.ifEmpty { ModeSwitchCodes.QUIESCE_TIMEOUT },
                        withdrawn.detail))
            }
        }
        val quiesced = hooks.quiesce(request.fromMode)
        if (!quiesced.ok) {
            return commitFailure(request, current, journal,
                GatewayOutcome(false, "", quiesced.code.ifEmpty { ModeSwitchCodes.QUIESCE_TIMEOUT },
                    quiesced.detail))
        }
        append(journal, current, "S4", SwitchSteps.QUIESCE, SwitchOp.MOVE_DONE)

        // 4b 出仓：真实 MoveSet→FileMoveExecutor（live → 离线仓）；这一步同时也是"自动备份"。
        val stage = moveStage
        var movePlan: MoveStagePlan? = null
        if (stage != null) {
            val planned = stage.plan(request.switchId, request.fromMode, request.toMode)
            if (!planned.ok) {
                return commitFailure(
                    request, current, journal,
                    GatewayOutcome(false, "", "MOVE_PLAN_INVALID", planned.validationErrors.joinToString(",")),
                    planned,
                )
            }
            movePlan = planned
            append(journal, current, "S4", SwitchSteps.MOVE_OUT, SwitchOp.MOVE_INTENT)
            val movedOut = stage.moveOut(planned, moveJournal(journal, current))
            append(journal, current, "S4", SwitchSteps.MOVE_OUT,
                if (movedOut.ok) SwitchOp.MOVE_DONE else SwitchOp.FAIL, code = movedOut.code)
            if (!movedOut.ok) {
                return commitFailure(
                    request, current, journal,
                    GatewayOutcome(false, "", movedOut.code, movedOut.detail), planned,
                )
            }
            current = current.copy(
                moves = planned.plan.outbound.map {
                    SwitchRecordMove(it.livePath, it.kind.name, it.expectedShape, it.owner.suffix, "MOVE_OUT")
                },
                updatedAtUptimeMs = clock.nowMillis(),
            )
            authority.write(current)
        }

        val outcome = runCatching { gateway.commit(request) }.getOrElse { error ->
            GatewayOutcome(false, "", ModeSwitchCodes.WRITE_FAILED, error.message.orEmpty())
        }
        if (!outcome.ok) return commitFailure(request, current, journal, outcome, movePlan)

        // 4e 入仓：离线仓 → 目标模式 live（正序；软链指针由执行器重建）。
        if (stage != null && movePlan != null) {
            append(journal, current, "S4", SwitchSteps.MOVE_IN, SwitchOp.MOVE_INTENT)
            val movedIn = stage.moveIn(movePlan, moveJournal(journal, current))
            append(journal, current, "S4", SwitchSteps.MOVE_IN,
                if (movedIn.ok) SwitchOp.MOVE_DONE else SwitchOp.FAIL, code = movedIn.code)
            if (!movedIn.ok) {
                return commitFailure(
                    request, current, journal,
                    GatewayOutcome(false, "", movedIn.code, movedIn.detail), movePlan,
                )
            }
            current = current.copy(
                moves = current.moves.map { it.copy(state = "DONE") },
                updatedAtUptimeMs = clock.nowMillis(),
            )
            authority.write(current)
            // 4f 物化 + 备份证据（move-manifest）：失败必须回滚，不静默。
            append(journal, current, "S4", SwitchSteps.MATERIALIZE, SwitchOp.MATERIALIZE_INTENT)
            val materialized = stage.materialize(movePlan, moveJournal(journal, current))
            append(journal, current, "S4", SwitchSteps.MATERIALIZE,
                if (materialized.ok) SwitchOp.MATERIALIZE_DONE else SwitchOp.FAIL, code = materialized.code)
            if (!materialized.ok) {
                return commitFailure(
                    request, current, journal,
                    GatewayOutcome(false, "", materialized.code, materialized.detail), movePlan,
                )
            }
        }

        val status = outcome.status
        val moveState = if (stage != null) "DONE" else "SKIPPED"
        current = current.copy(
            state = SwitchStateNames.REBOOT_REQUIRED,
            stage = "S4",
            step = SwitchSteps.COMMIT_PENDING,
            updatedAtUptimeMs = clock.nowMillis(),
            partitions = status?.partitions?.takeIf { it.isNotEmpty() }?.map { partition ->
                SwitchRecordPartition(
                    partition.name, partition.role, partition.size, partition.preSha256,
                    partition.targetSha256, partition.tailSha256, partition.state,
                    partition.observedSha256,
                )
            } ?: current.partitions.map { it.copy(state = "DONE") },
            steps = listOf(
                SwitchRecordStep(SwitchSteps.QUIESCE, "DONE"),
                SwitchRecordStep(SwitchSteps.MOVE_OUT, moveState),
                SwitchRecordStep(SwitchSteps.RESTORE_BASELINE, "DONE"),
                SwitchRecordStep(SwitchSteps.WRITE_CANDIDATE, "DONE"),
                SwitchRecordStep(SwitchSteps.MOVE_IN, moveState),
                SwitchRecordStep(SwitchSteps.MATERIALIZE, moveState),
                SwitchRecordStep(SwitchSteps.COMMIT_PENDING, "DONE"),
            ),
            materialize = SwitchRecordMaterialize(if (stage != null) "DONE" else "SKIPPED", ""),
        )
        current = current.withError("", "", "", "", 0)
        authority.write(current)
        append(journal, current, "S4", SwitchSteps.COMMIT_PENDING, SwitchOp.REBOOT_PENDING)
        return ModeSwitchRun.AwaitingReboot(ModeSwitchStatusProjector.project(current), current.planSha256)
    }

    /** S4 失败：逆序回滚（分区 → 配置 move），再按读回分类。 */
    private suspend fun commitFailure(
        request: ModeSwitchRequest,
        record: SwitchRecord,
        journal: SwitchJournal,
        outcome: GatewayOutcome,
        movePlan: MoveStagePlan? = null,
    ): ModeSwitchRun {
        hooks.restoreAfterFailure(request.fromMode)
        val code = outcome.code.ifEmpty { ModeSwitchCodes.WRITE_FAILED }
        append(journal, record, "S4", record.step, SwitchOp.FAIL, code = code)
        val stage = moveStage

        /** 逆序：先撤分区（4d/4c），再撤配置（4e/4b）。 */
        fun rollbackMoves(): MoveStageResult? =
            if (stage != null && movePlan != null) stage.rollback(movePlan, moveJournal(journal, record)) else null

        if (outcome.state == GatewayState.RECOVERY_REQUIRED) {
            // 分区已不可自动回滚；仍尽力恢复配置并如实记录（失败则升级 RECOVERY_REQUIRED）。
            val moves = runCatching { rollbackMoves() }.getOrNull()
            return markRecoveryRequired(
                record, request,
                if (moves != null && !moves.ok) "MOVE_ROLLBACK_FAILED" else code,
                outcome.detail, journal,
            )
        }
        // 服务端未给出终态：显式逆序回滚。
        val rolled = if (outcome.state == GatewayState.ROLLED_BACK) {
            GatewayOutcome(true, GatewayState.ROLLED_BACK)
        } else {
            runCatching { gateway.rollback(request) }.getOrElse { error ->
                GatewayOutcome(false, GatewayState.RECOVERY_REQUIRED, ModeSwitchCodes.ROLLBACK_FAILED,
                    error.message.orEmpty())
            }
        }
        if (rolled.state != GatewayState.ROLLED_BACK) {
            runCatching { rollbackMoves() }
            return markRecoveryRequired(record, request, ModeSwitchCodes.ROLLBACK_FAILED, outcome.detail, journal)
        }
        // 分区已回到 pre → 撤销配置 move（入仓方向逆序）。失败 → RECOVERY_REQUIRED，不静默。
        val moves = runCatching { rollbackMoves() }.getOrNull()
        if (moves != null && !moves.ok) {
            return markRecoveryRequired(record, request, "MOVE_ROLLBACK_FAILED",
                moves.detail, journal)
        }
        val restored = record.transition(SwitchStateNames.ROLLED_BACK, "RB", record.step,
            clock.nowMillis()).withError(code, "S4", record.step, outcome.detail, clock.nowMillis())
        authority.write(restored)
        append(journal, restored, "RB", record.step, SwitchOp.ROLLBACK_DONE)
        runCatching { snapshots.restoreAfterRollback(request) }
        return ModeSwitchRun.Failed(SwitchStateNames.ROLLED_BACK, code, outcome.detail,
            "S4", record.step, ModeSwitchStatusProjector.project(restored))
    }

    /** journal 行 planSha 固定为切换计划摘要（02 §3.3；move 内部摘要不得混入 WAL）。 */
    private fun moveJournal(journal: SwitchJournal, record: SwitchRecord): SwitchJournal =
        if (record.planSha256.isNotEmpty()) FixedPlanJournal(journal, record.planSha256) else journal

    // ------------------------------------------------------------------ 恢复

    private suspend fun resumeForward(
        request: ModeSwitchRequest,
        record: SwitchRecord,
        observation: SwitchObservation,
    ): ModeSwitchRun {
        return when (record.state) {
            SwitchStateNames.BEGIN, SwitchStateNames.SNAPSHOT, SwitchStateNames.PRODUCE ->
                execute(request, record)
            SwitchStateNames.COMMIT -> continueCommit(request, record)
            SwitchStateNames.REBOOT_REQUIRED, SwitchStateNames.VERIFYING -> verifyAfterBoot(record.switchId)
            SwitchStateNames.ROLLING_BACK -> rollback(record.switchId)
            else -> ModeSwitchRun.Incomplete(record.state, "", "", ModeSwitchStatusProjector.project(record))
        }
    }

    /** COMMIT 断点续跑：服务端 commit 幂等（已 target 的分区 SKIP）。 */
    private suspend fun continueCommit(request: ModeSwitchRequest, record: SwitchRecord): ModeSwitchRun {
        val journal = runCatching { journalFactory.open(record.switchId) }.getOrElse {
            return journalFailure(record, it)
        }
        val outcome = runCatching { gateway.commit(request) }.getOrElse { error ->
            GatewayOutcome(false, "", ModeSwitchCodes.WRITE_FAILED, error.message.orEmpty())
        }
        if (!outcome.ok) return commitFailure(request, record, journal, outcome)
        val status = outcome.status
        val next = record.copy(
            state = SwitchStateNames.REBOOT_REQUIRED,
            stage = "S4",
            step = SwitchSteps.COMMIT_PENDING,
            updatedAtUptimeMs = clock.nowMillis(),
            partitions = status?.partitions?.takeIf { it.isNotEmpty() }?.map { partition ->
                SwitchRecordPartition(partition.name, partition.role, partition.size, partition.preSha256,
                    partition.targetSha256, partition.tailSha256, partition.state, partition.observedSha256)
            } ?: record.partitions,
            error = SwitchRecordError(),
        )
        authority.write(next)
        append(journal, next, "S4", SwitchSteps.COMMIT_PENDING, SwitchOp.REBOOT_PENDING)
        return ModeSwitchRun.AwaitingReboot(ModeSwitchStatusProjector.project(next), next.planSha256)
    }

    private suspend fun verifyFailure(
        record: SwitchRecord,
        request: ModeSwitchRequest,
        code: String,
        detail: String,
        journal: SwitchJournal,
        @Suppress("UNUSED_PARAMETER") serviceStatus: GatewayStatus?,
    ): ModeSwitchRun {
        if (!environment.targetRootAvailable(request.toMode)) {
            return markRecoveryRequired(record, request, code, detail, journal)
        }
        // 目标 root 可用 → 写 pre + 数据回滚（02 §6.1 S6.1/6.2）。
        val rolled = runCatching { gateway.rollback(request) }.getOrElse { error ->
            GatewayOutcome(false, GatewayState.RECOVERY_REQUIRED, ModeSwitchCodes.ROLLBACK_FAILED,
                error.message.orEmpty())
        }
        return if (rolled.state == GatewayState.ROLLED_BACK) {
            hooks.restoreAfterFailure(request.fromMode)
            val restored = record.transition(SwitchStateNames.ROLLED_BACK, "RB", SwitchSteps.VERIFY_PARTITIONS,
                clock.nowMillis()).withError(code, "S6", SwitchSteps.VERIFY_PARTITIONS, detail, clock.nowMillis())
            authority.write(restored)
            append(journal, restored, "RB", SwitchSteps.VERIFY_PARTITIONS, SwitchOp.ROLLBACK_DONE)
            runCatching { snapshots.restoreAfterRollback(request) }
            ModeSwitchRun.Failed(SwitchStateNames.ROLLED_BACK, code, detail, "S6",
                SwitchSteps.VERIFY_PARTITIONS, ModeSwitchStatusProjector.project(restored))
        } else {
            markRecoveryRequired(record, request, ModeSwitchCodes.ROLLBACK_FAILED, detail, journal)
        }
    }

    private fun markRecoveryRequired(
        record: SwitchRecord,
        request: ModeSwitchRequest,
        code: String,
        detail: String,
        journal: SwitchJournal,
    ): ModeSwitchRun.Failed {
        val failed = record.transition(SwitchStateNames.RECOVERY_REQUIRED, record.stage, record.step,
            clock.nowMillis()).withError(code, record.stage, record.step, detail, clock.nowMillis())
        authority.write(failed)
        append(journal, failed, record.stage, record.step, SwitchOp.RECOVERY_REQUIRED, code = code)
        return ModeSwitchRun.Failed(SwitchStateNames.RECOVERY_REQUIRED, code, detail,
            record.stage, record.step, ModeSwitchStatusProjector.project(failed))
    }

    // ------------------------------------------------------------------ 失败收尾/工具

    private suspend fun finalizeFailure(
        request: ModeSwitchRequest,
        record: SwitchRecord,
        journal: SwitchJournal,
        code: String,
        detail: String,
    ): ModeSwitchRun {
        runCatching { hooks.restoreProducerSideEffects() }
        return when (record.state) {
            SwitchStateNames.COMMIT, SwitchStateNames.ROLLING_BACK -> commitFailure(
                request, record.withError(code, record.stage, record.step, detail, clock.nowMillis()),
                journal, GatewayOutcome(false, "", code, detail),
            )
            else -> {
                runCatching { gateway.abort(request) }
                val failed = record.transition(SwitchStateNames.FAILED_PRE_WRITE, record.stage, record.step,
                    clock.nowMillis()).withError(code, record.stage, record.step, detail, clock.nowMillis())
                authority.write(failed)
                append(journal, failed, record.stage, record.step, SwitchOp.FAIL, code = code)
                ModeSwitchRun.Failed(SwitchStateNames.FAILED_PRE_WRITE, code, detail,
                    record.stage, record.step, ModeSwitchStatusProjector.project(failed))
            }
        }
    }

    private fun append(
        journal: SwitchJournal,
        record: SwitchRecord,
        stage: String,
        step: String,
        op: SwitchOp,
        partition: String = "",
        expectedSha256: String = "",
        observedSha256: String = "",
        code: String = "",
    ): JournalLine = journal.append(
        switchId = record.switchId,
        planSha256 = record.planSha256,
        stage = stage,
        step = step,
        op = op,
        partition = partition,
        expectedSha256 = expectedSha256,
        observedSha256 = observedSha256,
        code = code,
    )

    private fun adjustedPending(request: ModeSwitchRequest): PendingFacts {
        val pending = environment.pending()
        if (!pending.switchPending) return pending
        val own = (authority.read() as? AuthorityRead.Ok)?.record
        return if (own != null && own.switchId == request.switchId) pending.copy(switchPending = false) else pending
    }

    private fun plannedPartitions(
        request: ModeSwitchRequest,
        baseline: BaselineVerification,
        inventory: PartitionInventory,
    ): List<PlannedPartition> {
        val target = request.resolvedTarget
        return request.plannedPartitions(inventory.present).map { name ->
            val size = inventory.sizes[name]
                ?: 0L
            PlannedPartition(
                name = name,
                role = if (name == target) "WRITE_CANDIDATE" else "RESTORE_BASELINE",
                size = size,
                targetSha256 = ModeSwitchPlanBuilder.baselineSha(baseline, name).orEmpty(),
            )
        }
    }

    private fun requestOf(record: SwitchRecord): ModeSwitchRequest? {
        val from = WorkMode.fromWire(record.fromMode) ?: return null
        val to = WorkMode.fromWire(record.toMode) ?: return null
        if (from == to) return null
        return runCatching { ModeSwitchRequest(record.switchId, from, to, record.baselineId, record.fromBuild, record.toBuild,
            targetPartition = record.targetPartition ?: ModeSwitchPreflight.targetPartition(to),
            sourcePartition = record.sourcePartition) }.getOrNull()
    }

    private fun journalFailure(record: SwitchRecord, error: Throwable): ModeSwitchRun.Failed =
        ModeSwitchRun.Failed(SwitchStateNames.FAILED_PRE_WRITE, ModeSwitchCodes.RECOVERY_JOURNAL_CORRUPT,
            error.message.orEmpty(), record.stage, record.step, ModeSwitchStatusProjector.project(record))

    private fun badRecord(record: SwitchRecord, stage: String, step: String): ModeSwitchRun.Failed =
        ModeSwitchRun.Failed(SwitchStateNames.FAILED_PRE_WRITE, ModeSwitchCodes.PLAN_INVALID,
            "persisted record has no valid mode", stage, step, ModeSwitchStatusProjector.project(record))

    private fun failWithoutRecord(code: String, detail: String, stage: String, step: String): ModeSwitchRun.Failed =
        ModeSwitchRun.Failed(SwitchStateNames.FAILED_PRE_WRITE, code, detail, stage, step, null)

    private suspend fun guardedRun(
        request: ModeSwitchRequest,
        action: suspend () -> ModeSwitchRun,
    ): ModeSwitchRun = try {
        action()
    } catch (failure: SwitchFailure) {
        ModeSwitchRun.Failed(SwitchStateNames.FAILED_PRE_WRITE, failure.code, failure.detail, "S0", "S0", null)
    } catch (error: Throwable) {
        if (error is Error) throw error
        ModeSwitchRun.Failed(SwitchStateNames.FAILED_PRE_WRITE, ModeSwitchCodes.WRITE_FAILED,
            error.message.orEmpty(), "S0", "S0", null)
    }
}
