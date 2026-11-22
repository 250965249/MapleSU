package dev.maplesu.manager.workmode.migration

import dev.maplesu.manager.workmode.WorkMode

/**
 * 外部 Root 迁移 UI 的纯状态机。
 *
 * 本文件**不依赖 Android/Compose**：只做「后端事件 → 页面状态」的纯 reducer，便于主机表驱动测试。
 * UI 层只投影这里的字段，禁止把 `ExternalRootInfo`/journal 原始结构直接塞进 Compose state
 * （05 §6.2：只含可展示字段，不含路径细节与授权值）。
 */
enum class MigrationStage(val wire: String) {
    /** 未检测/未进入。 */
    IDLE("IDLE"),
    DETECTING("DETECTING"),
    /** 检测完成：可展开目标选择；不表示一定能开始（看 blockers）。 */
    DETECTED("DETECTED"),
    /** 已展开确认区（destructive 文案 + 备份先行）。 */
    CONFIRMING("CONFIRMING"),
    BACKING_UP("BACKING_UP"),
    RESTORING_EXTERNAL("RESTORING_EXTERNAL"),
    WRITING_TARGET("WRITING_TARGET"),
    DEPLOYING("DEPLOYING"),
    /** 已落盘 pending，等待受控重启。 */
    PENDING_REBOOT("PENDING_REBOOT"),
    VERIFYING("VERIFYING"),
    COMPLETED("COMPLETED"),
    FAILED("FAILED"),
    ROLLED_BACK("ROLLED_BACK"),
    RECOVERY_REQUIRED("RECOVERY_REQUIRED"),
    /** 无可用后端（默认无 facade）：页面诚实降级，不显示开始按钮。 */
    UNAVAILABLE("UNAVAILABLE");

    val isTerminal: Boolean
        get() = this == COMPLETED || this == FAILED || this == ROLLED_BACK ||
            this == RECOVERY_REQUIRED || this == UNAVAILABLE || this == IDLE

    /** 进行中禁止返回（对齐切换进度页 S4/S5 语义）。 */
    val blocksBack: Boolean
        get() = this in setOf(BACKING_UP, RESTORING_EXTERNAL, WRITING_TARGET, DEPLOYING, PENDING_REBOOT, VERIFYING)

    /** 已开始破坏性写入：此时"中止"只能走回滚/恢复，不能静默回卷到检测态。 */
    val destructiveStarted: Boolean
        get() = this in setOf(RESTORING_EXTERNAL, WRITING_TARGET, DEPLOYING, PENDING_REBOOT)
}

/** 家族 → 展示 key（文案由 UI 层映射，禁止在纯逻辑里拼长句）。 */
object MigrationFamilyKeys {
    const val KSU = "migration_family_ksu"
    const val MAPLESU = "migration_family_maplesu"
    const val MAGISK = "migration_family_magisk"
    const val APATCH = "migration_family_apatch"
    const val UNKNOWN = "migration_family_unknown"

    fun of(family: Family): String = when (family) {
        Family.KSU_UPSTREAM -> KSU
        Family.KSU_7K -> MAPLESU
        Family.MAGISK -> MAGISK
        Family.APATCH -> APATCH
        Family.UNKNOWN -> UNKNOWN
    }
}

object MigrationBlockerKeys {
    const val NO_ROOT = "migration_blocker_no_root"
    const val NO_SPACE = "migration_blocker_no_space"
    const val PENDING = "migration_blocker_pending"
    const val LAYOUT = "migration_blocker_layout"
    const val CANDIDATE = "migration_blocker_candidate"
    const val CLEAN_IMAGE = "migration_blocker_clean_image"
    const val OWN_MANAGER = "migration_blocker_own_manager"
    const val UNKNOWN = "migration_blocker_unknown"

    fun of(blocker: Blocker): String = when (blocker) {
        is Blocker.NoRoot -> NO_ROOT
        is Blocker.NoSpace -> NO_SPACE
        is Blocker.PendingTransaction -> PENDING
        is Blocker.LayoutUnsupported -> LAYOUT
        is Blocker.CandidateUnproducible -> CANDIDATE
        is Blocker.CleanImageUnavailable -> CLEAN_IMAGE
        is Blocker.OwnManagerInstalled -> OWN_MANAGER
    }
}

object MigrationStageKeys {
    const val M0 = "migration_phase_m0"
    const val M1 = "migration_phase_m1"
    const val M2 = "migration_phase_m2"
    const val M3 = "migration_phase_m3"
    const val M4 = "migration_phase_m4"
    const val M5 = "migration_phase_m5"
    const val M6 = "migration_phase_m6"
    const val M7 = "migration_phase_m7"
    const val M8 = "migration_phase_m8"
    const val M9 = "migration_phase_m9"

    fun of(stage: MigrationStage): String = when (stage) {
        MigrationStage.BACKING_UP -> M1
        MigrationStage.RESTORING_EXTERNAL, MigrationStage.WRITING_TARGET -> M4
        MigrationStage.DEPLOYING -> M5
        MigrationStage.PENDING_REBOOT -> M7
        MigrationStage.VERIFYING -> M9
        MigrationStage.COMPLETED -> M9
        MigrationStage.FAILED, MigrationStage.ROLLED_BACK, MigrationStage.RECOVERY_REQUIRED -> M4
        else -> M0
    }

    /** 进度页"剩余步骤"用的固定 5 段（备份→还原→写目标→部署→待重启）。 */
    val PROGRESS_STAGES: List<MigrationStage> = listOf(
        MigrationStage.BACKING_UP,
        MigrationStage.RESTORING_EXTERNAL,
        MigrationStage.WRITING_TARGET,
        MigrationStage.DEPLOYING,
        MigrationStage.PENDING_REBOOT,
    )

    fun stepOf(stage: MigrationStage): Int = PROGRESS_STAGES.indexOf(stage).let { if (it < 0) 0 else it + 1 }
}

/** 检测结果的可展示投影。 */
data class MigrationDetectionUi(
    val familyKey: String,
    val versionLabel: String?,
    val uapi: Int?,
    /** 外部已改分区（排序）。 */
    val patchedPartitions: List<String>,
    /** 当前策略下"可取得干净镜像"的分区（排序）。 */
    val cleanImagePartitions: List<String>,
    val usableStockBackups: Int,
    val totalStockBackups: Int,
    val managerPackageCount: Int,
    val bestEffort: Boolean,
    val supported: Boolean,
    /** 阻断原因 key（inline 展示，不隐藏入口）。 */
    val blockerKeys: List<String>,
    /** 页面级是否可开始（与 target 选择共同决定 canStart）。 */
    val eligible: Boolean,
) {
    /** 给定目标模式时"将被还原"的分区：restoreSet - targetSet。 */
    fun restorePartitionsFor(target: WorkMode): List<String> =
        patchedPartitions.filter { it !in target.targetPartitions }.sorted()

    fun willUninstallManager(): Boolean = managerPackageCount > 0
}

data class MigrationTargetOption(
    val mode: WorkMode,
    val recommended: Boolean,
    val enabled: Boolean,
    val disabledReasonKey: String? = null,
)

data class MigrationBackupSummary(
    val objectCount: Int = 0,
    val totalBytes: Long = 0,
    /** manifest 落盘并通过读回校验。 */
    val verified: Boolean = false,
    val missing: Int = 0,
    val mismatched: Int = 0,
) {
    /** 备份完整性（05 §2.5：M1 的完成判据）。 */
    val complete: Boolean
        get() = verified && objectCount > 0 && missing == 0 && mismatched == 0

    companion object {
        fun of(manifest: BackupManifest, verification: BackupVerification): MigrationBackupSummary =
            MigrationBackupSummary(
                objectCount = manifest.objects.size,
                totalBytes = manifest.objects.sumOf { it.size },
                verified = manifest.verified && verification.ok,
                missing = verification.missing.size,
                mismatched = verification.mismatched.size,
            )
    }
}

data class MigrationProgressUi(
    val stage: MigrationStage = MigrationStage.IDLE,
    val stepIndex: Int = 0,
    val stepCount: Int = MigrationStageKeys.PROGRESS_STAGES.size,
    val stepKey: String = "",
    val logLine: String = "",
)

/** 判定是否"已落地"（与 [ModulePlanItem.imported] 同语义）。 */
val ModuleDecision.imported: Boolean
    get() = this == ModuleDecision.RESTORE_DIRECT ||
        this == ModuleDecision.IMPORT_LITE ||
        this == ModuleDecision.IMPORT_DISABLED

data class MigrationModuleResultUi(
    val moduleId: String,
    val decision: ModuleDecision,
    val reason: String = "",
) {
    val imported: Boolean get() = decision.imported
    val decisionKey: String
        get() = when (decision) {
            ModuleDecision.RESTORE_DIRECT -> "migration_module_restored"
            ModuleDecision.IMPORT_LITE -> "migration_module_imported"
            ModuleDecision.IMPORT_DISABLED -> "migration_module_disabled"
            ModuleDecision.SKIP_UNSUPPORTED -> "migration_module_unsupported"
            ModuleDecision.SKIP_FAILED -> "migration_module_failed"
        }
}

data class MigrationAuthResultUi(
    val intents: Int = 0,
    val stale: Int = 0,
    val applied: Int = 0,
    val pending: Int = 0,
)

enum class MigrationResultKind(val stage: MigrationStage) {
    VERIFIED(MigrationStage.COMPLETED),
    FAILED(MigrationStage.FAILED),
    ROLLED_BACK(MigrationStage.ROLLED_BACK),
    RECOVERY_REQUIRED(MigrationStage.RECOVERY_REQUIRED),
}

data class MigrationResultUi(
    val kind: MigrationResultKind,
    val modules: List<MigrationModuleResultUi> = emptyList(),
    val auth: MigrationAuthResultUi = MigrationAuthResultUi(),
    /** 任一未还原/未知管理器 → 报告必须显式展示，不计入"无残留"（红线 14）。 */
    val residual: Boolean = false,
    val residues: List<String> = emptyList(),
    val backup: MigrationBackupSummary? = null,
    val rebootRequired: Boolean = false,
    val errorCode: String = "",
) {
    val importedModules: Int get() = modules.count { it.imported }
    val unsupportedModules: Int get() = modules.count { it.decision == ModuleDecision.SKIP_UNSUPPORTED }
    val failedModules: Int get() = modules.count { it.decision == ModuleDecision.SKIP_FAILED }

    fun modulesForDecision(decision: ModuleDecision): List<MigrationModuleResultUi> =
        modules.filter { it.decision == decision }
}

data class MigrationFailureUi(
    val code: String,
    val stage: MigrationStage,
    val rolledBack: Boolean = false,
    val recoveryRequired: Boolean = false,
    val detailKey: String = "",
)

/** 页面状态（不可变）。 */
data class MigrationUiSnapshot(
    val stage: MigrationStage = MigrationStage.IDLE,
    val migrationId: String = "",
    val detection: MigrationDetectionUi? = null,
    val targetOptions: List<MigrationTargetOption> = emptyList(),
    val selectedTarget: WorkMode? = null,
    val backup: MigrationBackupSummary? = null,
    val progress: MigrationProgressUi = MigrationProgressUi(),
    val result: MigrationResultUi? = null,
    val failure: MigrationFailureUi? = null,
    val unavailableCode: String = "",
    val confirming: Boolean = false,
) {
    val canStart: Boolean
        get() = stage == MigrationStage.DETECTED && !confirming && selectedTarget != null &&
            targetOptions.any { it.mode == selectedTarget && it.enabled } &&
            (detection?.eligible == true)

    val canAbort: Boolean
        get() = stage.blocksBack

    val showBestEffortNotice: Boolean get() = detection?.bestEffort == true

    val residualWarning: Boolean get() = result?.residual == true

    val confirmedTarget: MigrationTargetOption? get() = targetOptions.firstOrNull { it.mode == selectedTarget }

    val restorePartitions: List<String>
        get() = selectedTarget?.let { detection?.restorePartitionsFor(it) } ?: emptyList()
}

sealed interface MigrationUiEvent {
    data object DetectStarted : MigrationUiEvent
    data class Detected(val info: ExternalRootInfo, val eligibility: MigrationEligibility) : MigrationUiEvent
    data class DetectionUnavailable(val code: String) : MigrationUiEvent
    data class TargetSelected(val mode: WorkMode) : MigrationUiEvent
    data object ConfirmRequested : MigrationUiEvent
    data object ConfirmDismissed : MigrationUiEvent
    data object StartRequested : MigrationUiEvent
    data class Started(val migrationId: String) : MigrationUiEvent
    data class Progress(
        val stage: MigrationStage,
        val stepIndex: Int = 0,
        val stepCount: Int = MigrationStageKeys.PROGRESS_STAGES.size,
        val stepKey: String = "",
        val logLine: String = "",
    ) : MigrationUiEvent
    data class BackupCaptured(val summary: MigrationBackupSummary) : MigrationUiEvent
    data class Completed(val result: MigrationResultUi) : MigrationUiEvent
    data class Failed(val failure: MigrationFailureUi) : MigrationUiEvent
    data object Aborted : MigrationUiEvent
    data object Dismissed : MigrationUiEvent
    data object Reset : MigrationUiEvent
}

/**
 * 纯 reducer：`reduce(state, event)`。所有非法/越界事件被忽略或保守降级，绝不抛异常
 * （UI 线程不接受因未接线/乱序事件导致崩溃）。
 */
object MigrationUiReducer {

    fun reduce(state: MigrationUiSnapshot, event: MigrationUiEvent): MigrationUiSnapshot = when (event) {
        MigrationUiEvent.DetectStarted -> state.copy(
            stage = MigrationStage.DETECTING,
            detection = null,
            targetOptions = emptyList(),
            selectedTarget = null,
            result = null,
            failure = null,
            unavailableCode = "",
            confirming = false,
        )

        is MigrationUiEvent.Detected -> {
            val detection = detectionSummary(event.info, event.eligibility)
            val options = targetOptions(event.info, event.eligibility)
            val selected = event.eligibility.recommendedTarget?.takeIf { mode ->
                options.any { it.mode == mode && it.enabled }
            } ?: options.firstOrNull { it.enabled }?.mode
            state.copy(
                stage = MigrationStage.DETECTED,
                detection = detection,
                targetOptions = options,
                selectedTarget = selected,
                result = null,
                failure = null,
                unavailableCode = "",
                backup = null,
                progress = MigrationProgressUi(),
                confirming = false,
            )
        }

        is MigrationUiEvent.DetectionUnavailable -> state.copy(
            stage = MigrationStage.UNAVAILABLE,
            detection = null,
            targetOptions = emptyList(),
            selectedTarget = null,
            unavailableCode = event.code,
            result = null,
            failure = null,
            confirming = false,
        )

        is MigrationUiEvent.TargetSelected -> {
            val option = state.targetOptions.firstOrNull { it.mode == event.mode }
            if (option == null || !option.enabled || state.stage != MigrationStage.DETECTED) {
                state
            } else {
                state.copy(
                    selectedTarget = event.mode,
                    confirming = false,
                    // 兼容旧意图：目标变化时恢复分区列表随之变化（由 detection 计算）。
                    detection = state.detection,
                )
            }
        }

        MigrationUiEvent.ConfirmRequested ->
            if (state.canStart) state.copy(confirming = true, stage = MigrationStage.CONFIRMING) else state

        MigrationUiEvent.ConfirmDismissed ->
            if (state.stage == MigrationStage.CONFIRMING) {
                state.copy(confirming = false, stage = MigrationStage.DETECTED)
            } else {
                state
            }

        MigrationUiEvent.StartRequested ->
            if (state.canStart) {
                state.copy(
                    confirming = false,
                    stage = MigrationStage.BACKING_UP,
                    progress = MigrationProgressUi(
                        stage = MigrationStage.BACKING_UP,
                        stepIndex = 1,
                        stepCount = MigrationStageKeys.PROGRESS_STAGES.size,
                        stepKey = MigrationStageKeys.M1,
                    ),
                )
            } else {
                state
            }

        is MigrationUiEvent.Started -> state.copy(
            migrationId = event.migrationId,
            stage = if (state.stage.isTerminal) state.stage else MigrationStage.BACKING_UP,
        )

        is MigrationUiEvent.Progress -> {
            // 终态之后不接受进度回退（late event 不能把成功页变回进行中）。
            if (state.stage.isTerminal) {
                state
            } else {
                state.copy(
                    stage = event.stage,
                    progress = MigrationProgressUi(
                        stage = event.stage,
                        stepIndex = if (event.stepIndex > 0) event.stepIndex else MigrationStageKeys.stepOf(event.stage),
                        stepCount = event.stepCount,
                        stepKey = if (event.stepKey.isNotBlank()) {
                            event.stepKey
                        } else {
                            MigrationStageKeys.of(event.stage)
                        },
                        logLine = event.logLine,
                    ),
                )
            }
        }

        is MigrationUiEvent.BackupCaptured -> state.copy(backup = event.summary)

        is MigrationUiEvent.Completed -> state.copy(
            stage = event.result.kind.stage,
            result = event.result,
            failure = null,
            confirming = false,
            progress = state.progress.copy(stage = event.result.kind.stage),
        )

        is MigrationUiEvent.Failed -> state.copy(
            stage = when {
                event.failure.recoveryRequired -> MigrationStage.RECOVERY_REQUIRED
                event.failure.rolledBack -> MigrationStage.ROLLED_BACK
                else -> MigrationStage.FAILED
            },
            failure = event.failure,
            confirming = false,
        )

        MigrationUiEvent.Aborted -> when {
            // 破坏性写入已开始：中止 = 需要回滚/恢复，不能静默回检测态。
            state.stage.destructiveStarted -> state.copy(
                stage = MigrationStage.RECOVERY_REQUIRED,
                failure = MigrationFailureUi(
                    code = MIGRATION_ABORT_AFTER_WRITE,
                    stage = state.stage,
                    recoveryRequired = true,
                    detailKey = "migration_abort_after_write",
                ),
                confirming = false,
            )
            state.stage in setOf(MigrationStage.DETECTING, MigrationStage.DETECTED, MigrationStage.CONFIRMING) ||
                state.stage == MigrationStage.BACKING_UP -> state.copy(
                stage = if (state.detection != null) MigrationStage.DETECTED else MigrationStage.IDLE,
                migrationId = "",
                confirming = false,
                progress = MigrationProgressUi(),
                backup = null,
            )
            else -> state
        }

        MigrationUiEvent.Dismissed ->
            if (state.result != null || state.stage.isTerminal) {
                state.copy(
                    stage = if (state.detection != null) MigrationStage.DETECTED else MigrationStage.IDLE,
                    result = null,
                    failure = null,
                    migrationId = "",
                    confirming = false,
                    progress = MigrationProgressUi(),
                )
            } else {
                state
            }

        MigrationUiEvent.Reset -> MigrationUiSnapshot()
    }

    // ------------------------------------------------------------------ 投影

    fun detectionSummary(info: ExternalRootInfo, eligibility: MigrationEligibility): MigrationDetectionUi {
        val usableBackups = info.stockBackups.values.count { it.state == BackupState.USABLE }
        val blockerKeys = eligibility.blockers.map { MigrationBlockerKeys.of(it) }.distinct()
        return MigrationDetectionUi(
            familyKey = MigrationFamilyKeys.of(info.family),
            versionLabel = info.version,
            uapi = info.uapi,
            patchedPartitions = info.patchedPartitions.sorted(),
            cleanImagePartitions = info.cleanImagePartitions.sorted(),
            usableStockBackups = usableBackups,
            totalStockBackups = info.stockBackups.size,
            managerPackageCount = info.managerPackages.size,
            bestEffort = info.bestEffort,
            supported = info.supported,
            blockerKeys = blockerKeys,
            eligible = eligibility.enabled && blockerKeys.isEmpty(),
        )
    }

    fun targetOptions(info: ExternalRootInfo, eligibility: MigrationEligibility): List<MigrationTargetOption> =
        WorkMode.entries.map { mode ->
            val allowed = eligibility.targetAllowed[mode] ?: false
            MigrationTargetOption(
                mode = mode,
                recommended = eligibility.recommendedTarget == mode,
                enabled = allowed,
                disabledReasonKey = if (allowed) null else MigrationBlockerKeys.CLEAN_IMAGE,
            )
        }

    fun recommendTarget(info: ExternalRootInfo, eligibility: MigrationEligibility): WorkMode? =
        eligibility.recommendedTarget ?: targetOptions(info, eligibility).firstOrNull { it.enabled }?.mode

    fun classifyResult(result: MigrationResultUi): MigrationStage = result.kind.stage

    const val MIGRATION_ABORT_AFTER_WRITE = "MIGRATION_ABORT_AFTER_WRITE"
}
