package dev.maplesu.manager.workmode.recovery

import dev.maplesu.manager.workmode.control.schema.SwitchHeadView
import dev.maplesu.manager.workmode.switch.BaselineState
import dev.maplesu.manager.workmode.switch.SwitchStateNames

/**
 * 恢复决策——**纯函数**，不 import Android。
 *
 * 输入：`switch.json` 只读投影（head）、WAL 重放状态、baseline 状态、设备事实（bootId/slot/固件/内核）、
 * root 通道可用性、重试计数、迁移 pending。
 * 输出：唯一动作 + 理由 + 允许/禁止的控制项 + i18n key。
 *
 * 安全原则（fail-closed）：
 * - 读不出/不认识 ≠ 可自动修复：UNKNOWN/CORRUPT → 只读诊断，绝不自动写分区；
 * - 回滚需要**可验证 root + PRESENT_OK baseline**；缺任一 → 设备外恢复，不承诺自愈；
 * - 连续启动确认失败 2 次 → 禁止无限重试（主文档 :711）；
 * - 无 root 时只给"已导出镜像的外部恢复步骤"，不谎称重启后源模式会自行回来（主文档 §5.7）。
 */
enum class RecoveryAction(val wire: String) {
    /** 无待恢复项（或无切换）。 */
    NONE("NONE"),

    /** 切换进行中：只观察，禁止并发写。 */
    IN_PROGRESS("IN_PROGRESS"),

    /** 需要/继续完整重启（REBOOT_REQUIRED 且 bootId 未变）。 */
    RESUME_REBOOT("RESUME_REBOOT"),

    /** bootId 已变：自动进入启动确认（S6）。 */
    AUTO_VERIFY("AUTO_VERIFY"),

    /** root + 可用 baseline：允许（并推荐）自动回滚到源模式。 */
    AUTO_ROLLBACK("AUTO_ROLLBACK"),

    /** 需要设备外镜像/外部恢复：本机不再自动写。 */
    EXTERNAL_RECOVERY("EXTERNAL_RECOVERY"),

    /** 禁止任何自动动作（现场不可信/重试超限/设备已变化）：只读诊断。 */
    FORBIDDEN("FORBIDDEN"),
}

/** 理由码（UI 文案 key 由 [RecoveryReason.copyKey] 提供；不是穷举主文档错误码）。 */
enum class RecoveryReason(val code: String, val copyKey: String) {
    NO_PENDING_SWITCH("RECOVERY_NO_PENDING", "recovery_reason_none"),
    SWITCH_ACTIVE("RECOVERY_SWITCH_ACTIVE", "recovery_reason_active"),
    ROLLBACK_ACTIVE("RECOVERY_ROLLBACK_ACTIVE", "recovery_reason_rolling_back"),
    REBOOT_REQUIRED("RECOVERY_REBOOT_REQUIRED", "recovery_reason_reboot"),
    REBOOT_OBSERVED("RECOVERY_REBOOT_OBSERVED", "recovery_reason_reboot_observed"),
    REBOOT_NOT_OBSERVED("RECOVERY_REBOOT_NOT_OBSERVED", "recovery_reason_reboot_missing"),
    REBOOT_LIMIT_REACHED("RECOVERY_REBOOT_LIMIT", "recovery_reason_reboot_limit"),
    VERIFY_PENDING("RECOVERY_VERIFY_PENDING", "recovery_reason_verify"),
    VERIFIED("RECOVERY_VERIFIED", "recovery_reason_verified"),
    ROLLED_BACK("RECOVERY_ROLLED_BACK", "recovery_reason_rolled_back"),
    FAILED_PRE_WRITE("RECOVERY_FAILED_PRE_WRITE", "recovery_reason_failed_pre_write"),
    CANCELLED("RECOVERY_CANCELLED", "recovery_reason_cancelled"),
    RECOVERY_REQUIRED("RECOVERY_REQUIRED", "recovery_reason_required"),
    ROLLBACK_AVAILABLE("RECOVERY_ROLLBACK_AVAILABLE", "recovery_reason_rollback_available"),
    VERIFY_FAILED_TWICE("RECOVERY_VERIFY_FAILED_TWICE", "recovery_reason_verify_failed_twice"),
    BASELINE_OK("RECOVERY_BASELINE_OK", "recovery_reason_baseline_ok"),
    BASELINE_MISSING("RECOVERY_BASELINE_MISSING", "recovery_reason_baseline_missing"),
    BASELINE_STALE("RECOVERY_BASELINE_STALE", "recovery_reason_baseline_stale"),
    BASELINE_CORRUPT("RECOVERY_BASELINE_CORRUPT", "recovery_reason_baseline_corrupt"),
    BASELINE_IMPORT_REQUIRED("RECOVERY_BASELINE_IMPORT_REQUIRED", "recovery_reason_baseline_import"),
    NO_ROOT_CHANNEL("RECOVERY_NO_ROOT", "recovery_reason_no_root"),
    DEVICE_MISMATCH("RECOVERY_DEVICE_MISMATCH", "recovery_reason_device_changed"),
    JOURNAL_CORRUPT("RECOVERY_JOURNAL_CORRUPT", "recovery_reason_journal_corrupt"),
    JOURNAL_MISSING("RECOVERY_JOURNAL_MISSING", "recovery_reason_journal_missing"),
    UNKNOWN_STATE("RECOVERY_UNKNOWN_STATE", "recovery_reason_unknown"),
    MIGRATION_PENDING("RECOVERY_MIGRATION_PENDING", "recovery_reason_migration"),
    INVALID_INPUT("RECOVERY_INVALID_INPUT", "recovery_reason_invalid"),
}

/** 恢复页可以出现的动作/入口；禁止项用于 UI 置灰与安装/切换入口门控。 */
enum class RecoveryControl {
    NORMAL_OPERATIONS,
    SWITCH,
    INSTALL,
    MODULE,
    FLASH,
    REBOOT,
    VERIFY,
    ROLLBACK,
    IMPORT_BASELINE,
    EXPORT_DIAGNOSTICS,
}

data class RecoveryInput(
    /** `control/switch.json` 投影；null = 无文件。 */
    val head: SwitchHeadView? = null,
    /** WAL 重放得到的最近状态；null = 无 journal。 */
    val journalState: String? = null,
    val journalCorrupt: Boolean = false,
    val baselineState: BaselineState = BaselineState.MISSING_NEVER_CAPTURED,
    val baselineBlocker: String? = null,
    val currentBootId: String = "",
    /** 设备当前事实。 */
    val slot: String = "",
    val firmware: String = "",
    val kernelRelease: String = "",
    /** journal/plan 记录的来源事实；只有槽位参与设备匹配，内核/固件文字留作记录。 */
    val expectedSlot: String = "",
    val expectedFirmware: String = "",
    val expectedKernelRelease: String = "",
    val rootAvailable: Boolean = false,
    val bootVerifyFailures: Int = 0,
    val rebootRequests: Int = 0,
    val migrationPending: Boolean = false,
    val errorCode: String = "",
    val errorStage: String = "",
) {
    val bootIdChanged: Boolean
        get() {
            val begin = head?.bootIdAtBegin.orEmpty()
            return begin.isNotBlank() && currentBootId.isNotBlank() && begin != currentBootId
        }

    val deviceMismatch: Boolean
        get() = expectedSlot.isNotBlank() && slot.isNotBlank() && expectedSlot != slot
}

data class RecoveryDecision(
    val action: RecoveryAction,
    val reasons: List<RecoveryReason>,
    val allowed: Set<RecoveryControl>,
    val blocked: Set<RecoveryControl>,
    /** 页面标题/解释/下一步的 i18n key（UI 映射文案，不在此拼长句）。 */
    val titleKey: String,
    val detailKey: String,
    val nextStepKey: String,
    val autoRecoverable: Boolean,
    val requiresExternalImage: Boolean,
    /** true = 只读诊断模式（不得出现任何写按钮）。 */
    val diagnosticOnly: Boolean,
    val switchId: String? = null,
) {
    fun allows(control: RecoveryControl): Boolean = control in allowed
    fun blocks(control: RecoveryControl): Boolean = control in blocked
}

object RecoveryCopyKeys {
    const val TITLE_NONE = "recovery_title_none"
    const val TITLE_ACTIVE = "recovery_title_active"
    const val TITLE_REBOOT = "recovery_title_reboot"
    const val TITLE_ROLLBACK = "recovery_title_rollback"
    const val TITLE_EXTERNAL = "recovery_title_external"
    const val TITLE_FORBIDDEN = "recovery_title_forbidden"

    const val DETAIL_NONE = "recovery_detail_none"
    const val DETAIL_ACTIVE = "recovery_detail_active"
    const val DETAIL_REBOOT = "recovery_detail_reboot"
    const val DETAIL_VERIFY = "recovery_detail_verify"
    const val DETAIL_ROLLBACK = "recovery_detail_rollback"
    const val DETAIL_EXTERNAL = "recovery_detail_external"
    const val DETAIL_FORBIDDEN = "recovery_detail_forbidden"

    const val NEXT_NONE = "recovery_next_none"
    const val NEXT_WAIT = "recovery_next_wait"
    const val NEXT_REBOOT = "recovery_next_reboot"
    const val NEXT_VERIFY = "recovery_next_verify"
    const val NEXT_ROLLBACK = "recovery_next_rollback"
    const val NEXT_IMPORT_BASELINE = "recovery_next_import_baseline"
    const val NEXT_EXTERNAL = "recovery_next_external"
    const val NEXT_DIAGNOSE = "recovery_next_diagnose"
}

object RecoveryDecisionEngine {

    private val READ_ONLY_SET = setOf(
        RecoveryControl.NORMAL_OPERATIONS,
        RecoveryControl.EXPORT_DIAGNOSTICS,
    )
    private val WRITE_CONTROLS = setOf(
        RecoveryControl.SWITCH,
        RecoveryControl.INSTALL,
        RecoveryControl.MODULE,
        RecoveryControl.FLASH,
        RecoveryControl.REBOOT,
        RecoveryControl.VERIFY,
        RecoveryControl.ROLLBACK,
    )

    fun decide(input: RecoveryInput): RecoveryDecision {
        val head = input.head
        val state = head?.state
        val journalOnly = state == null && input.journalState != null

        // ---- 现场不可信：journal 损坏 / 只读到 journal / 状态未知 → 只读诊断
        if (input.journalCorrupt) {
            return forbidden(
                input,
                reasons = listOf(RecoveryReason.JOURNAL_CORRUPT),
                extraAllowed = setOf(RecoveryControl.EXPORT_DIAGNOSTICS),
            )
        }
        if (state != null && !SwitchStateNames.isKnown(state)) {
            return forbidden(
                input,
                reasons = listOf(RecoveryReason.UNKNOWN_STATE),
                extraAllowed = setOf(RecoveryControl.EXPORT_DIAGNOSTICS),
            )
        }
        if (journalOnly && input.journalState != null && !SwitchStateNames.isKnown(input.journalState)) {
            return forbidden(
                input,
                reasons = listOf(RecoveryReason.UNKNOWN_STATE),
                extraAllowed = setOf(RecoveryControl.EXPORT_DIAGNOSTICS),
            )
        }
        // 读到 WAL 有未完成切换、但权威 switch.json 丢失：不自动补写状态（保守只读）。
        if (journalOnly && SwitchStateNames.isPending(input.journalState)) {
            return forbidden(
                input,
                reasons = listOf(RecoveryReason.JOURNAL_MISSING, RecoveryReason.JOURNAL_CORRUPT),
                extraAllowed = setOf(RecoveryControl.EXPORT_DIAGNOSTICS),
            )
        }

        // ---- 无 pending 切换：正常态；baseline 问题只影响"能否切换"
        if (state == null) {
            val baselineReasons = baselineReasons(input)
            val blocked = linkedSetOf<RecoveryControl>()
            val reasons = mutableListOf(RecoveryReason.NO_PENDING_SWITCH)
            reasons += baselineReasons
            if (input.baselineState != BaselineState.PRESENT_OK) blocked += RecoveryControl.SWITCH
            if (input.migrationPending) {
                reasons += RecoveryReason.MIGRATION_PENDING
                blocked += setOf(RecoveryControl.SWITCH, RecoveryControl.INSTALL, RecoveryControl.MODULE)
            }
            val importBaseline = if (input.baselineState != BaselineState.PRESENT_OK) {
                setOf(RecoveryControl.IMPORT_BASELINE)
            } else {
                emptySet()
            }
            return RecoveryDecision(
                action = RecoveryAction.NONE,
                reasons = reasons.distinct(),
                allowed = READ_ONLY_SET + importBaseline,
                blocked = blocked,
                titleKey = RecoveryCopyKeys.TITLE_NONE,
                detailKey = RecoveryCopyKeys.DETAIL_NONE,
                nextStepKey = if (input.migrationPending) {
                    RecoveryCopyKeys.NEXT_WAIT
                } else if (importBaseline.isNotEmpty()) {
                    RecoveryCopyKeys.NEXT_IMPORT_BASELINE
                } else {
                    RecoveryCopyKeys.NEXT_NONE
                },
                autoRecoverable = false,
                requiresExternalImage = false,
                diagnosticOnly = false,
                switchId = head?.switchId,
            )
        }

        return when (state) {
            SwitchStateNames.BEGIN,
            SwitchStateNames.SNAPSHOT,
            SwitchStateNames.PRODUCE,
            SwitchStateNames.COMMIT -> active(input, RecoveryReason.SWITCH_ACTIVE)

            SwitchStateNames.ROLLING_BACK -> active(input, RecoveryReason.ROLLBACK_ACTIVE)

            SwitchStateNames.REBOOT_REQUIRED -> rebootRequired(input)

            SwitchStateNames.VERIFYING -> verifying(input)

            SwitchStateNames.VERIFIED,
            SwitchStateNames.ROLLED_BACK,
            SwitchStateNames.FAILED_PRE_WRITE,
            SwitchStateNames.CANCELLED -> terminal(input, state)

            SwitchStateNames.RECOVERY_REQUIRED -> recoveryRequired(input)

            else -> forbidden(input, reasons = listOf(RecoveryReason.UNKNOWN_STATE))
        }
    }

    // ------------------------------------------------------------------ 分支

    private fun active(input: RecoveryInput, reason: RecoveryReason): RecoveryDecision =
        RecoveryDecision(
            action = RecoveryAction.IN_PROGRESS,
            reasons = listOf(reason),
            allowed = setOf(RecoveryControl.EXPORT_DIAGNOSTICS),
            blocked = WRITE_CONTROLS + setOf(
                RecoveryControl.SWITCH, RecoveryControl.INSTALL, RecoveryControl.MODULE, RecoveryControl.FLASH,
            ),
            titleKey = RecoveryCopyKeys.TITLE_ACTIVE,
            detailKey = RecoveryCopyKeys.DETAIL_ACTIVE,
            nextStepKey = RecoveryCopyKeys.NEXT_WAIT,
            autoRecoverable = false,
            requiresExternalImage = false,
            diagnosticOnly = false,
            switchId = input.head?.switchId,
        )

    private fun rebootRequired(input: RecoveryInput): RecoveryDecision {
        if (input.bootIdChanged) {
            return RecoveryDecision(
                action = RecoveryAction.AUTO_VERIFY,
                reasons = listOf(RecoveryReason.REBOOT_OBSERVED, RecoveryReason.VERIFY_PENDING),
                allowed = setOf(
                    RecoveryControl.VERIFY, RecoveryControl.EXPORT_DIAGNOSTICS,
                    RecoveryControl.ROLLBACK.takeIf { canAutoRollback(input) },
                ).filterNotNull().toSet(),
                blocked = WRITE_CONTROLS - setOf(RecoveryControl.VERIFY, RecoveryControl.ROLLBACK),
                titleKey = RecoveryCopyKeys.TITLE_REBOOT,
                detailKey = RecoveryCopyKeys.DETAIL_VERIFY,
                nextStepKey = RecoveryCopyKeys.NEXT_VERIFY,
                autoRecoverable = true,
                requiresExternalImage = false,
                diagnosticOnly = false,
                switchId = input.head?.switchId,
            )
        }
        val limitReached = input.rebootRequests >= MAX_REBOOT_REQUESTS
        val reasons = mutableListOf(RecoveryReason.REBOOT_REQUIRED, RecoveryReason.REBOOT_NOT_OBSERVED)
        if (limitReached) reasons += RecoveryReason.REBOOT_LIMIT_REACHED
        if (!input.rootAvailable) reasons += RecoveryReason.NO_ROOT_CHANNEL
        val canRollback = canAutoRollback(input)
        val allowed = linkedSetOf(RecoveryControl.EXPORT_DIAGNOSTICS)
        if (!limitReached) allowed += RecoveryControl.REBOOT
        if (canRollback) allowed += RecoveryControl.ROLLBACK
        val blocked = WRITE_CONTROLS - allowed
        val action = when {
            limitReached && canRollback -> RecoveryAction.AUTO_ROLLBACK
            limitReached -> RecoveryAction.EXTERNAL_RECOVERY
            else -> RecoveryAction.RESUME_REBOOT
        }
        return RecoveryDecision(
            action = action,
            reasons = reasons,
            allowed = allowed,
            blocked = blocked,
            titleKey = if (action == RecoveryAction.EXTERNAL_RECOVERY) {
                RecoveryCopyKeys.TITLE_EXTERNAL
            } else {
                RecoveryCopyKeys.TITLE_REBOOT
            },
            detailKey = if (action == RecoveryAction.EXTERNAL_RECOVERY) {
                RecoveryCopyKeys.DETAIL_EXTERNAL
            } else {
                RecoveryCopyKeys.DETAIL_REBOOT
            },
            nextStepKey = when (action) {
                RecoveryAction.AUTO_ROLLBACK -> RecoveryCopyKeys.NEXT_ROLLBACK
                RecoveryAction.EXTERNAL_RECOVERY -> RecoveryCopyKeys.NEXT_EXTERNAL
                else -> RecoveryCopyKeys.NEXT_REBOOT
            },
            autoRecoverable = action == RecoveryAction.AUTO_ROLLBACK,
            requiresExternalImage = action == RecoveryAction.EXTERNAL_RECOVERY,
            diagnosticOnly = false,
            switchId = input.head?.switchId,
        )
    }

    private fun verifying(input: RecoveryInput): RecoveryDecision {
        if (input.bootIdChanged) {
            return RecoveryDecision(
                action = RecoveryAction.AUTO_VERIFY,
                reasons = listOf(RecoveryReason.VERIFY_PENDING),
                allowed = setOf(RecoveryControl.VERIFY, RecoveryControl.EXPORT_DIAGNOSTICS),
                blocked = WRITE_CONTROLS - setOf(RecoveryControl.VERIFY),
                titleKey = RecoveryCopyKeys.TITLE_REBOOT,
                detailKey = RecoveryCopyKeys.DETAIL_VERIFY,
                nextStepKey = RecoveryCopyKeys.NEXT_VERIFY,
                autoRecoverable = true,
                requiresExternalImage = false,
                diagnosticOnly = false,
                switchId = input.head?.switchId,
            )
        }
        return RecoveryDecision(
            action = RecoveryAction.RESUME_REBOOT,
            reasons = listOf(RecoveryReason.REBOOT_NOT_OBSERVED),
            allowed = setOf(RecoveryControl.REBOOT, RecoveryControl.EXPORT_DIAGNOSTICS)
                .let { if (canAutoRollback(input)) it + RecoveryControl.ROLLBACK else it },
            blocked = WRITE_CONTROLS - setOf(RecoveryControl.REBOOT, RecoveryControl.ROLLBACK),
            titleKey = RecoveryCopyKeys.TITLE_REBOOT,
            detailKey = RecoveryCopyKeys.DETAIL_REBOOT,
            nextStepKey = RecoveryCopyKeys.NEXT_REBOOT,
            autoRecoverable = false,
            requiresExternalImage = false,
            diagnosticOnly = false,
            switchId = input.head?.switchId,
        )
    }

    private fun terminal(input: RecoveryInput, state: String): RecoveryDecision {
        val reasons = mutableListOf(
            when (state) {
                SwitchStateNames.VERIFIED -> RecoveryReason.VERIFIED
                SwitchStateNames.ROLLED_BACK -> RecoveryReason.ROLLED_BACK
                SwitchStateNames.FAILED_PRE_WRITE -> RecoveryReason.FAILED_PRE_WRITE
                else -> RecoveryReason.CANCELLED
            },
        )
        reasons += baselineReasons(input)
        val blocked = linkedSetOf<RecoveryControl>()
        if (input.baselineState != BaselineState.PRESENT_OK) blocked += RecoveryControl.SWITCH
        val importBaseline = if (input.baselineState != BaselineState.PRESENT_OK) {
            setOf(RecoveryControl.IMPORT_BASELINE)
        } else {
            emptySet()
        }
        return RecoveryDecision(
            action = RecoveryAction.NONE,
            reasons = reasons.distinct(),
            allowed = READ_ONLY_SET + importBaseline,
            blocked = blocked,
            titleKey = RecoveryCopyKeys.TITLE_NONE,
            detailKey = RecoveryCopyKeys.DETAIL_NONE,
            nextStepKey = if (importBaseline.isNotEmpty()) {
                RecoveryCopyKeys.NEXT_IMPORT_BASELINE
            } else {
                RecoveryCopyKeys.NEXT_NONE
            },
            autoRecoverable = false,
            requiresExternalImage = false,
            diagnosticOnly = false,
            switchId = input.head?.switchId,
        )
    }

    private fun recoveryRequired(input: RecoveryInput): RecoveryDecision {
        val reasons = mutableListOf(RecoveryReason.RECOVERY_REQUIRED)
        if (input.baselineState != BaselineState.PRESENT_OK) reasons += baselineReasons(input)
        if (!input.rootAvailable) reasons += RecoveryReason.NO_ROOT_CHANNEL
        if (input.deviceMismatch) reasons += RecoveryReason.DEVICE_MISMATCH
        if (input.bootVerifyFailures >= MAX_VERIFY_FAILURES) reasons += RecoveryReason.VERIFY_FAILED_TWICE
        if (canAutoRollback(input)) reasons += RecoveryReason.ROLLBACK_AVAILABLE

        // 1) 无 root：设备外恢复（不自动写）
        if (!input.rootAvailable) {
            return external(input, reasons + RecoveryReason.NO_ROOT_CHANNEL, allowImportBaseline = false)
        }
        // 2) 槽位已变化：写回会打错分区 → 禁止自动，只导出
        if (input.deviceMismatch) {
            return forbidden(input, reasons, extraAllowed = setOf(RecoveryControl.EXPORT_DIAGNOSTICS))
        }
        // 3) baseline 不可用：回滚目标不可验证 → 需外部镜像；允许导入 baseline
        if (input.baselineState != BaselineState.PRESENT_OK) {
            return external(input, reasons, allowImportBaseline = true)
        }
        // 4) 连续确认失败 ≥2：禁止无限重试，但允许用户显式回滚（root+baseline 均满足）
        if (input.bootVerifyFailures >= MAX_VERIFY_FAILURES) {
            return RecoveryDecision(
                action = RecoveryAction.FORBIDDEN,
                reasons = reasons,
                allowed = setOf(RecoveryControl.ROLLBACK, RecoveryControl.EXPORT_DIAGNOSTICS),
                blocked = WRITE_CONTROLS - setOf(RecoveryControl.ROLLBACK) + RecoveryControl.SWITCH +
                    RecoveryControl.INSTALL + RecoveryControl.MODULE + RecoveryControl.FLASH,
                titleKey = RecoveryCopyKeys.TITLE_FORBIDDEN,
                detailKey = RecoveryCopyKeys.DETAIL_FORBIDDEN,
                nextStepKey = RecoveryCopyKeys.NEXT_ROLLBACK,
                autoRecoverable = false,
                requiresExternalImage = false,
                diagnosticOnly = false,
                switchId = input.head?.switchId,
            )
        }
        // 5) root + PRESENT_OK baseline：可自动回滚
        return RecoveryDecision(
            action = RecoveryAction.AUTO_ROLLBACK,
            reasons = reasons,
            allowed = setOf(RecoveryControl.ROLLBACK, RecoveryControl.EXPORT_DIAGNOSTICS),
            blocked = WRITE_CONTROLS - setOf(RecoveryControl.ROLLBACK),
            titleKey = RecoveryCopyKeys.TITLE_ROLLBACK,
            detailKey = RecoveryCopyKeys.DETAIL_ROLLBACK,
            nextStepKey = RecoveryCopyKeys.NEXT_ROLLBACK,
            autoRecoverable = true,
            requiresExternalImage = false,
            diagnosticOnly = false,
            switchId = input.head?.switchId,
        )
    }

    private fun external(
        input: RecoveryInput,
        reasons: List<RecoveryReason>,
        allowImportBaseline: Boolean,
    ): RecoveryDecision = RecoveryDecision(
        action = RecoveryAction.EXTERNAL_RECOVERY,
        reasons = reasons.distinct(),
        allowed = READ_ONLY_SET +
            (if (allowImportBaseline) setOf(RecoveryControl.IMPORT_BASELINE) else emptySet()),
        blocked = WRITE_CONTROLS,
        titleKey = RecoveryCopyKeys.TITLE_EXTERNAL,
        detailKey = RecoveryCopyKeys.DETAIL_EXTERNAL,
        nextStepKey = RecoveryCopyKeys.NEXT_EXTERNAL,
        autoRecoverable = false,
        requiresExternalImage = true,
        diagnosticOnly = false,
        switchId = input.head?.switchId,
    )

    private fun forbidden(
        input: RecoveryInput,
        reasons: List<RecoveryReason>,
        extraAllowed: Set<RecoveryControl> = emptySet(),
    ): RecoveryDecision = RecoveryDecision(
        action = RecoveryAction.FORBIDDEN,
        reasons = reasons.distinct() + baselineReasons(input),
        allowed = setOf(RecoveryControl.EXPORT_DIAGNOSTICS) + extraAllowed,
        blocked = WRITE_CONTROLS + setOf(RecoveryControl.SWITCH, RecoveryControl.INSTALL,
            RecoveryControl.MODULE, RecoveryControl.FLASH),
        titleKey = RecoveryCopyKeys.TITLE_FORBIDDEN,
        detailKey = RecoveryCopyKeys.DETAIL_FORBIDDEN,
        nextStepKey = RecoveryCopyKeys.NEXT_DIAGNOSE,
        autoRecoverable = false,
        requiresExternalImage = false,
        diagnosticOnly = true,
        switchId = input.head?.switchId,
    )

    // ------------------------------------------------------------------ 工具

    private fun canAutoRollback(input: RecoveryInput): Boolean =
        input.rootAvailable && input.baselineState == BaselineState.PRESENT_OK

    private fun baselineReasons(input: RecoveryInput): List<RecoveryReason> = when (input.baselineState) {
        BaselineState.PRESENT_OK -> listOf(RecoveryReason.BASELINE_OK)
        BaselineState.MISSING_NEVER_CAPTURED -> listOf(RecoveryReason.BASELINE_MISSING)
        BaselineState.IMPORT_REQUIRED -> listOf(RecoveryReason.BASELINE_IMPORT_REQUIRED)
        BaselineState.STALE -> listOf(RecoveryReason.BASELINE_STALE)
        BaselineState.CORRUPT -> listOf(RecoveryReason.BASELINE_CORRUPT)
    }

    const val MAX_VERIFY_FAILURES = 2
    const val MAX_REBOOT_REQUESTS = 2
}
