package dev.maplesu.manager.workmode.switch

import dev.maplesu.manager.workmode.WorkMode

/**
 * H5：隐藏状态 × 双模式切换的纯策略（主机可测，无 Android 依赖）。
 *
 * 背景（主文档 / Stealth.kt / StealthPathPolicy.kt）：
 * - KSU 隐身是**内核 stealth**（GET_INFO 不上报 MANAGER → 管理器 UI 伪装未安装，密令恢复）；
 * - Lite 即将有独立 App 级隐藏（密令恢复）；
 * - 隐藏开着时用户可能"看不到切换入口"，因此切换前后必须保证**恢复通道可验证**，
 *   并且不得在隐藏 ON 时静默开始切换（UI 二次确认）。
 *
 * 本策略只做判定；真正的"关隐藏/恢复隐藏"由 [HiddenSwitchCoordinator] 调端口执行。
 */
enum class HiddenState { ON, OFF, UNKNOWN }

/** 隐藏由谁提供（用于 UI 文案/诊断；不影响判定）。 */
enum class HiddenOwner { KSU_STEALTH, LITE_HIDDEN }

/**
 * 恢复通道事实（全部为"已验证"才算可用；configured 仅用于文案）。
 * 与 StealthCodeStore/StealthReceiver（A）/ webadmin（B）对齐。
 */
data class HiddenRecoveryFacts(
    val secretCodeConfigured: Boolean = false,
    /** 最近一次用真实密令验证成功（或默认密令由接收器构造性接受）。 */
    val secretCodeVerified: Boolean = false,
    val webAdminAvailable: Boolean = false,
    val webAdminVerified: Boolean = false,
    val externalRecoveryAvailable: Boolean = false,
    val externalRecoveryVerified: Boolean = false,
) {
    /** 至少一条**验证可用**的恢复通道。 */
    val usableChannels: List<String>
        get() = buildList {
            if (secretCodeConfigured && secretCodeVerified) add("SECRET_CODE")
            if (webAdminAvailable && webAdminVerified) add("WEB_ADMIN")
            if (externalRecoveryAvailable && externalRecoveryVerified) add("EXTERNAL_BACKUP")
        }

    val anyUsable: Boolean get() = usableChannels.isNotEmpty()
}

/** 一次切换的隐藏输入（双向对称）。 */
data class HiddenSwitchInput(
    val fromMode: WorkMode,
    val toMode: WorkMode,
    /** 源模式当前隐藏状态；null = 该模式没有隐藏能力（按 OFF 处理）。 */
    val fromHidden: HiddenState? = HiddenState.OFF,
    /** 目标模式此前持久化的隐藏状态（切回时待恢复）；null = 从未开启。 */
    val targetSavedHidden: HiddenState? = HiddenState.OFF,
    val recovery: HiddenRecoveryFacts = HiddenRecoveryFacts(),
    val pendingSwitch: Boolean = false,
    val pendingInstall: Boolean = false,
) {
    init {
        require(fromMode != toMode) { HiddenSwitchCodes.HIDDEN_INPUT_INVALID }
    }

    val fromIsHidden: Boolean get() = fromHidden == HiddenState.ON
    val targetWasHidden: Boolean get() = targetSavedHidden == HiddenState.ON
}

enum class HiddenSwitchAction {
    /** 切换开始前显式关闭源模式隐藏（内核 stealth/App 隐藏），并回读确认。 */
    UNHIDE_SOURCE_BEFORE_COMMIT,

    /** 切换验证通过后把目标模式隐藏复位为 OFF（不继承源模式）。 */
    RESET_TARGET_HIDDEN_AFTER_VERIFY,

    /** 切回时按该模式独立持久化恢复原隐藏（仅在恢复通道仍可用时）。 */
    RESTORE_TARGET_HIDDEN_AFTER_VERIFY,
}

sealed interface HiddenSwitchDecision {
    /**
     * 允许推进。`requiresConfirmation=true` 表示隐藏 ON：UI 必须展示风险并二次确认；
     * `actions` 是执行器必须完成的隐藏动作（顺序固定）。
     */
    data class Allowed(
        val requiresConfirmation: Boolean,
        val actions: List<HiddenSwitchAction>,
        val reasons: List<HiddenSwitchBlocker> = emptyList(),
    ) : HiddenSwitchDecision

    data class MustUnhideFirst(val blocker: HiddenSwitchBlocker) : HiddenSwitchDecision

    data class MustConfigureRecovery(val blocker: HiddenSwitchBlocker, val channels: List<String>) :
        HiddenSwitchDecision

    data class Block(val blocker: HiddenSwitchBlocker) : HiddenSwitchDecision
}

data class HiddenSwitchBlocker(val code: String, val detail: String)

object HiddenSwitchCodes {
    const val HIDDEN_INPUT_INVALID = "HIDDEN_INPUT_INVALID"
    const val HIDDEN_PENDING_SWITCH = "HIDDEN_PENDING_SWITCH"
    const val HIDDEN_PENDING_INSTALL = "HIDDEN_PENDING_INSTALL"
    const val HIDDEN_STATE_UNKNOWN = "HIDDEN_STATE_UNKNOWN"
    const val HIDDEN_RECOVERY_NOT_CONFIGURED = "HIDDEN_RECOVERY_NOT_CONFIGURED"
    const val HIDDEN_SWITCH_CONFIRMATION_REQUIRED = "HIDDEN_SWITCH_CONFIRMATION_REQUIRED"
    const val HIDDEN_UNHIDE_FAILED = "HIDDEN_UNHIDE_FAILED"
    const val HIDDEN_TARGET_RESET_FAILED = "HIDDEN_TARGET_RESET_FAILED"
    const val HIDDEN_RESTORE_FAILED = "HIDDEN_RESTORE_FAILED"
    const val HIDDEN_RESTORE_CHANNEL_LOST = "HIDDEN_RESTORE_CHANNEL_LOST"
}

object HiddenSwitchPolicy {

    fun evaluate(input: HiddenSwitchInput): HiddenSwitchDecision {
        // 读不到隐藏状态 = 可能开着（安全方向：不假设 OFF，也不静默切换）。
        if (input.fromHidden == HiddenState.UNKNOWN || input.targetSavedHidden == HiddenState.UNKNOWN) {
            return HiddenSwitchDecision.Block(
                HiddenSwitchBlocker(HiddenSwitchCodes.HIDDEN_STATE_UNKNOWN, "hidden state unreadable"),
            )
        }
        val requiresRecovery = input.fromIsHidden || input.targetWasHidden
        if (requiresRecovery && !input.recovery.anyUsable) {
            return HiddenSwitchDecision.MustConfigureRecovery(
                HiddenSwitchBlocker(
                    HiddenSwitchCodes.HIDDEN_RECOVERY_NOT_CONFIGURED,
                    "hidden=${input.fromHidden}/${input.targetSavedHidden} " +
                        "configured=${input.recovery.secretCodeConfigured}",
                ),
                input.recovery.usableChannels,
            )
        }
        val actions = mutableListOf<HiddenSwitchAction>()
        if (input.fromIsHidden) actions += HiddenSwitchAction.UNHIDE_SOURCE_BEFORE_COMMIT
        if (input.targetWasHidden) {
            // 切回时要恢复目标模式原隐藏；恢复通道已在上面验证。
            actions += HiddenSwitchAction.RESTORE_TARGET_HIDDEN_AFTER_VERIFY
        } else {
            // 目标模式默认 OFF（不继承源模式隐藏）。
            actions += HiddenSwitchAction.RESET_TARGET_HIDDEN_AFTER_VERIFY
        }
        return HiddenSwitchDecision.Allowed(
            requiresConfirmation = input.fromIsHidden,
            actions = actions,
            reasons = buildList {
                // Journal state is recovery evidence, not a running partition writer.
                if (input.pendingSwitch) add(HiddenSwitchBlocker(
                    HiddenSwitchCodes.HIDDEN_PENDING_SWITCH, "previous switch record",
                ))
                if (input.pendingInstall) add(HiddenSwitchBlocker(
                    HiddenSwitchCodes.HIDDEN_PENDING_INSTALL, "previous install record",
                ))
            },
        )
    }
}
