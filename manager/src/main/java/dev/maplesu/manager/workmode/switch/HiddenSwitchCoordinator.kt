package dev.maplesu.manager.workmode.switch

import dev.maplesu.manager.workmode.WorkMode

/** 隐藏状态读写端口（生产实现见 `ProductionHiddenSwitchPort`：KSU stealth + 按模式持久化）。 */
interface HiddenStateController {
    fun state(mode: WorkMode): HiddenState

    fun setOff(mode: WorkMode): HookResult

    fun setOn(mode: WorkMode): HookResult
}

/** 按模式独立持久化的隐藏状态（切回时恢复用）。 */
interface HiddenStateStore {
    fun saved(mode: WorkMode): HiddenState

    fun save(mode: WorkMode, state: HiddenState)
}

fun interface HiddenRecoveryFactsProvider {
    fun facts(): HiddenRecoveryFacts
}

data class HiddenSwitchResult(val ok: Boolean, val code: String = "", val detail: String = "") {
    companion object {
        val OK = HiddenSwitchResult(true)
        fun failed(code: String, detail: String = "") = HiddenSwitchResult(false, code, detail)
    }
}

/**
 * H5 执行器：把 [HiddenSwitchPolicy] 的判定落到隐藏开关上，保证"不锁死 + 可恢复"。
 *
 * 关键顺序（与切换事务对齐）：
 * 1. `beforeSwitch`（preflight 通过后、begin 前）：二次确认 → 持久化源模式隐藏供切回 →
 *    关闭源模式隐藏并回读确认（未关掉不得开始写分区）；
 * 2. `afterVerified`（S6 通过后）：目标模式默认 **OFF**（不继承）；若目标模式此前保存过
 *    ON（切回场景），仅当恢复通道**仍验证可用**时恢复，否则显式失败（不静默）。
 */
class HiddenSwitchCoordinator(
    private val controller: HiddenStateController,
    private val store: HiddenStateStore,
    private val recovery: HiddenRecoveryFactsProvider,
) {

    fun evaluate(
        fromMode: WorkMode,
        toMode: WorkMode,
        pendingSwitch: Boolean = false,
        pendingInstall: Boolean = false,
    ): HiddenSwitchDecision = HiddenSwitchPolicy.evaluate(
        HiddenSwitchInput(
            fromMode = fromMode,
            toMode = toMode,
            fromHidden = controller.state(fromMode),
            targetSavedHidden = store.saved(toMode),
            recovery = recovery.facts(),
            pendingSwitch = pendingSwitch,
            pendingInstall = pendingInstall,
        ),
    )

    fun beforeSwitch(fromMode: WorkMode, toMode: WorkMode, confirmed: Boolean): HiddenSwitchResult {
        val decision = evaluate(fromMode, toMode)
        when (decision) {
            is HiddenSwitchDecision.Block ->
                return HiddenSwitchResult.failed(decision.blocker.code, decision.blocker.detail)
            is HiddenSwitchDecision.MustConfigureRecovery ->
                return HiddenSwitchResult.failed(decision.blocker.code, decision.blocker.detail)
            is HiddenSwitchDecision.MustUnhideFirst ->
                return HiddenSwitchResult.failed(decision.blocker.code, decision.blocker.detail)
            is HiddenSwitchDecision.Allowed -> {
                if (decision.requiresConfirmation && !confirmed) {
                    return HiddenSwitchResult.failed(
                        HiddenSwitchCodes.HIDDEN_SWITCH_CONFIRMATION_REQUIRED,
                        "hidden is ON; confirmation required",
                    )
                }
                // 源模式隐藏独立持久化（切回时恢复）。
                val current = controller.state(fromMode)
                if (current == HiddenState.ON) store.save(fromMode, HiddenState.ON)
                if (HiddenSwitchAction.UNHIDE_SOURCE_BEFORE_COMMIT in decision.actions) {
                    val off = controller.setOff(fromMode)
                    if (!off.ok) return HiddenSwitchResult.failed(off.code.ifEmpty {
                        HiddenSwitchCodes.HIDDEN_UNHIDE_FAILED
                    }, off.detail)
                    if (controller.state(fromMode) != HiddenState.OFF) {
                        return HiddenSwitchResult.failed(HiddenSwitchCodes.HIDDEN_UNHIDE_FAILED,
                            "state readback not OFF")
                    }
                }
                return HiddenSwitchResult.OK
            }
        }
    }

    fun afterVerified(toMode: WorkMode): HiddenSwitchResult {
        val saved = store.saved(toMode)
        if (saved == HiddenState.ON) {
            // 切回：恢复原隐藏，但恢复通道必须**仍然**验证可用（防切换后新旧模式都不认恢复码）。
            if (!recovery.facts().anyUsable) {
                return HiddenSwitchResult.failed(HiddenSwitchCodes.HIDDEN_RESTORE_CHANNEL_LOST,
                    "recovery channel lost after switch")
            }
            val on = controller.setOn(toMode)
            if (!on.ok) return HiddenSwitchResult.failed(
                on.code.ifEmpty { HiddenSwitchCodes.HIDDEN_RESTORE_FAILED }, on.detail,
            )
            if (controller.state(toMode) != HiddenState.ON) {
                return HiddenSwitchResult.failed(HiddenSwitchCodes.HIDDEN_RESTORE_FAILED, "readback not ON")
            }
            return HiddenSwitchResult.OK
        }
        // 目标模式默认 OFF（不继承源模式隐藏）。
        val off = controller.setOff(toMode)
        if (!off.ok) return HiddenSwitchResult.failed(
            off.code.ifEmpty { HiddenSwitchCodes.HIDDEN_TARGET_RESET_FAILED }, off.detail,
        )
        if (controller.state(toMode) != HiddenState.OFF) {
            return HiddenSwitchResult.failed(HiddenSwitchCodes.HIDDEN_TARGET_RESET_FAILED, "readback not OFF")
        }
        store.save(toMode, HiddenState.OFF)
        return HiddenSwitchResult.OK
    }
}
