package dev.maplesu.manager.workmode.switch

import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * H5：隐藏状态 × 双模式切换策略矩阵（host，双向对称）。
 * 覆盖：ON/OFF/UNKNOWN、恢复通道缺失/验证、双向、pending、二次确认、切后默认 OFF/切回恢复。
 */
class HiddenSwitchPolicyTest {

    private fun facts(
        code: Boolean = false,
        web: Boolean = false,
        backup: Boolean = false,
    ) = HiddenRecoveryFacts(
        secretCodeConfigured = code,
        secretCodeVerified = code,
        webAdminAvailable = web,
        webAdminVerified = web,
        externalRecoveryAvailable = backup,
        externalRecoveryVerified = backup,
    )

    private fun input(
        from: WorkMode = WorkMode.LITE,
        to: WorkMode = WorkMode.KSU,
        fromHidden: HiddenState? = HiddenState.OFF,
        targetSaved: HiddenState? = HiddenState.OFF,
        recovery: HiddenRecoveryFacts = facts(),
        pendingSwitch: Boolean = false,
        pendingInstall: Boolean = false,
    ) = HiddenSwitchInput(
        fromMode = from, toMode = to, fromHidden = fromHidden,
        targetSavedHidden = targetSaved, recovery = recovery,
        pendingSwitch = pendingSwitch, pendingInstall = pendingInstall,
    )

    private fun HiddenSwitchDecision.blocker(): HiddenSwitchBlocker = when (this) {
        is HiddenSwitchDecision.Block -> blocker
        is HiddenSwitchDecision.MustConfigureRecovery -> blocker
        is HiddenSwitchDecision.MustUnhideFirst -> blocker
        is HiddenSwitchDecision.Allowed -> error("Allowed has no blocker")
    }

    // ------------------------------------------------------------------ 矩阵

    @Test
    fun bothOffWithNoRecoveryIsAllowedWithoutConfirmation() {
        val decision = HiddenSwitchPolicy.evaluate(input())
        assertTrue(decision is HiddenSwitchDecision.Allowed)
        val allowed = decision as HiddenSwitchDecision.Allowed
        assertFalse(allowed.requiresConfirmation)
        assertTrue(HiddenSwitchAction.UNHIDE_SOURCE_BEFORE_COMMIT !in allowed.actions)
        assertTrue(HiddenSwitchAction.RESET_TARGET_HIDDEN_AFTER_VERIFY in allowed.actions)
    }

    @Test
    fun bothDirectionsAreSymmetric() {
        for ((from, to) in listOf(WorkMode.LITE to WorkMode.KSU, WorkMode.KSU to WorkMode.LITE)) {
            val hiddenOn = HiddenSwitchPolicy.evaluate(
                input(from = from, to = to, fromHidden = HiddenState.ON, recovery = facts(code = true)),
            )
            assertTrue("$from->$to", hiddenOn is HiddenSwitchDecision.Allowed)
            assertTrue((hiddenOn as HiddenSwitchDecision.Allowed).requiresConfirmation)
            assertTrue(HiddenSwitchAction.UNHIDE_SOURCE_BEFORE_COMMIT in hiddenOn.actions)

            val missingRecovery = HiddenSwitchPolicy.evaluate(
                input(from = from, to = to, fromHidden = HiddenState.ON),
            )
            assertTrue("$from->$to", missingRecovery is HiddenSwitchDecision.MustConfigureRecovery)
            assertEquals(HiddenSwitchCodes.HIDDEN_RECOVERY_NOT_CONFIGURED,
                (missingRecovery as HiddenSwitchDecision.MustConfigureRecovery).blocker.code)
        }
    }

    @Test
    fun hiddenOnWithoutVerifiedRecoveryMustConfigureFirst() {
        // 只"配置了"但没验证 → 不算可用。
        val unverified = HiddenSwitchPolicy.evaluate(
            input(fromHidden = HiddenState.ON, recovery = HiddenRecoveryFacts(secretCodeConfigured = true)),
        )
        assertTrue(unverified is HiddenSwitchDecision.MustConfigureRecovery)

        val webVerified = HiddenSwitchPolicy.evaluate(
            input(fromHidden = HiddenState.ON, recovery = facts(web = true)),
        )
        assertTrue(webVerified is HiddenSwitchDecision.Allowed)

        val backupVerified = HiddenSwitchPolicy.evaluate(
            input(fromHidden = HiddenState.ON, recovery = facts(backup = true)),
        )
        assertTrue(backupVerified is HiddenSwitchDecision.Allowed)
    }

    @Test
    fun hiddenOnAlwaysRequiresExplicitConfirmation() {
        val allowed = HiddenSwitchPolicy.evaluate(
            input(fromHidden = HiddenState.ON, recovery = facts(code = true)),
        ) as HiddenSwitchDecision.Allowed
        assertTrue(allowed.requiresConfirmation)
    }

    @Test
    fun unknownHiddenStateBlocksInsteadOfAssumingOff() {
        for (unknown in listOf(HiddenState.UNKNOWN)) {
            val decision = HiddenSwitchPolicy.evaluate(input(fromHidden = unknown))
            assertTrue(decision is HiddenSwitchDecision.Block)
            assertEquals(HiddenSwitchCodes.HIDDEN_STATE_UNKNOWN, decision.blocker().code)
        }
        val targetUnknown = HiddenSwitchPolicy.evaluate(input(targetSaved = HiddenState.UNKNOWN))
        assertTrue(targetUnknown is HiddenSwitchDecision.Block)
    }

    @Test
    fun savedHiddenOnTargetNeedsRecoveryForSwitchBack() {
        val noRecovery = HiddenSwitchPolicy.evaluate(input(targetSaved = HiddenState.ON))
        assertTrue(noRecovery is HiddenSwitchDecision.MustConfigureRecovery)
        val withRecovery = HiddenSwitchPolicy.evaluate(
            input(targetSaved = HiddenState.ON, recovery = facts(code = true)),
        ) as HiddenSwitchDecision.Allowed
        assertTrue(HiddenSwitchAction.RESTORE_TARGET_HIDDEN_AFTER_VERIFY in withRecovery.actions)
        assertTrue(HiddenSwitchAction.RESET_TARGET_HIDDEN_AFTER_VERIFY !in withRecovery.actions)
        // 源模式 OFF + 目标曾 ON：不要求二次确认（只有源隐藏 ON 需要确认）。
        assertFalse(withRecovery.requiresConfirmation)
    }

    @Test
    fun historicalPendingRecordsRemainVisibleWithoutBlockingEitherDirection() {
        for ((from, to) in listOf(WorkMode.LITE to WorkMode.KSU, WorkMode.KSU to WorkMode.LITE)) {
            for (install in listOf(false, true)) for (switch in listOf(false, true)) {
                val decision = HiddenSwitchPolicy.evaluate(input(
                    from = from, to = to, pendingSwitch = switch, pendingInstall = install,
                ))
                assertTrue("$from->$to install=$install switch=$switch", decision is HiddenSwitchDecision.Allowed)
                val reasons = (decision as HiddenSwitchDecision.Allowed).reasons.map { it.code }
                assertEquals(switch, HiddenSwitchCodes.HIDDEN_PENDING_SWITCH in reasons)
                assertEquals(install, HiddenSwitchCodes.HIDDEN_PENDING_INSTALL in reasons)
                assertFalse(decision.requiresConfirmation)
            }
        }
    }

    // ------------------------------------------------------------------ coordinator

    private class FakeController : HiddenStateController {
        val states = mutableMapOf(WorkMode.LITE to HiddenState.OFF, WorkMode.KSU to HiddenState.OFF)
        var failSetOff = false
        var failSetOn = false
        val calls = mutableListOf<String>()

        override fun state(mode: WorkMode): HiddenState = states.getValue(mode)

        override fun setOff(mode: WorkMode): HookResult {
            calls += "off:${mode.suffix}"
            if (failSetOff) return HookResult.failed("", "injected")
            states[mode] = HiddenState.OFF
            return HookResult.OK
        }

        override fun setOn(mode: WorkMode): HookResult {
            calls += "on:${mode.suffix}"
            if (failSetOn) return HookResult.failed("", "injected")
            states[mode] = HiddenState.ON
            return HookResult.OK
        }
    }

    private class FakeStore : HiddenStateStore {
        val saved = mutableMapOf<WorkMode, HiddenState>()
        override fun saved(mode: WorkMode): HiddenState = saved[mode] ?: HiddenState.OFF
        override fun save(mode: WorkMode, state: HiddenState) {
            saved[mode] = state
        }
    }

    private class Harness(
        var recovery: HiddenRecoveryFacts = HiddenRecoveryFacts(
            secretCodeConfigured = true, secretCodeVerified = true,
        ),
    ) {
        val controller = FakeController()
        val store = FakeStore()
        val coordinator = HiddenSwitchCoordinator(controller, store) { recovery }
    }

    @Test
    fun beforeSwitchRequiresConfirmationThenUnhidesAndPersistsSourceState() {
        val h = Harness().also { h -> h.controller.states[WorkMode.LITE] = HiddenState.ON }
        val rejected = h.coordinator.beforeSwitch(WorkMode.LITE, WorkMode.KSU, confirmed = false)
        assertFalse(rejected.ok)
        assertEquals(HiddenSwitchCodes.HIDDEN_SWITCH_CONFIRMATION_REQUIRED, rejected.code)
        assertEquals(HiddenState.ON, h.controller.state(WorkMode.LITE)) // 未确认不动隐藏

        val accepted = h.coordinator.beforeSwitch(WorkMode.LITE, WorkMode.KSU, confirmed = true)
        assertTrue(accepted.ok)
        assertEquals(HiddenState.OFF, h.controller.state(WorkMode.LITE))
        assertEquals(HiddenState.ON, h.store.saved[WorkMode.LITE])
    }

    @Test
    fun beforeSwitchFailsClosedWhenUnhideCannotBeProven() {
        val h = Harness().apply {
            controller.states[WorkMode.LITE] = HiddenState.ON
            controller.failSetOff = true
        }
        val result = h.coordinator.beforeSwitch(WorkMode.LITE, WorkMode.KSU, confirmed = true)
        assertFalse(result.ok)
        assertEquals(HiddenSwitchCodes.HIDDEN_UNHIDE_FAILED, result.code)
    }

    @Test
    fun beforeSwitchBlocksWhenRecoveryMissingInsteadOfSilentlySwitching() {
        val h = Harness().apply {
            controller.states[WorkMode.LITE] = HiddenState.ON
            recovery = HiddenRecoveryFacts()
        }
        val result = h.coordinator.beforeSwitch(WorkMode.LITE, WorkMode.KSU, confirmed = true)
        assertFalse(result.ok)
        assertEquals(HiddenSwitchCodes.HIDDEN_RECOVERY_NOT_CONFIGURED, result.code)
    }

    @Test
    fun afterVerifiedResetsTargetToOffByDefault() {
        val h = Harness()
        h.coordinator.beforeSwitch(WorkMode.LITE, WorkMode.KSU, confirmed = true)
        val result = h.coordinator.afterVerified(WorkMode.KSU)
        assertTrue(result.ok)
        assertEquals(HiddenState.OFF, h.controller.state(WorkMode.KSU))
        assertTrue(h.controller.calls.contains("off:B"))
    }

    @Test
    fun afterVerifiedRestoresSavedHiddenWhenSwitchBackAndChannelStillUsable() {
        val h = Harness()
        h.store.save(WorkMode.LITE, HiddenState.ON) // 之前从 A 切出时留存
        h.coordinator.beforeSwitch(WorkMode.KSU, WorkMode.LITE, confirmed = true)
        val result = h.coordinator.afterVerified(WorkMode.LITE)
        assertTrue(result.ok)
        assertEquals(HiddenState.ON, h.controller.state(WorkMode.LITE))
        assertTrue(h.controller.calls.contains("on:A"))
    }

    @Test
    fun afterVerifiedFailsClosedWhenRecoveryChannelLostAfterSwitch() {
        val h = Harness()
        h.store.save(WorkMode.LITE, HiddenState.ON)
        h.recovery = HiddenRecoveryFacts() // 切换后恢复通道失效
        val result = h.coordinator.afterVerified(WorkMode.LITE)
        assertFalse(result.ok)
        assertEquals(HiddenSwitchCodes.HIDDEN_RESTORE_CHANNEL_LOST, result.code)
        assertEquals(HiddenState.OFF, h.controller.state(WorkMode.LITE))
    }

    @Test
    fun afterVerifiedReportsRestoreAndResetFailures() {
        val h = Harness().apply {
            store.save(WorkMode.LITE, HiddenState.ON)
            controller.failSetOn = true
        }
        assertEquals(HiddenSwitchCodes.HIDDEN_RESTORE_FAILED, h.coordinator.afterVerified(WorkMode.LITE).code)

        val h2 = Harness().apply { controller.failSetOff = true }
        assertEquals(HiddenSwitchCodes.HIDDEN_TARGET_RESET_FAILED, h2.coordinator.afterVerified(WorkMode.KSU).code)
    }

    @Test
    fun coordinatorBlocksPendingAndUnknownWithoutTouchingHidden() {
        val h = Harness().apply { controller.states[WorkMode.LITE] = HiddenState.UNKNOWN }
        val result = h.coordinator.beforeSwitch(WorkMode.LITE, WorkMode.KSU, confirmed = true)
        assertFalse(result.ok)
        assertEquals(HiddenSwitchCodes.HIDDEN_STATE_UNKNOWN, result.code)
        assertTrue(h.controller.calls.isEmpty())
    }
}
