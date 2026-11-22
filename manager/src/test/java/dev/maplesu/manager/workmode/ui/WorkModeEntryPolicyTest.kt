package dev.maplesu.manager.workmode.ui

import dev.maplesu.manager.workmode.detect.ModeState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 三入口可见性判定表。 */
class WorkModeEntryPolicyTest {

    @Test
    fun activeModesShowAllThreeEntries() {
        for (state in listOf(
            ModeState.MODE_A_ACTIVE,
            ModeState.MODE_B_ACTIVE,
            ModeState.MODE_B_KERNEL_ONLY,
            ModeState.MODE_A_INSTALLED_UNBOUND,
        )) {
            assertEquals(state.name, WorkModeEntryPolicy.ALL, decideWorkModeEntry(state, stealthLooksStealthy = false, pendingSwitch = false))
        }
    }

    @Test
    fun foreignRootHidesHomeCardOnly() {
        assertEquals(
            WorkModeEntryPolicy.SETTINGS_ONLY,
            decideWorkModeEntry(ModeState.FOREIGN_SU, stealthLooksStealthy = false, pendingSwitch = false),
        )
    }

    @Test
    fun notInstalledAndIndeterminateHideEverything() {
        for (state in listOf(ModeState.NOT_INSTALLED, ModeState.INDETERMINATE)) {
            assertFalse(decideWorkModeEntry(state, stealthLooksStealthy = false, pendingSwitch = false).showHomeCard)
            assertFalse(decideWorkModeEntry(state, stealthLooksStealthy = false, pendingSwitch = false).showInstallCard)
            assertFalse(decideWorkModeEntry(state, stealthLooksStealthy = false, pendingSwitch = false).showSettingsRow)
        }
    }

    @Test
    fun stealthHidesEveryEntryForAnyState() {
        for (state in ModeState.entries) {
            for (pending in listOf(false, true)) {
                assertEquals(state.name, WorkModeEntryPolicy.NONE, decideWorkModeEntry(state, stealthLooksStealthy = true, pendingSwitch = pending))
            }
        }
    }

    @Test
    fun pendingSwitchForcesRecoveryEntries() {
        assertEquals(
            WorkModeEntryPolicy.ALL,
            decideWorkModeEntry(ModeState.INDETERMINATE, stealthLooksStealthy = false, pendingSwitch = true),
        )
        assertTrue(decideWorkModeEntry(ModeState.NOT_INSTALLED, stealthLooksStealthy = false, pendingSwitch = true).showSettingsRow)
    }

    // 2026-10-31 真机缺陷：Ultra（LITE）下 `Stealth.looksStealthy()` 恒 true（KSU stealth 不存在），
    // 导致首页入口被永久隐藏、工作模式页说“隐身模式下不显示工作模式信息”。隐藏信号必须按模式取。
    @Test
    fun hiddenMaskIsModeAwareAndNeverBorrowsTheOtherModesSignal() {
        val on = dev.maplesu.manager.workmode.WorkMode.LITE
        val ksu = dev.maplesu.manager.workmode.WorkMode.KSU
        val stealthOn = com.maplesu.core.ui.security.Stealth.State.ON
        val stealthUnknown = com.maplesu.core.ui.security.Stealth.State.UNKNOWN
        val stealthOff = com.maplesu.core.ui.security.Stealth.State.OFF

        // Ultra：只认 Lite 隐藏；KSU stealth 的 UNKNOWN 不能把 Ultra 的入口/页面藏掉。
        assertFalse(workModeHiddenMask(on, liteHiddenOn = false, ksuStealth = stealthUnknown))
        assertTrue(workModeHiddenMask(on, liteHiddenOn = true, ksuStealth = stealthOff))

        // Normal：内核 stealth 明确 OFF 才放行；ON/UNKNOWN 一律按隐藏。
        assertFalse(workModeHiddenMask(ksu, liteHiddenOn = false, ksuStealth = stealthOff))
        assertTrue(workModeHiddenMask(ksu, liteHiddenOn = false, ksuStealth = stealthOn))
        assertTrue(workModeHiddenMask(ksu, liteHiddenOn = false, ksuStealth = stealthUnknown))

        // 模式未判定：不按隐藏（由 INDETERMINATE 自己表达），也不借任何一路信号。
        assertFalse(workModeHiddenMask(null, liteHiddenOn = true, ksuStealth = stealthOn))
    }

    @Test
    fun ultraWithoutLiteHiddenKeepsEveryEntryVisible() {
        val hidden = workModeHiddenMask(
            dev.maplesu.manager.workmode.WorkMode.LITE,
            liteHiddenOn = false,
            ksuStealth = com.maplesu.core.ui.security.Stealth.State.UNKNOWN,
        )
        assertEquals(
            WorkModeEntryPolicy.ALL,
            decideWorkModeEntry(ModeState.MODE_A_ACTIVE, stealthLooksStealthy = hidden, pendingSwitch = false),
        )
    }
}
