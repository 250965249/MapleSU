package dev.maplesu.manager.workmode.ui

import dev.maplesu.manager.workmode.ModeCapabilities
import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** W18 三卡能力门控矩阵（纯 JVM）。 */
class BFeatureCardsTest {

    private val lite = ModeCapabilities.forMode(WorkMode.LITE)
    private val ksu = ModeCapabilities.forMode(WorkMode.KSU)
    private val none = ModeCapabilities.NONE

    @Test
    fun liteHidesAllThreeCardsAndReadsNothingMeaningful() {
        val cards = BFeaturePolicy.evaluate(lite, stealthRaw = -1, appLockRaw = -1, webAdminEnabledPref = false)
        assertFalse(cards.stealth.show)
        assertFalse(cards.appLock.show)
        assertFalse(cards.webAdmin.show)
    }

    @Test
    fun unresolvedCapabilitiesHideAllThreeCards() {
        val cards = BFeaturePolicy.evaluate(none, 0, 0, true)
        assertFalse(cards.stealth.show)
        assertFalse(cards.appLock.show)
        assertFalse(cards.webAdmin.show)
    }

    @Test
    fun ksuStealthIsOperableWhenKernelStateReadable() {
        val on = BFeaturePolicy.evaluate(ksu, stealthRaw = 1, appLockRaw = -1, webAdminEnabledPref = false)
        assertTrue(on.stealth.show)
        assertTrue(on.stealth.operable)
        assertTrue(on.stealth.enabled)

        val off = BFeaturePolicy.evaluate(ksu, stealthRaw = 0, appLockRaw = -1, webAdminEnabledPref = false)
        assertTrue(off.stealth.operable)
        assertFalse(off.stealth.enabled)
    }

    @Test
    fun ksuStealthUnreadableShowsDisabledWithReason() {
        val cards = BFeaturePolicy.evaluate(ksu, stealthRaw = -1, appLockRaw = -1, webAdminEnabledPref = false)
        assertTrue(cards.stealth.show)
        assertFalse(cards.stealth.operable)
        assertEquals(BFeatureReasons.KERNEL_UNREADABLE, cards.stealth.reasonCode)
    }

    @Test
    fun appLockIsAlwaysHonestlyUnavailableInV1() {
        for (raw in listOf(-1, 0, 1)) {
            val cards = BFeaturePolicy.evaluate(ksu, stealthRaw = 0, appLockRaw = raw, webAdminEnabledPref = false)
            assertTrue(cards.appLock.show)
            assertFalse("v1 kernel deprecates app lock (raw=$raw)", cards.appLock.operable)
            assertEquals(BFeatureReasons.KERNEL_DEPRECATED, cards.appLock.reasonCode)
        }
    }

    @Test
    fun webAdminFollowsCapabilityAndPref() {
        val enabled = BFeaturePolicy.evaluate(ksu, 0, -1, webAdminEnabledPref = true)
        assertTrue(enabled.webAdmin.show)
        assertTrue(enabled.webAdmin.operable)
        assertTrue(enabled.webAdmin.enabled)

        val disabled = BFeaturePolicy.evaluate(ksu, 0, -1, webAdminEnabledPref = false)
        assertFalse(disabled.webAdmin.enabled)
    }

    @Test
    fun stealthToggleOnLiteCanNeverBeOperable() {
        val cards = BFeaturePolicy.evaluate(lite, stealthRaw = 1, appLockRaw = 0, webAdminEnabledPref = true)
        assertFalse(cards.stealth.show)
        // 即便内核读数看起来"可读"，LITE 下也不显示/不可操作（能力位为唯一来源）。
        assertFalse(cards.stealth.operable)
    }
}
