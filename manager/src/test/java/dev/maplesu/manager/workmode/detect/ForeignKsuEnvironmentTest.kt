// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.workmode.detect

import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 「有第三方 KSU 内核、但没装 MapleSU」时必须给出**终态**，而不是永远停在
 * 环境检查未完成（`ENV_UNKNOWN_TIMEOUT`）。
 *
 * 现场：vivo PD2509 / 6.12.58，官方 KernelSU 4.2.0-rc3 在跑；MapleSU 的 JNI 快照读不到
 * 认主状态（`ksuNormal() == null`），旧逻辑直接落 UNKNOWN 且不落盘 ⇒ 首页永远
 * 「环境检查未完成」，用户无法继续安装。本组用例锁住新的判定顺序。
 */
class ForeignKsuEnvironmentTest {

    private companion object {
        const val BOOT = "boot-current"
    }

    private class CountingProbes(
        var ksu: Boolean? = null,
        var foreign: Boolean? = null,
        var su: Boolean = false,
        var ultraThrows: Boolean = false,
    ) : EnvironmentProbes {
        val calls = mutableListOf<String>()

        override fun suPresent(): Boolean {
            calls += "su"
            return su
        }

        override fun ultraFingerprint(): String? {
            calls += "ultra"
            if (ultraThrows) throw IllegalStateException("ULTRA_RECOVERY_PROBE_UNKNOWN")
            return null
        }

        override fun ksuNormal(): Boolean? {
            calls += "ksu"
            return ksu
        }

        override fun foreignKsuKernel(): Boolean? {
            calls += "foreignKsu"
            return foreign
        }

        fun count(name: String): Int = calls.count { it == name }
    }

    private object FixedClock : Clock {
        override fun nowMillis(): Long = 1_000L
    }

    private fun store(initial: EnvironmentSnapshot? = null) =
        EnvironmentStateStore(InMemoryEnvironmentStatePersistence(initial))

    private fun resolve(probes: CountingProbes, state: EnvironmentStateStore) =
        EnvironmentResolver(probes, state, FixedClock).resolve(BOOT)

    @Test
    fun respondingForeignKernelIsTerminalNotInstalled() {
        val probes = CountingProbes(ksu = null, foreign = true)
        val state = store()

        val outcome = resolve(probes, state)

        assertEquals(EnvironmentVerdict.NOT_INSTALLED, outcome.verdict)
        assertEquals("ENV_NOT_INSTALLED", outcome.code)
        assertTrue("must be terminal", outcome.terminal)
        assertEquals(EnvironmentCheckDetail.KSU_PROBE_FOREIGN, outcome.detail)
        assertNull("no mode may be granted by a foreign kernel", outcome.mode)
        assertEquals(1, probes.count("foreignKsu"))
        // 终态必须落盘，否则下次冷启动又回到未确认。
        val saved = state.snapshot()
        assertTrue("terminal verdict must persist", saved != null)
        assertNull(saved!!.mode)
        assertEquals(BOOT, saved.bootId)
    }

    @Test
    fun silentKernelStaysUnknownAndDoesNotPersist() {
        for (foreign in listOf<Boolean?>(null, false)) {
            val probes = CountingProbes(ksu = null, foreign = foreign)
            val state = store()

            val outcome = resolve(probes, state)

            assertEquals("foreign=$foreign", EnvironmentVerdict.UNKNOWN, outcome.verdict)
            assertFalse("foreign=$foreign must not be terminal", outcome.terminal)
            assertTrue("foreign=$foreign must not persist", state.snapshot() == null)
        }
    }

    @Test
    fun explicitNegativeSkipsTheWeakProbe() {
        val probes = CountingProbes(ksu = false, foreign = true)

        val outcome = resolve(probes, store())

        assertEquals(EnvironmentVerdict.NOT_INSTALLED, outcome.verdict)
        assertEquals(EnvironmentCheckDetail.KSU_PROBE_NEGATIVE, outcome.detail)
        assertEquals("explicit negative is enough", 0, probes.count("foreignKsu"))
    }

    @Test
    fun failedUltraRecoveryDoesNotVoidTheVerdict() {
        // 现场复现：没有 Ultra 凭据时 UltraIdentityRecovery 抛 ULTRA_RECOVERY_PROBE_UNKNOWN，
        // 旧实现让整次判定变成 PROBE_FAILED ⇒ 首页永远「环境检查未完成」。
        val probes = CountingProbes(ksu = false, su = true, ultraThrows = true)
        val state = store()

        val outcome = resolve(probes, state)

        assertEquals(EnvironmentVerdict.NOT_INSTALLED, outcome.verdict)
        assertEquals(EnvironmentCheckDetail.KSU_PROBE_NEGATIVE, outcome.detail)
        assertTrue("must be terminal", outcome.terminal)
        assertNull(state.snapshot()?.mode)
        assertTrue("terminal verdict must persist", state.snapshot() != null)
    }

    @Test
    fun confirmedMapleSuNormalNeverAsksForForeignKernel() {
        val probes = CountingProbes(ksu = true, foreign = true)
        val state = store()

        val outcome = resolve(probes, state)

        assertEquals(EnvironmentVerdict.KSU_NORMAL, outcome.verdict)
        assertEquals(WorkMode.KSU, outcome.mode)
        assertEquals(0, probes.count("foreignKsu"))
        assertEquals(WorkMode.KSU, state.snapshot()?.mode)
    }
}
