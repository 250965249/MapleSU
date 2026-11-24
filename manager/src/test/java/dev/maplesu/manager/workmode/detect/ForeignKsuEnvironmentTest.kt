// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.workmode.detect

import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CancellationException

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
        assertEquals(EnvironmentCheckDetail.SU_ABSENT_NO_ULTRA + ":" + EnvironmentCheckDetail.KSU_PROBE_NEGATIVE, outcome.detail)
        assertEquals("explicit negative is enough", 0, probes.count("foreignKsu"))
    }

    @Test
    fun failedUltraRecoveryPreservesThePreviousState() {
        for (ksu in listOf<Boolean?>(false, null)) {
            val probes = CountingProbes(ksu = ksu, foreign = true, su = true, ultraThrows = true)
            val state = store()
            val outcome = resolve(probes, state)
            assertEquals(EnvironmentVerdict.UNKNOWN, outcome.verdict)
            assertTrue(outcome.detail.startsWith(EnvironmentCheckDetail.PROBE_FAILED))
            assertFalse(outcome.terminal)
            assertNull(state.snapshot())
        }
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

    @Test
    fun cancellationStopsAtEveryProbeWithoutPersisting() {
        for (probe in listOf("ksuFirst", "ultraCurrent", "su", "ultra", "ksuSecond", "foreignKsu")) {
            assertProbeStops(probe, CancellationException(probe))
        }
    }

    @Test
    fun cancelledRecoveryPreservesAnEarlierLiteSnapshot() {
        val previous = EnvironmentSnapshot(WorkMode.LITE, true, "ultra:running", BOOT, 1L)
        assertProbeStops("ultra", CancellationException("ultra"), previous)
    }

    @Test
    fun ordinaryRecoveryFailureStillAllowsIndependentNormalIdentity() {
        var ksuCalls = 0
        val probes = object : EnvironmentProbes {
            override fun ksuNormal(): Boolean? = if (++ksuCalls == 1) null else true
            override fun suPresent(): Boolean = false
            override fun ultraFingerprint(): String? = throw IllegalStateException("ULTRA_RECOVERY_PROBE_UNKNOWN")
        }
        val state = store()
        val outcome = EnvironmentResolver(probes, state, FixedClock).resolve(BOOT)
        assertEquals(EnvironmentVerdict.KSU_NORMAL, outcome.verdict)
        assertEquals(WorkMode.KSU, state.snapshot()?.mode)
    }

    @Test
    fun interruptionStopsAtEveryProbeAndPreservesTheInterrupt() {
        for (probe in listOf("ksuFirst", "ultraCurrent", "su", "ultra", "ksuSecond", "foreignKsu")) {
            try {
                assertProbeStops(probe, InterruptedException(probe))
                assertTrue(Thread.currentThread().isInterrupted)
            } finally {
                Thread.interrupted()
            }
        }
    }

    private fun assertProbeStops(failedProbe: String, failure: Throwable, previous: EnvironmentSnapshot? = null) {
        val calls = mutableListOf<String>()
        var ksuCalls = 0
        fun visit(name: String) {
            calls += name
            if (name == failedProbe) throw failure
        }
        val probes = object : EnvironmentProbes {
            override fun ksuNormal(): Boolean? {
                visit(if (ksuCalls++ == 0) "ksuFirst" else "ksuSecond")
                return if (ksuCalls > 1 && failedProbe == "ultra") true else null
            }
            override fun currentUltraFingerprint(): String? { visit("ultraCurrent"); return null }
            override fun suPresent(): Boolean { visit("su"); return false }
            override fun ultraFingerprint(): String? { visit("ultra"); return null }
            override fun foreignKsuKernel(): Boolean? { visit("foreignKsu"); return true }
        }
        val state = store(previous)
        val thrown = runCatching { EnvironmentResolver(probes, state, FixedClock).resolve(BOOT) }.exceptionOrNull()
        assertSame("failedProbe=$failedProbe calls=$calls", failure, thrown)
        assertEquals(failedProbe, calls.last())
        assertSame("failedProbe=$failedProbe must preserve state", previous, state.snapshot())
    }
}
