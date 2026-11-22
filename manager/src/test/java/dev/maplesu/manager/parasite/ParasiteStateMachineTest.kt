package dev.maplesu.manager.parasite

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** N0–N6 状态机：合法链/reset/非法拒绝/卸载必须 N5/四结果证据独立。 */
class ParasiteStateMachineTest {
    private val sm = ParasiteStateMachine

    @Test
    fun forwardChainIsAllowed() {
        val chain = listOf(
            ParasiteState.N0_IDLE to ParasiteState.N1_PRECHECKED,
            ParasiteState.N1_PRECHECKED to ParasiteState.N2_IMPLANTED,
            ParasiteState.N2_IMPLANTED to ParasiteState.N3_HOST_LAUNCHED,
            ParasiteState.N3_HOST_LAUNCHED to ParasiteState.N4_WEB_SERVING,
            ParasiteState.N4_WEB_SERVING to ParasiteState.N5_RECOVERABLE,
            ParasiteState.N5_RECOVERABLE to ParasiteState.N6_UNINSTALLED,
        )
        val capabilities = ParasiteCapabilities(
            soLoaded = true, webReachable = true, serviceEstablished = true, rootCommandOk = true,
        )
        for ((from, to) in chain) {
            val result = sm.transition(from, to, capabilities, recoveryVerified = true)
            assertTrue("${from.name}->${to.name}: ${result.code} ${result.detail}", result.ok)
            assertTrue(sm.canTransition(from, to))
        }
    }

    @Test
    fun resetToIdleIsAllowedFromIntermediateStates() {
        for (state in listOf(
            ParasiteState.N1_PRECHECKED,
            ParasiteState.N2_IMPLANTED,
            ParasiteState.N3_HOST_LAUNCHED,
            ParasiteState.N4_WEB_SERVING,
            ParasiteState.N5_RECOVERABLE,
        )) {
            assertTrue("${state.name} reset", sm.transition(state, ParasiteState.N0_IDLE).ok)
        }
        assertFalse(sm.canTransition(ParasiteState.N6_UNINSTALLED, ParasiteState.N0_IDLE))
    }

    @Test
    fun illegalJumpsAreRejected() {
        val illegal = listOf(
            ParasiteState.N0_IDLE to ParasiteState.N2_IMPLANTED,
            ParasiteState.N1_PRECHECKED to ParasiteState.N3_HOST_LAUNCHED,
            ParasiteState.N2_IMPLANTED to ParasiteState.N5_RECOVERABLE,
            ParasiteState.N3_HOST_LAUNCHED to ParasiteState.N5_RECOVERABLE,
            ParasiteState.N4_WEB_SERVING to ParasiteState.N0_IDLE.let { ParasiteState.N6_UNINSTALLED },
            ParasiteState.N6_UNINSTALLED to ParasiteState.N5_RECOVERABLE,
        )
        for ((from, to) in illegal) {
            val result = sm.transition(from, to)
            assertFalse("${from.name}->${to.name} must be rejected", result.ok)
            assertTrue(
                result.code == ParasiteStateMachine.ILLEGAL_TRANSITION ||
                    result.code == ParasiteStateMachine.UNINSTALL_REQUIRES_RECOVERABLE,
            )
        }
    }

    @Test
    fun uninstallRequiresRecoverableState() {
        val fromN4 = sm.transition(ParasiteState.N4_WEB_SERVING, ParasiteState.N6_UNINSTALLED)
        assertFalse(fromN4.ok)
        assertEquals(ParasiteStateMachine.UNINSTALL_REQUIRES_RECOVERABLE, fromN4.code)
        assertEquals(
            ParasiteStateMachine.UNINSTALL_REQUIRES_RECOVERABLE,
            sm.uninstallBlockedReason(ParasiteState.N4_WEB_SERVING),
        )
        assertNull(sm.uninstallBlockedReason(ParasiteState.N5_RECOVERABLE))
        assertTrue(sm.transition(ParasiteState.N5_RECOVERABLE, ParasiteState.N6_UNINSTALLED).ok)
    }

    @Test
    fun implantStateRequiresSoLoadedEvidence() {
        val missing = sm.transition(ParasiteState.N1_PRECHECKED, ParasiteState.N2_IMPLANTED)
        assertFalse(missing.ok)
        assertEquals(ParasiteStateMachine.EVIDENCE_MISSING, missing.code)
        assertTrue(
            sm.transition(
                ParasiteState.N1_PRECHECKED, ParasiteState.N2_IMPLANTED,
                ParasiteCapabilities(soLoaded = true),
            ).ok,
        )
    }

    @Test
    fun webServingRequiresWebAndServiceButNotRoot() {
        val both = ParasiteCapabilities(webReachable = true, serviceEstablished = true)
        assertTrue(sm.transition(ParasiteState.N3_HOST_LAUNCHED, ParasiteState.N4_WEB_SERVING, both).ok)
        // 只有网页、没有服务 → 拒绝。
        val webOnly = sm.transition(
            ParasiteState.N3_HOST_LAUNCHED, ParasiteState.N4_WEB_SERVING,
            ParasiteCapabilities(webReachable = true),
        )
        assertFalse(webOnly.ok)
        assertEquals(ParasiteStateMachine.EVIDENCE_MISSING, webOnly.code)
        // 只有服务、没有网页 → 拒绝。
        assertFalse(
            sm.transition(
                ParasiteState.N3_HOST_LAUNCHED, ParasiteState.N4_WEB_SERVING,
                ParasiteCapabilities(serviceEstablished = true),
            ).ok,
        )
        // root 命令成功不是 N4 的必要条件（四结果独立）。
        assertTrue(
            sm.transition(
                ParasiteState.N3_HOST_LAUNCHED, ParasiteState.N4_WEB_SERVING,
                both.copy(rootCommandOk = false),
            ).ok,
        )
    }

    @Test
    fun recoverableRequiresVerifiedBackup() {
        val missing = sm.transition(ParasiteState.N4_WEB_SERVING, ParasiteState.N5_RECOVERABLE)
        assertFalse(missing.ok)
        assertEquals(ParasiteStateMachine.EVIDENCE_MISSING, missing.code)
        assertTrue(
            sm.transition(
                ParasiteState.N4_WEB_SERVING, ParasiteState.N5_RECOVERABLE,
                recoveryVerified = true,
            ).ok,
        )
    }

    @Test
    fun fourResultsAreIndependent() {
        val defaults = ParasiteCapabilities()
        assertFalse(defaults.soLoaded)
        assertFalse(defaults.webReachable)
        assertFalse(defaults.serviceEstablished)
        assertFalse(defaults.rootCommandOk)
        assertFalse(defaults.allFour)

        val onlySo = defaults.copy(soLoaded = true)
        assertTrue(onlySo.soLoaded)
        assertFalse(onlySo.webReachable)
        assertFalse(onlySo.allFour)

        val all = ParasiteCapabilities(
            soLoaded = true, webReachable = true, serviceEstablished = true, rootCommandOk = true,
        )
        assertTrue(all.allFour)
        // 去掉任意一项后 allFour 必须为 false（禁止合并成"成功"）。
        for (
            variant in listOf(
                all.copy(soLoaded = false),
                all.copy(webReachable = false),
                all.copy(serviceEstablished = false),
                all.copy(rootCommandOk = false),
            )
        ) {
            assertFalse(variant.allFour)
        }
    }

    @Test
    fun recordWithUnknownStateIsInvalid() {
        val record = ParasiteHostRecord(
            registrationId = "reg-1",
            hostPackage = "com.example.host",
            hostUid = 10_200,
            targetPidCmdline = "com.example.host",
            originalSoPath = "/data/app/lib/libfoo.so",
            state = "N9_BOGUS",
        )
        assertNull(record.stateEnum())
        assertNull(sm.stateOf(record))
    }

    @Test
    fun stateTerminalOnlyForUninstalled() {
        assertTrue(ParasiteState.N6_UNINSTALLED.terminal)
        for (state in ParasiteState.entries - ParasiteState.N6_UNINSTALLED) {
            assertFalse(state.terminal)
        }
    }
}
