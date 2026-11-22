package dev.maplesu.manager.litehidden

import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 宿主激活/解除的后端契约（JVM）：未接线 fail-closed、参数校验、宿主与端口透传、
 * 失败码与分步结果如实回传（**不**拿部分成功当成功）。
 */
class HiddenModeBackendHostTest {

    private class FakeBackend(
        val activateResult: HiddenActivateResult? = null,
        val deactivateResult: HiddenDeactivateResult? = null,
    ) : HiddenModeBackend {
        var activateCalls = 0
        var deactivateCalls = 0
        var lastHost = ""
        var lastPort = 0
        var lastDeactivateHost = ""

        override suspend fun enableHidden(port: Int): HiddenEnableResult = HiddenEnableResult(success = true)

        override suspend fun restore(): HiddenEnableResult = HiddenEnableResult(success = true)

        override suspend fun activate(hostPackage: String, port: Int): HiddenActivateResult {
            activateCalls++
            lastHost = hostPackage
            lastPort = port
            return activateResult ?: HiddenActivateResult(
                success = true,
                hostPackage = hostPackage,
                steps = listOf(
                    HiddenStepResult(HiddenActivateStep.PRECHECK.wire, ok = true),
                    HiddenStepResult(HiddenActivateStep.HOST_SO.wire, ok = true),
                ),
            )
        }

        override suspend fun deactivate(hostPackage: String): HiddenDeactivateResult {
            deactivateCalls++
            lastDeactivateHost = hostPackage
            return deactivateResult ?: HiddenDeactivateResult(
                success = true,
                hostPackage = hostPackage,
                steps = listOf(
                    HiddenStepResult(HiddenDeactivateStep.RESTORE_HOST_SO.wire, ok = true),
                    HiddenStepResult(HiddenDeactivateStep.REVOKE_SU_AUTH.wire, ok = true),
                    HiddenStepResult(HiddenDeactivateStep.STOP_DAEMON.wire, ok = true),
                ),
                hostSoRestored = true,
                suAuthRevoked = true,
                daemonStopped = true,
            )
        }
    }

    @After
    fun clearBackend() {
        HiddenModeBackends.current = null
        HiddenModeBackends.ensureProvider = null
    }

    @Test
    fun backendRecoversOnDemandAfterStartupModeWaitExpired() = runBlocking {
        val backend = FakeBackend()
        var modeReady = false
        var attempts = 0
        HiddenModeBackends.current = null
        HiddenModeBackends.ensureProvider = {
            attempts++
            backend.takeIf { modeReady }
        }
        assertEquals(HiddenFailure.BACKEND_UNAVAILABLE,
            HiddenModeBackends.activate("com.example.chat", 18427).failure)
        modeReady = true
        assertTrue(HiddenModeBackends.activate("com.example.chat", 18427).success)
        assertTrue(HiddenModeBackends.deactivate("com.example.chat").success)
        assertEquals(2, attempts)
        assertEquals(1, backend.activateCalls)
        assertEquals(1, backend.deactivateCalls)
    }

    // 1
    @Test
    fun activateWithoutBackendFailsClosed() = runBlocking {
        HiddenModeBackends.current = null
        val result = HiddenModeBackends.activate("com.example.chat", 18427)
        assertFalse("未接线绝不能返回成功", result.success)
        assertEquals(HiddenFailure.BACKEND_UNAVAILABLE, result.failure)
        assertEquals("LITE_HIDDEN_BACKEND_UNAVAILABLE", result.code)
        assertEquals("com.example.chat", result.hostPackage)
    }

    // 2
    @Test
    fun activateRequiresHostSelectionBeforeCallingBackend() = runBlocking {
        val backend = FakeBackend()
        HiddenModeBackends.current = backend
        val result = HiddenModeBackends.activate("   ", 18427)
        assertFalse(result.success)
        assertEquals(HiddenFailure.HOST_NOT_SELECTED, result.failure)
        assertEquals("HOST_NOT_SELECTED", result.code)
        assertEquals("未选宿主不得调用后端", 0, backend.activateCalls)
    }

    // 3
    @Test
    fun activateRejectsInvalidPortBeforeCallingBackend() = runBlocking {
        val backend = FakeBackend()
        HiddenModeBackends.current = backend
        val result = HiddenModeBackends.activate("com.example.chat", 80)
        assertFalse(result.success)
        assertEquals(HiddenFailure.INVALID_PORT, result.failure)
        assertEquals(0, backend.activateCalls)
    }

    // 4
    @Test
    fun activatePassesHostAndPortToBackendAndKeepsItsSteps() = runBlocking {
        val backend = FakeBackend()
        HiddenModeBackends.current = backend
        val result = HiddenModeBackends.activate(" com.example.chat ", 20000)
        assertTrue(result.success)
        assertEquals("com.example.chat", backend.lastHost)
        assertEquals("端口必须透传", 20000, backend.lastPort)
        assertEquals(
            listOf(HiddenActivateStep.PRECHECK.wire, HiddenActivateStep.HOST_SO.wire),
            result.steps.map { it.step },
        )
    }

    // 5
    @Test
    fun activateFailureSurfacesBackendCodeAndSteps() = runBlocking {
        val backend = FakeBackend(
            activateResult = HiddenActivateResult(
                success = false,
                failure = HiddenFailure.HOST_SO_PATCH_FAILED,
                code = "HOST_SO_PATCH_FAILED",
                hostPackage = "com.example.chat",
                steps = listOf(
                    HiddenStepResult(HiddenActivateStep.PRECHECK.wire, ok = true),
                    HiddenStepResult(
                        HiddenActivateStep.HOST_SO.wire,
                        ok = false,
                        code = "HOST_SO_PATCH_FAILED",
                        detail = "rename failed",
                    ),
                ),
            ),
        )
        HiddenModeBackends.current = backend
        val result = HiddenModeBackends.activate("com.example.chat", 18427)
        assertFalse(result.success)
        assertEquals(HiddenFailure.HOST_SO_PATCH_FAILED, result.failure)
        assertEquals("lite_hidden_reason_host_so", HiddenModePolicy.failureMessageKey(result.code))
        assertEquals(2, result.steps.size)
        assertTrue(result.steps[0].ok)
        assertFalse(result.steps[1].ok)
    }

    // 6
    @Test
    fun deactivateWithoutBackendFailsClosed() = runBlocking {
        HiddenModeBackends.current = null
        val result = HiddenModeBackends.deactivate("com.example.chat")
        assertFalse(result.success)
        assertEquals(HiddenFailure.BACKEND_UNAVAILABLE, result.failure)
        assertEquals("LITE_HIDDEN_BACKEND_UNAVAILABLE", result.code)
    }

    // 7
    @Test
    fun deactivateRequiresHostPackage() = runBlocking {
        val backend = FakeBackend()
        HiddenModeBackends.current = backend
        val result = HiddenModeBackends.deactivate("")
        assertFalse(result.success)
        assertEquals(HiddenFailure.HOST_NOT_SELECTED, result.failure)
        assertEquals(0, backend.deactivateCalls)
    }

    // 8
    @Test
    fun deactivateReportsThreeIndependentSteps() = runBlocking {
        val backend = FakeBackend()
        HiddenModeBackends.current = backend
        val result = HiddenModeBackends.deactivate("com.example.chat")
        assertTrue(result.success)
        assertEquals("com.example.chat", backend.lastDeactivateHost)
        assertEquals(
            listOf(
                HiddenDeactivateStep.RESTORE_HOST_SO.wire,
                HiddenDeactivateStep.REVOKE_SU_AUTH.wire,
                HiddenDeactivateStep.STOP_DAEMON.wire,
            ),
            result.steps.map { it.step },
        )
        assertTrue(result.hostSoRestored)
        assertTrue(result.suAuthRevoked)
        assertTrue(result.daemonStopped)
    }

    // 9
    @Test
    fun deactivateFailureKeepsEveryStepResult() = runBlocking {
        val backend = FakeBackend(
            deactivateResult = HiddenDeactivateResult(
                success = false,
                failure = HiddenFailure.DEACTIVATE_FAILED,
                code = "HIDDEN_DEACTIVATE_FAILED",
                hostPackage = "com.example.chat",
                steps = listOf(
                    HiddenStepResult(HiddenDeactivateStep.RESTORE_HOST_SO.wire, ok = true),
                    HiddenStepResult(HiddenDeactivateStep.REVOKE_SU_AUTH.wire, ok = false, code = "SU_AUTH_REVOKE_FAILED"),
                    HiddenStepResult(HiddenDeactivateStep.STOP_DAEMON.wire, ok = true),
                ),
                hostSoRestored = true,
            ),
        )
        HiddenModeBackends.current = backend
        val result = HiddenModeBackends.deactivate("com.example.chat")
        assertFalse(result.success)
        assertEquals(HiddenFailure.DEACTIVATE_FAILED, result.failure)
        assertEquals(listOf(true, false, true), result.steps.map { it.ok })
        assertEquals("lite_hidden_reason_deactivate", HiddenModePolicy.failureMessageKey(result.code))
    }

    // 10
    @Test
    fun allStepsOkButSuccessFalseIsStillFailure() = runBlocking {
        val backend = FakeBackend(
            activateResult = HiddenActivateResult(
                success = false,
                failure = HiddenFailure.VERIFY_FAILED,
                code = "LITE_HIDDEN_VERIFY_FAILED",
                hostPackage = "com.example.chat",
                steps = HiddenActivateStep.entries.map { HiddenStepResult(it.wire, ok = true) },
            ),
        )
        HiddenModeBackends.current = backend
        val result = HiddenModeBackends.activate("com.example.chat", 18427)
        assertFalse("分步全 ok 也不能覆盖 success=false", result.success)
        assertEquals(HiddenFailure.VERIFY_FAILED, result.failure)
    }

    // 11
    @Test
    fun hostFailureCodesHaveDistinctShortReasons() {
        val hostFailures = listOf(
            HiddenFailure.HOST_NOT_SELECTED,
            HiddenFailure.HOST_REJECTED,
            HiddenFailure.HOST_SCAN_FAILED,
            HiddenFailure.HOST_BACKUP_FAILED,
            HiddenFailure.HOST_SO_PATCH_FAILED,
            HiddenFailure.DEACTIVATE_FAILED,
        )
        val keys = hostFailures.map { it.messageKey }
        assertEquals("每个失败码一个独立文案", keys.size, keys.toSet().size)
        assertTrue(keys.all { it.startsWith("lite_hidden_reason_") })
        hostFailures.forEach { failure ->
            assertEquals(
                "wire 必须能回读成同一失败码",
                failure,
                HiddenFailure.fromWire(failure.wire),
            )
        }
        assertNotEquals(HiddenFailure.HOST_SO_PATCH_FAILED.messageKey, HiddenFailure.DEACTIVATE_FAILED.messageKey)
    }

    // 12
    @Test
    fun stepWiresAreStableContract() {
        assertEquals(
            listOf("precheck", "host_so", "webui_start", "webui_ping", "hide_state"),
            HiddenActivateStep.entries.take(5).map { it.wire },
        )
        assertEquals(listOf("final_verify", "manager_removal"), HiddenActivateStep.entries.drop(5).map { it.wire })
        assertEquals(
            listOf("restore_host_so", "revoke_su_auth", "stop_daemon"),
            HiddenDeactivateStep.entries.map { it.wire },
        )
    }
}
