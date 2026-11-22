package dev.maplesu.manager.modules.webui

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

/**
 * 「打开模块 WebUI」的编排回归。
 *
 * 这些用例直接驱动产品入口 `ModuleWebUiLauncher.openDetailed` 内部使用的
 * [WebUiOpenCoordinator]，只替换两个注入点（SDK 启动器、探活器）和兼容门：
 *  - 20 次并发同模块打开 → SDK 只启动 1 次，20 个调用拿到同一个结果；
 *  - 两个模块各自失败 → 原因/明细/id32 互不覆盖；
 *  - PATH 不在本文件里断言（同进程取三次 `System.getenv` 不可能失败，W5 复核 S1-3）；
 *    改由 [ModuleWebUiEnvironmentGuardTest] 的源文本守卫 + 运行时 tripwire 负责；
 *  - 门挡住 → SDK 调用 0 次 + 明确的失败码；
 *  - 探活成功只探一次；失败 detail 指向本次 port；
 *  - 连续两次顺序打开 → 各启动一次（单飞只合并重叠请求，不缓存已完成的成功结果）。
 *
 * 不使用 Robolectric：编排本身没有 Android import，`SdkOpenRunner` / `HttpReadyProbe`
 * 都是纯 JVM 注入点。
 */
class ModuleWebUiOrchestrationTest {

    private fun ultraSpec(id32: String) = WebUiOpenSpec(id32, WebUiRoute.ULTRA_SDK)

    private fun permitGate(): WebUiCompatibilityCheck = WebUiCompatibilityCheck {
        WebUiGateVerdict.permit(
            decision = "UNVERIFIED",
            reasonCodes = listOf("UNKNOWN_PACKAGE"),
            detail = "gate=UNVERIFIED record=none codes=UNKNOWN_PACKAGE",
        )
    }

    /** 计数型探活替身：返回**本次** port 对应的结果，并记录调用次数/端口。 */
    private class RecordingProbe(
        private val result: (Int) -> HttpReadyResult,
    ) : HttpReadyProbe {
        val calls = AtomicInteger()
        val ports = mutableListOf<Int>()

        override suspend fun await(port: Int): HttpReadyResult {
            calls.incrementAndGet()
            ports += port
            return result(port)
        }
    }

    // ------------------------------------------------------------------ 单飞

    @Test
    fun twentyConcurrentOpensForOneModuleStartExactlyOneSdkRequest() = runBlocking {
        val runnerCalls = AtomicInteger()
        val probe = RecordingProbe { port -> HttpReadyResult.readyAt(port) }
        val runner = SdkOpenRunner { _ ->
            runnerCalls.incrementAndGet()
            // 让后到的 19 个请求在同一个「正在飞」的窗口里合并进来。
            delay(500)
            SdkOpenOutcome(ok = true, port = 32431, sdkError = "OK")
        }
        val coordinator = WebUiOpenCoordinator(runner, probe, permitGate())

        val results = (1..20).map {
            async(Dispatchers.IO) { coordinator.open(ultraSpec("aaaa1111")) }
        }.awaitAll()

        assertEquals("同一模块的并发打开只能启动一次 SDK 请求", 1, runnerCalls.get())
        assertEquals("一次打开只探一次就绪", 1, probe.calls.get())
        assertEquals(20, results.size)
        assertTrue(results.all { it.succeeded })
        assertTrue(results.all { it.moduleId32 == "aaaa1111" })
        assertTrue(results.all { it.port == 32431 })
        assertEquals("20 个调用必须共用同一个 operationId", 1, results.map { it.operationId }.distinct().size)

        // PATH 回归**不**在这里做：这三处读的是同一个 JVM 环境，测试与被测代码都不碰 PATH，
        // 即使把 `Os.setenv` 加回 launcher 也仍然全绿（W5 复核 S1-3）。有效守卫是
        // ModuleWebUiEnvironmentGuardTest 的源文本断言（能红）；本文件不再保留空转比较。
    }

    // ------------------------------------------------------------------ 错误归属

    @Test
    fun twoModulesKeepTheirOwnFailureDetails() = runBlocking {
        val runner = SdkOpenRunner { id32 ->
            when (id32) {
                "alpha001" -> SdkOpenOutcome(false, 0, "ERR_ALPHA", 11, "ERR_ALPHA")
                "beta0002" -> SdkOpenOutcome(false, 0, "ERR_BETA", 22, "ERR_BETA")
                else -> error("unexpected module id $id32")
            }
        }
        val coordinator = WebUiOpenCoordinator(
            runner,
            RecordingProbe { port -> HttpReadyResult.readyAt(port) },
            permitGate(),
        )

        val (alpha, beta) = listOf(
            async(Dispatchers.IO) { coordinator.open(ultraSpec("alpha001")) },
            async(Dispatchers.IO) { coordinator.open(ultraSpec("beta0002")) },
        ).awaitAll()

        val alphaFailure = requireNotNull(alpha.failure)
        val betaFailure = requireNotNull(beta.failure)
        assertEquals("alpha001", alpha.moduleId32)
        assertEquals("beta0002", beta.moduleId32)
        assertEquals(WebUiFailureReason.SDK_REJECTED, alphaFailure.reason)
        assertEquals(WebUiFailureReason.SDK_REJECTED, betaFailure.reason)
        assertTrue("alpha 的明细必须是 alpha 的错误", alphaFailure.detail.contains("ERR_ALPHA"))
        assertFalse("alpha 的明细不能被 beta 覆盖", alphaFailure.detail.contains("ERR_BETA"))
        assertTrue("beta 的明细必须是 beta 的错误", betaFailure.detail.contains("ERR_BETA"))
        assertFalse("beta 的明细不能被 alpha 覆盖", betaFailure.detail.contains("ERR_ALPHA"))
        // SDK 回执失败 = 服务侧退出/未启动，不是页面关闭（§5.2 分账）。
        assertEquals(WebUiLifecycleStage.SERVICE_EXIT, alpha.stage)
        assertEquals(WebUiLifecycleStage.SERVICE_EXIT, beta.stage)
    }

    // ------------------------------------------------------------------ 兼容门

    @Test
    fun blockedGateNeverCallsTheSdk() = runBlocking {
        val runnerCalls = AtomicInteger()
        val gate = WebUiCompatibilityCheck {
            WebUiGateVerdict.refusal(
                failure = WebUiFailure(
                    WebUiFailureReason.BLOCKED_INCOMPATIBLE,
                    "gate=KNOWN_INCOMPATIBLE codes=PACKAGE_ARCHIVE_SHA256_MATCH",
                ),
                decision = "KNOWN_INCOMPATIBLE",
                reasonCodes = listOf("PACKAGE_ARCHIVE_SHA256_MATCH"),
                detail = "gate=KNOWN_INCOMPATIBLE record=fixture codes=PACKAGE_ARCHIVE_SHA256_MATCH",
            )
        }
        val coordinator = WebUiOpenCoordinator(
            SdkOpenRunner {
                runnerCalls.incrementAndGet()
                error("被门拦下时不允许调用 SDK")
            },
            RecordingProbe { port -> HttpReadyResult.readyAt(port) },
            gate,
        )

        val result = coordinator.open(ultraSpec("deadbeef"))

        assertEquals("门挡住时 SDK 调用次数必须为 0", 0, runnerCalls.get())
        assertEquals("deadbeef", result.moduleId32)
        assertEquals(WebUiRoute.ULTRA_SDK, result.route)
        assertEquals(WebUiLifecycleStage.GATE_BLOCKED, result.stage)
        assertEquals(WebUiPageOpener.SDK, result.opener)
        assertEquals("BLOCKED_INCOMPATIBLE", result.failure?.code)
        assertTrue(result.failure?.detail.orEmpty().contains("KNOWN_INCOMPATIBLE"))
    }

    // ------------------------------------------------------------------ 探活

    @Test
    fun readyProbeRunsExactlyOnceAndReportsTheSdkAsPageOpener() = runBlocking {
        val probe = RecordingProbe { port -> HttpReadyResult.readyAt(port) }
        val coordinator = WebUiOpenCoordinator(
            SdkOpenRunner { SdkOpenOutcome(true, 40123, "OK") },
            probe,
            permitGate(),
        )

        val result = coordinator.open(ultraSpec("abc123"))

        assertNull(result.failure)
        assertEquals(40123, result.port)
        assertEquals(WebUiLifecycleStage.READY, result.stage)
        // Ultra 路由沿用 SDK 的打开方式（§5.1），MapleSU 不再重复拉起页面。
        assertEquals(WebUiPageOpener.SDK, result.opener)
        assertEquals(1, probe.calls.get())
        assertEquals(listOf(40123), probe.ports)
    }

    @Test
    fun probeFailureCarriesThisCallsPort() = runBlocking {
        val probe = RecordingProbe { port ->
            HttpReadyResult.failedAt(port, WebUiFailure(WebUiFailureReason.NOT_HTTP, ""))
        }
        val coordinator = WebUiOpenCoordinator(
            SdkOpenRunner { SdkOpenOutcome(true, 45678, "OK") },
            probe,
            permitGate(),
        )

        val result = coordinator.open(ultraSpec("abc123"))

        assertEquals(WebUiLifecycleStage.PROBE_FAILED, result.stage)
        assertEquals(WebUiFailureReason.NOT_HTTP, result.failure?.reason)
        assertTrue(
            "失败 detail 必须指向本次 port",
            result.failure?.detail.orEmpty().contains("port=45678"),
        )
        assertEquals(1, probe.calls.get())
    }

    // ------------------------------------------------------------------ 顺序打开

    @Test
    fun sequentialOpensEachStartOneSdkRequest() = runBlocking {
        val runnerCalls = AtomicInteger()
        val probe = RecordingProbe { port -> HttpReadyResult.readyAt(port) }
        val coordinator = WebUiOpenCoordinator(
            SdkOpenRunner {
                val attempt = runnerCalls.incrementAndGet()
                SdkOpenOutcome(true, 41000 + attempt, "OK")
            },
            probe,
            permitGate(),
        )

        val first = coordinator.open(ultraSpec("abc123"))
        val second = coordinator.open(ultraSpec("abc123"))

        assertEquals("单飞只合并重叠请求，不缓存已完成的成功结果", 2, runnerCalls.get())
        assertEquals(2, probe.calls.get())
        assertNotEquals(first.operationId, second.operationId)
        assertEquals(41001, first.port)
        assertEquals(41002, second.port)
    }

    // ------------------------------------------------------------ 生命周期码分账

    @Test
    fun pageCloseCodeDoesNotClaimTheModuleStopped() {
        assertTrue(
            "页面关闭的稳定码必须写明它不是模块停止",
            WebUiPageLifecycle.PAGE_CLOSED.contains("NOT_MODULE_STOP"),
        )
        assertNotEquals(WebUiPageLifecycle.PAGE_CLOSED, WebUiPageLifecycle.SERVICE_EXIT)
        assertNotEquals(WebUiPageLifecycle.PAGE_CLOSED, WebUiPageLifecycle.APP_PROCESS_EXIT)
    }
}
