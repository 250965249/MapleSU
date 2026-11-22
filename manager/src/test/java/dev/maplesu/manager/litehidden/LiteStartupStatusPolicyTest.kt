package dev.maplesu.manager.litehidden

import dev.maplesu.manager.workmode.detect.ModeState
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** P0 首页启动状态纯策略测试（≥8）。 */
class LiteStartupStatusPolicyTest {

    private fun facts(
        liteMode: Boolean = false,
        liteEvidence: Boolean = false,
        ultraRunning: Boolean = false,
        rootAvailable: Boolean = false,
        probeRoot: Boolean = false,
        stealthOn: Boolean = false,
        ksuMode: Boolean = false,
        rootProbeSettled: Boolean = true,
        detectedState: ModeState? = null,
    ) = LiteStartupFacts(
        liteMode = liteMode,
        liteEvidence = liteEvidence,
        ultraEnvironmentRunning = ultraRunning,
        rootAvailable = rootAvailable,
        probeRoot = probeRoot,
        stealthOn = stealthOn,
        ksuMode = ksuMode,
        rootProbeSettled = rootProbeSettled,
        detectedState = detectedState,
    )

    @Test
    fun liteModeIsInstalledImmediately() {
        val status = LiteStartupStatusPolicy.evaluate(facts(liteMode = true))
        assertTrue(status.liteInstalled)
        assertTrue(status.forceManager)
        assertTrue(status.forceRootAvailable)
    }

    @Test
    fun liteEvidenceCountsAsInstalled() {
        val status = LiteStartupStatusPolicy.evaluate(facts(liteEvidence = true))
        assertTrue("本地 Lite 证据 = 已安装", status.liteInstalled)
        assertTrue(status.forceManager)
    }

    @Test
    fun nonLiteUnchanged() {
        val status = LiteStartupStatusPolicy.evaluate(facts())
        assertFalse(status.liteInstalled)
        assertFalse(status.liteRootFailure)
        assertFalse(status.forceManager)
        assertFalse(status.forceRootAvailable)
    }

    @Test
    fun firstFrameLiteInstalledWithoutFailure() {
        val status = LiteStartupStatusPolicy.evaluate(facts(liteMode = true, probeRoot = false))
        assertTrue(status.liteInstalled)
        assertFalse("首帧不探测 → 不得提前显示失败", status.liteRootFailure)
    }

    @Test
    fun rootFailureShowsLineButStaysInstalled() {
        val status = LiteStartupStatusPolicy.evaluate(
            facts(liteMode = true, probeRoot = true, ultraRunning = false, rootAvailable = false),
        )
        assertTrue("已安装态不回退", status.liteInstalled)
        assertTrue("root 失败 → 显示固定提示行", status.liteRootFailure)
        assertTrue("已安装仍强制展示 Manager/root 可用", status.forceManager && status.forceRootAvailable)
    }

    @Test
    fun rootSuccessHidesFailureLine() {
        val status = LiteStartupStatusPolicy.evaluate(
            facts(liteMode = true, probeRoot = true, ultraRunning = true, rootAvailable = true),
        )
        assertTrue(status.liteInstalled)
        assertFalse(status.liteRootFailure)
    }

    @Test
    fun retrySuccessClearsFailureWhileInstalled() {
        val failed = LiteStartupStatusPolicy.evaluate(
            facts(liteMode = true, probeRoot = true),
        )
        assertTrue(failed.liteRootFailure)
        val retried = LiteStartupStatusPolicy.evaluate(
            facts(liteMode = true, probeRoot = true, rootAvailable = true),
        )
        assertFalse("重试成功后失败行消失", retried.liteRootFailure)
        assertTrue(retried.liteInstalled)
    }

    @Test
    fun ksuModeUnchangedEvenWhenRootProbeFails() {
        val status = LiteStartupStatusPolicy.evaluate(
            facts(liteMode = false, probeRoot = true, ultraRunning = false, rootAvailable = false),
        )
        assertFalse("KSU 行为不变", status.liteInstalled)
        assertFalse(status.liteRootFailure)
        assertFalse(status.forceManager)
    }

    @Test
    fun stealthSuppressesFailureLine() {
        val status = LiteStartupStatusPolicy.evaluate(
            facts(liteMode = true, probeRoot = true, stealthOn = true),
        )
        assertTrue(status.liteInstalled)
        assertFalse("隐身伪装时不显示失败行", status.liteRootFailure)
    }

    @Test
    fun liteRootAvailableWithoutUltraIsSuccess() {
        val status = LiteStartupStatusPolicy.evaluate(
            facts(liteMode = true, probeRoot = true, rootAvailable = true),
        )
        assertFalse(status.liteRootFailure)
    }

    // ── 2026-10-30 复核补强：KSU 残留证据 / 未判定时序 / 重试额度 / IS_MANAGER 语义 ──

    @Test
    fun ksuModeIgnoresStaleLiteEvidence() {
        val status = LiteStartupStatusPolicy.evaluate(
            facts(
                liteMode = false,
                liteEvidence = true, // 以前装过 Lite，no-backup 凭据文件还在
                ksuMode = true,
                probeRoot = true,
                ultraRunning = false,
                rootAvailable = false,
            ),
        )
        assertFalse("KSU 模式行为不变：残留 Lite 凭据不得把首页翻成 Lite 已安装", status.liteInstalled)
        assertFalse("KSU 绝不能出现 Lite 失败行", status.liteRootFailure)
        assertFalse(status.forceManager)
        assertFalse(status.forceRootAvailable)
    }

    @Test
    fun isManagerSemanticsNotForcedOutsideLite() {
        // IS_MANAGER 语义不回退：只有 Lite 已安装才强制 isManager=true；
        // KSU / 未判定一律不动（交给既有判定）。
        assertTrue(LiteStartupStatusPolicy.evaluate(facts(liteMode = true, probeRoot = true)).forceManager)
        assertFalse(LiteStartupStatusPolicy.evaluate(facts(probeRoot = true)).forceManager)
        assertFalse(
            LiteStartupStatusPolicy.evaluate(
                facts(liteEvidence = true, ksuMode = true, probeRoot = true),
            ).forceManager,
        )
    }

    @Test
    fun unresolvedEvidenceDoesNotShowFailureBeforeSettled() {
        val status = LiteStartupStatusPolicy.evaluate(
            facts(liteEvidence = true, probeRoot = true, rootAvailable = false, rootProbeSettled = false),
        )
        assertTrue("首帧/未判定窗口内仍是已安装", status.liteInstalled)
        assertFalse(
            "未判定窗口里的 root 失败是启动门控导致的，不能当 Ultra 模式启动失败",
            status.liteRootFailure,
        )
    }

    @Test
    fun unresolvedEvidenceShowsFailureAfterSettled() {
        val status = LiteStartupStatusPolicy.evaluate(
            facts(liteEvidence = true, probeRoot = true, rootAvailable = false, rootProbeSettled = true),
        )
        assertTrue(status.liteInstalled)
        assertTrue("等模式判定落定后仍拿不到 root → 真失败，显示提示行", status.liteRootFailure)
    }

    @Test
    fun ultraRunningCountsAsRootSuccess() {
        val status = LiteStartupStatusPolicy.evaluate(
            facts(liteMode = true, probeRoot = true, ultraRunning = true, rootAvailable = false),
        )
        assertTrue(status.liteInstalled)
        assertFalse("Ultra 环境 Running = root 通道可用，不显示失败行", status.liteRootFailure)
    }

    @Test
    fun retryOnlyForInstalledFailureWithinBudget() {
        assertTrue(LiteStartupStatusPolicy.shouldRetryRoot(true, true, 0))
        assertTrue(
            LiteStartupStatusPolicy.shouldRetryRoot(
                true,
                true,
                LiteStartupStatusPolicy.ROOT_RETRY_ATTEMPTS - 1,
            ),
        )
        assertFalse(
            "重试额度用尽后不再重试",
            LiteStartupStatusPolicy.shouldRetryRoot(
                true,
                true,
                LiteStartupStatusPolicy.ROOT_RETRY_ATTEMPTS,
            ),
        )
        assertFalse("已成功不重试", LiteStartupStatusPolicy.shouldRetryRoot(true, false, 0))
        assertFalse("未安装（KSU/未判定）不重试", LiteStartupStatusPolicy.shouldRetryRoot(false, false, 0))
    }

    // ── 2026-10-30 复核补缺：六态判定痕迹也是"本地安装证据"（首页必须与设置页一致） ──

    @Test
    fun detectedActiveStateCountsAsInstalledOnFirstFrame() {
        val status = LiteStartupStatusPolicy.evaluate(
            facts(detectedState = ModeState.MODE_A_ACTIVE),
        )
        assertTrue("判定已认出 A 态 = 首帧即已安装", status.liteInstalled)
        assertTrue(status.forceManager && status.forceRootAvailable)
        assertFalse("首帧不显示失败行", status.liteRootFailure)
    }

    @Test
    fun detectedUnboundStateCountsAsInstalledToo() {
        // 工作模式页把「已安装未绑定」写明"这不是未安装" ⇒ 首页不许翻成未安装。
        val status = LiteStartupStatusPolicy.evaluate(
            facts(detectedState = ModeState.MODE_A_INSTALLED_UNBOUND),
        )
        assertTrue(status.liteInstalled)
        assertFalse(status.liteRootFailure)
    }

    @Test
    fun detectedUnboundShowsFailureOnlyAfterSettled() {
        val unresolved = LiteStartupStatusPolicy.evaluate(
            facts(
                detectedState = ModeState.MODE_A_INSTALLED_UNBOUND,
                probeRoot = true,
                rootProbeSettled = false,
            ),
        )
        assertTrue(unresolved.liteInstalled)
        assertFalse("未判定窗口内的失败不算 Ultra 启动失败", unresolved.liteRootFailure)

        val settled = LiteStartupStatusPolicy.evaluate(
            facts(
                detectedState = ModeState.MODE_A_INSTALLED_UNBOUND,
                probeRoot = true,
                rootProbeSettled = true,
            ),
        )
        assertTrue(settled.liteInstalled)
        assertTrue("判定落定后仍拿不到 root ⇒ 显示固定提示行", settled.liteRootFailure)
    }

    @Test
    fun detectedNonLiteStatesAreNotEvidence() {
        val notEvidence = listOf(
            null,
            ModeState.MODE_B_ACTIVE,
            ModeState.MODE_B_KERNEL_ONLY,
            ModeState.NOT_INSTALLED,
            ModeState.INDETERMINATE,
            ModeState.FOREIGN_SU,
        )
        notEvidence.forEach { detected ->
            assertFalse("$detected 不是 Lite 安装证据", LiteStartupStatusPolicy.detectedLiteState(detected))
            assertFalse(LiteStartupStatusPolicy.evaluate(facts(detectedState = detected)).liteInstalled)
        }
        assertTrue(LiteStartupStatusPolicy.detectedLiteState(ModeState.MODE_A_ACTIVE))
        assertTrue(LiteStartupStatusPolicy.detectedLiteState(ModeState.MODE_A_INSTALLED_UNBOUND))
    }

    @Test
    fun ksuModeIgnoresDetectedLiteState() {
        // 双保险：即使判定痕迹是 A 态，只要模式已判定为 KSU，就按 KSU 原判定走（KSU 行为不变）。
        val status = LiteStartupStatusPolicy.evaluate(
            facts(
                ksuMode = true,
                liteEvidence = true,
                detectedState = ModeState.MODE_A_ACTIVE,
                probeRoot = true,
            ),
        )
        assertFalse(status.liteInstalled)
        assertFalse(status.liteRootFailure)
        assertFalse(status.forceManager)
    }

    @Test
    fun liteModeStillWinsOverDetectedState() {
        val status = LiteStartupStatusPolicy.evaluate(
            facts(liteMode = true, detectedState = ModeState.INDETERMINATE, probeRoot = true),
        )
        assertTrue(status.liteInstalled)
        assertTrue("已激活 LITE ⇒ 真实 root 失败要提示，但仍保持已安装", status.liteRootFailure)
    }
}
