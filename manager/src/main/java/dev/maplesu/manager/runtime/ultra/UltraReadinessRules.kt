package dev.maplesu.manager.runtime.ultra

/**
 * Ultra 环境「就绪」的**严格判定**（2026-10-30 P0 修复）。
 *
 * 背景：`UltraRuntimeClient.capabilities()` 曾把 `Fault` 也算 ready
 * （`ultraEnvironmentReady = state == "Running" || state == "Fault"`），于是：
 * - 授权/`Natives` 走 `UltraEnvironmentProbe.isRunning()`（只认 Running，严格）；
 * - 模块动作走 `capabilities().ultraEnvironmentReady`（Fault 也放行）；
 * 同一设备上同一种状态得到两个相反结论，模块动作会在环境异常态被放行。
 *
 * 现在唯一口径与探针一致：**只有 `Running` 是 ready**。`Fault`/`NotInstalled`/
 * `NoKey`/`Unknown`/SDK 不可用（state 为 null）一律不是 ready。版本回读、`testRoot`
 * 是「已激活」的**额外**证据，见 [UltraEnvActivationEvidence] 的 strictReady。
 */
internal object UltraReadinessRules {

    const val STATE_RUNNING = "Running"

    /**
     * 环境是否 ready。
     *
     * 只接受**字面量** `Running`；不做 trim/忽略大小写/前缀匹配——SDK 的状态词表是固定
     * 的机器接口（Running/NotInstalled/Fault/...），放宽匹配只会制造新的"看起来已激活"。
     */
    fun ultraEnvironmentReady(environmentState: String?): Boolean =
        environmentState == STATE_RUNNING

    // Fault also covers an incomplete boot session. It is a recovery state, never full readiness.
    fun isSafeMode(environmentState: String?): Boolean = environmentState == "Fault"

    fun moduleRecoveryAvailable(environmentState: String?): Boolean =
        ultraEnvironmentReady(environmentState) || isSafeMode(environmentState)
}
