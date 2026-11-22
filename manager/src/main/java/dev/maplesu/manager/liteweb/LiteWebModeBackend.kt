package dev.maplesu.manager.liteweb

/**
 * 模式无关的隐藏/WebUI/恢复后端（A=Lite/Ultra、B=KSU 共用同一套 HTTP API）。
 *
 * 依赖 wm-core 的 `HiddenModeBackend`（A=Ultra 模块 boot 钩子；B=KSU 模块 boot 钩子）
 * 提供 daemon 启动/停止、隐藏状态写入、备份/重装/组件恢复与重启证据；
 * 未接线时 [UnavailableHiddenModeBackend] 显式失败（不假装成功）。
 *
 * daemon 应从 `/data/adb/maplesu/recovery/` 副本启动（不依赖 APK 路径），由各自 root 后端
 * 的 boot 钩子拉起，因此 App 被卸载后 WebUI 仍可用。
 */

object LiteWebMode {
    const val LITE = "LITE"
    const val KSU = "KSU"
    const val UNKNOWN = "UNKNOWN"
}

object LiteWebRootBackendNames {
    const val ULTRA_ENV = "ULTRA_ENV"
    const val KSU = "KSU"
    const val UNKNOWN = "UNKNOWN"
}

object LiteWebBootHooks {
    const val ULTRA_MODULE = "ULTRA_MODULE"
    const val KSU_MODULE = "KSU_MODULE"
    const val UNKNOWN = "UNKNOWN"
}

data class LiteWebModeInfo(
    val mode: String = LiteWebMode.UNKNOWN,
    val rootBackend: String = LiteWebRootBackendNames.UNKNOWN,
    val bootHook: String = LiteWebBootHooks.UNKNOWN,
    val daemonRunning: Boolean? = null,
    val daemonPort: Int? = null,
)

data class LiteWebBackupInfo(
    val present: Boolean? = null,
    val shaValid: Boolean? = null,
    val apkPath: String = "",
    val sha256: String = "",
)

/** 重启证据：daemon 是否确认在重启后由 boot 钩子拉起（持久化证明）。 */
data class LiteWebBootEvidence(
    val bootIdObserved: Boolean? = null,
    val persistent: Boolean? = null,
    val bootPersistence: String = LiteWebBootPersistence.UNKNOWN,
    val detail: String = "",
)

data class LiteWebDaemonInfo(
    val running: Boolean? = null,
    val port: Int = LiteWebPortPolicy.DEFAULT_PORT,
    val urlTokenPresent: Boolean = false,
)

/** 模式无关恢复/daemon 后端（可注入 fake；wm-core HiddenModeBackend 适配后注入）。 */
interface LiteWebHiddenModeBackend {
    fun mode(): LiteWebModeInfo

    fun startDaemon(): LiteWebRestoreStep

    fun stopDaemon(): LiteWebRestoreStep

    fun backup(): LiteWebBackupInfo

    fun bootEvidence(): LiteWebBootEvidence

    /** restore dry-run：返回计划步骤（不执行副作用）；ok=false 的步骤为前置不满足。 */
    fun restorePlan(): List<LiteWebRestoreStep>

    /** 取消隐藏：A=写 lite_hidden OFF；B=KSU stealth off。 */
    fun restoreUnhide(): LiteWebRestoreStep

    fun installApk(): LiteWebRestoreStep

    fun verifyPackage(): LiteWebRestoreStep

    fun restoreComponents(): LiteWebRestoreStep
}

object UnavailableHiddenModeBackend : LiteWebHiddenModeBackend {
    private fun unavailable(name: String) =
        LiteWebRestoreStep(name, false, "MODE_BACKEND_UNAVAILABLE")

    override fun mode(): LiteWebModeInfo = LiteWebModeInfo()
    override fun startDaemon() = unavailable("startDaemon")
    override fun stopDaemon() = unavailable("stopDaemon")
    override fun backup(): LiteWebBackupInfo = LiteWebBackupInfo()
    override fun bootEvidence(): LiteWebBootEvidence = LiteWebBootEvidence()
    override fun restorePlan(): List<LiteWebRestoreStep> = listOf(unavailable("restorePlan"))
    override fun restoreUnhide() = unavailable("restoreUnhide")
    override fun installApk() = unavailable("installApk")
    override fun verifyPackage() = unavailable("verifyPackage")
    override fun restoreComponents() = unavailable("restoreComponents")
}

/**
 * 两模式一致的完整恢复事务（自检 dry-run 与真实执行共用同一计划）：
 * 取消隐藏 → pm install -r 备份 APK → 回读包 → 恢复组件。
 */
class LiteWebModeRestoreTransaction(private val backend: LiteWebHiddenModeBackend) {
    fun plan(): List<LiteWebRestoreStep> = listOf(
        LiteWebRestoreStep("verifyBackupSha", backend.backup().shaValid == true),
        LiteWebRestoreStep("unhide", true),
        LiteWebRestoreStep("installApk", true),
        LiteWebRestoreStep("verifyPackageInstalled", true),
        LiteWebRestoreStep("restoreComponents", true),
    )

    fun execute(): List<LiteWebRestoreStep> {
        val steps = ArrayList<LiteWebRestoreStep>()
        val backup = runCatching { backend.backup() }.getOrElse { LiteWebBackupInfo() }
        val verify = LiteWebRestoreStep(
            "verifyBackupSha",
            backup.shaValid == true,
            if (backup.shaValid == true) "" else LiteWebRecoveryCodes.APK_SHA_INVALID,
        )
        steps += verify
        if (!verify.ok) return steps
        for (next in listOf(
            backend::restoreUnhide,
            backend::installApk,
            backend::verifyPackage,
            backend::restoreComponents,
        )) {
            val result = next()
            steps += result
            if (!result.ok) break
        }
        return steps
    }
}
