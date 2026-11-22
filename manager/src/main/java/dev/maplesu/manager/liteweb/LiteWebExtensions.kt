package dev.maplesu.manager.liteweb

/**
 * Lite WebUI 隐藏/恢复最终形态（纯 Kotlin，主机可测）。
 *
 * 一键隐藏（`POST /api/activate`）事务：
 * 校验端口 → 恢复前置（APK 备份存在 + sha 有效 + boot 持久化已证明）→ prepare（备份+sha）
 * → 应用端口（webui.conf + 重启监听 + 回读）→ startDaemon（wm-core，Ultra 环境 run_root_cmd 策略）
 * → pingDaemon（127.0.0.1:port /api/ping）→ 写隐藏 ON → 最终复核；任一步失败按已完成步骤逆序回滚
 * （写 OFF / 停 daemon / 还原端口），不进入半隐藏。真实卸载 APK 由 App 端在事务成功后执行。
 *
 * 一键恢复（`POST /api/restore {action:"full"}`）事务：备份 sha 校验 → `pm install -r`
 * → 回读包存在 → 写 hidden OFF → 恢复组件 → 验证；幂等，失败 fail-closed。
 */

/** 端口策略：默认 18427，1024..65535；启动自定义端口优先 + 默认候选回退；显式改端口严格绑定。 */
object LiteWebPortPolicy {
    const val DEFAULT_PORT = 18427
    const val MIN_PORT = 1024
    const val MAX_PORT = 65535
    const val CODE_RANGE = "LITEWEB_PORT_RANGE"
    const val CODE_CONFLICT = "LITEWEB_PORT_CONFLICT"

    fun validate(port: Int): String? =
        if (port in MIN_PORT..MAX_PORT) null else CODE_RANGE

    fun preferred(configured: Int, candidates: List<Int> = LiteWebConstants.PORT_CANDIDATES): List<Int> {
        if (validate(configured) != null) return candidates
        return listOf(configured) + candidates.filterNot { it == configured }
    }

    fun strict(configured: Int): List<Int> = listOf(configured)
}

// ------------------------------------------------------------------ steps / recovery

/**
 * 单步结果。
 *
 * [error] 是结构化失败码（成功时为空）；[detail] 只放诊断（路径/包名/exit code），
 * 绝不包含 token/rootKey。两者分开，避免把"细节"当"错误码"解析。
 */
data class LiteWebRestoreStep(
    val name: String,
    val ok: Boolean,
    val error: String = "",
    val detail: String = "",
)

object LiteWebBootPersistence {
    const val PROVEN = "proven"
    const val UNPROVEN = "unproven"
    const val UNKNOWN = "unknown"
}

data class LiteWebRecoveryStatus(
    /** null = 读不到（诚实未知）。 */
    val apkBackupPresent: Boolean? = null,
    val apkShaValid: Boolean? = null,
    val daemonRunning: Boolean? = null,
    val bootPersistence: String = LiteWebBootPersistence.UNKNOWN,
    val daemonUptimeSeconds: Long? = null,
)

object LiteWebRecoveryCodes {
    const val BACKEND_UNAVAILABLE = "ACTIVATE_BACKEND_UNAVAILABLE"
    const val BACKUP_MISSING = "APK_BACKUP_MISSING"
    const val APK_SHA_INVALID = "APK_BACKUP_SHA_INVALID"
    const val BOOT_UNPROVEN = "BOOT_PERSISTENCE_UNPROVEN"
    const val DAEMON_START_FAILED = "RECOVERY_DAEMON_START_FAILED"
    const val DAEMON_PING_FAILED = "RECOVERY_DAEMON_PING_FAILED"
    const val HIDDEN_WRITE_FAILED = "LITE_HIDDEN_WRITE_FAILED"
    const val PORT_APPLY_FAILED = "LITEWEB_PORT_APPLY_FAILED"
    const val ROLLBACK_FAILED = "ACTIVATE_ROLLBACK_FAILED"
    const val RESTORE_BACKEND_UNAVAILABLE = "RESTORE_BACKEND_UNAVAILABLE"
}

data class LiteWebHiddenView(
    val hidden: Boolean?,
    val port: Int,
    val recovery: LiteWebRecoveryStatus,
    val steps: List<LiteWebRestoreStep> = emptyList(),
    /** null = package presence has not been verified; never infer removal from hidden state. */
    val managerUninstalled: Boolean? = null,
)

// ------------------------------------------------------------------ shared root daemon port

interface LiteWebRecoveryPort {
    fun recovery(): LiteWebRecoveryStatus

    /** 写 `/data/adb/maplesu/lite_hidden`（ON/OFF）并回读校验。 */
    fun writeHidden(enabled: Boolean): LiteWebRestoreStep

    fun currentPort(): Int

    /** 最近一次事务步骤（GET /api/hidden 回显）；默认空。 */
    fun recordedSteps(): List<LiteWebRestoreStep> = emptyList()

    fun recordSteps(steps: List<LiteWebRestoreStep>) = Unit
}

interface LiteWebActivatePort : LiteWebRecoveryPort {
    /** wm-core FullHideTransaction.prepare：备份 APK + 记录 sha。 */
    fun prepareBackup(): LiteWebRestoreStep

    /** wm-core daemon 启动（Ultra 环境 run_root_cmd；失败即 activate 失败）。 */
    fun startDaemon(): LiteWebRestoreStep

    /** ping `127.0.0.1:<port>/api/ping`（恢复通道可用性）。 */
    fun pingDaemon(port: Int): LiteWebRestoreStep

    /** 应用新端口：写 webui.conf（0600）+ 重启监听 + 回读实际端口。 */
    fun applyPort(port: Int?): LiteWebRestoreStep

    fun revertPort(): LiteWebRestoreStep

    fun stopDaemon(): LiteWebRestoreStep
}

object UnavailableActivatePort : LiteWebActivatePort {
    private fun unavailable(name: String) = LiteWebRestoreStep(name, false, LiteWebRecoveryCodes.BACKEND_UNAVAILABLE)

    override fun recovery(): LiteWebRecoveryStatus = LiteWebRecoveryStatus()

    override fun writeHidden(enabled: Boolean) = unavailable("writeHidden")

    override fun currentPort(): Int = LiteWebPortPolicy.DEFAULT_PORT

    override fun prepareBackup() = unavailable("prepareBackup")

    override fun startDaemon() = unavailable("startDaemon")

    override fun pingDaemon(port: Int) = unavailable("pingDaemon")

    override fun applyPort(port: Int?) = unavailable("applyPort")

    override fun revertPort() = unavailable("revertPort")

    override fun stopDaemon() = unavailable("stopDaemon")
}

interface LiteWebRestorePort : LiteWebRecoveryPort {
    fun verifyBackupSha(): LiteWebRestoreStep

    fun installApk(): LiteWebRestoreStep

    fun verifyPackageInstalled(): LiteWebRestoreStep

    fun restoreComponents(): LiteWebRestoreStep

    fun verify(): LiteWebRestoreStep

    fun needReboot(): Boolean = false
}

object UnavailableRestorePort : LiteWebRestorePort {
    private fun unavailable(name: String) =
        LiteWebRestoreStep(name, false, LiteWebRecoveryCodes.RESTORE_BACKEND_UNAVAILABLE)

    override fun recovery(): LiteWebRecoveryStatus = LiteWebRecoveryStatus()

    override fun writeHidden(enabled: Boolean) = unavailable("writeHidden")

    override fun currentPort(): Int = LiteWebPortPolicy.DEFAULT_PORT

    override fun verifyBackupSha() = unavailable("verifyBackupSha")

    override fun installApk() = unavailable("installApk")

    override fun verifyPackageInstalled() = unavailable("verifyPackageInstalled")

    override fun restoreComponents() = unavailable("restoreComponents")

    override fun verify() = unavailable("verify")
}

// ------------------------------------------------------------------ activate transaction

data class LiteWebActivateResult(
    val ok: Boolean,
    val port: Int,
    val recoveryUrlTokenPresent: Boolean,
    val recovery: LiteWebRecoveryStatus,
    val steps: List<LiteWebRestoreStep>,
    val code: String = "",
)

class LiteWebActivateTransaction(
    private val port: LiteWebActivatePort,
    private val tokenPresent: () -> Boolean = { true },
) {
    fun run(requestedPort: Int?): LiteWebActivateResult {
        val steps = ArrayList<LiteWebRestoreStep>()
        val recovery = runCatching { port.recovery() }.getOrElse { LiteWebRecoveryStatus() }
        // 后端完全未接线（三项事实全 null + boot unknown）→ 显式不可用，不误报"备份缺失"。
        if (recovery.apkBackupPresent == null && recovery.apkShaValid == null &&
            recovery.daemonRunning == null && recovery.bootPersistence == LiteWebBootPersistence.UNKNOWN
        ) {
            steps += LiteWebRestoreStep("preconditionBackend", false, LiteWebRecoveryCodes.BACKEND_UNAVAILABLE)
            port.recordSteps(steps)
            return LiteWebActivateResult(
                ok = false,
                port = runCatching { port.currentPort() }.getOrDefault(LiteWebPortPolicy.DEFAULT_PORT),
                recoveryUrlTokenPresent = false,
                recovery = recovery,
                steps = steps,
                code = LiteWebRecoveryCodes.BACKEND_UNAVAILABLE,
            )
        }
        if (requestedPort != null) {
            val code = LiteWebPortPolicy.validate(requestedPort)
            val step = if (code == null) {
                LiteWebRestoreStep("validatePort", true)
            } else {
                LiteWebRestoreStep("validatePort", false, code)
            }
            steps += step
            if (!step.ok) return failure(steps, recovery, code)
        }
        // 6) 恢复通道前置：备份存在 + sha 有效；boot 持久化未证明 → 拒绝且不卸载。
        if (recovery.apkBackupPresent != true) {
            steps += LiteWebRestoreStep("preconditionBackup", false, LiteWebRecoveryCodes.BACKUP_MISSING)
            return failure(steps, recovery, LiteWebRecoveryCodes.BACKUP_MISSING)
        }
        if (recovery.apkShaValid != true) {
            steps += LiteWebRestoreStep("preconditionBackupSha", false, LiteWebRecoveryCodes.APK_SHA_INVALID)
            return failure(steps, recovery, LiteWebRecoveryCodes.APK_SHA_INVALID)
        }
        if (recovery.bootPersistence == LiteWebBootPersistence.UNPROVEN) {
            steps += LiteWebRestoreStep("preconditionBootPersistence", false, LiteWebRecoveryCodes.BOOT_UNPROVEN)
            return failure(steps, recovery, LiteWebRecoveryCodes.BOOT_UNPROVEN)
        }
        steps += LiteWebRestoreStep("preconditionBootPersistence", true)

        val prepared = port.prepareBackup()
        steps += prepared
        if (!prepared.ok) return rollbackAndFail(steps, recovery, prepared.error, emptyList())

        val applied = port.applyPort(requestedPort)
        steps += applied
        if (!applied.ok) return rollbackAndFail(steps, recovery, applied.error, listOf("applyPort"))

        val started = port.startDaemon()
        steps += started
        if (!started.ok) return rollbackAndFail(steps, recovery, started.error, listOf("applyPort", "startDaemon"))

        val actualPort = runCatching { port.currentPort() }.getOrDefault(requestedPort ?: port.currentPort())
        val pinged = port.pingDaemon(actualPort)
        steps += pinged
        if (!pinged.ok) {
            return rollbackAndFail(
                steps, recovery, pinged.error, listOf("applyPort", "startDaemon"),
            )
        }

        val hidden = port.writeHidden(true)
        steps += hidden
        if (!hidden.ok) {
            return rollbackAndFail(
                steps, recovery, hidden.error, listOf("applyPort", "startDaemon", "writeHidden"),
            )
        }

        val finalRecovery = runCatching { port.recovery() }.getOrDefault(recovery)
        val verified = finalRecovery.apkBackupPresent == true &&
            finalRecovery.apkShaValid == true && finalRecovery.daemonRunning == true
        steps += LiteWebRestoreStep(
            "verifyRecovery",
            verified,
            if (verified) "" else "RECOVERY_CHANNEL_NOT_VERIFIED",
        )
        if (!verified) {
            return rollbackAndFail(
                steps, finalRecovery, "RECOVERY_CHANNEL_NOT_VERIFIED",
                listOf("applyPort", "startDaemon", "writeHidden"),
            )
        }
        val token = runCatching { tokenPresent() }.getOrDefault(false)
        steps += LiteWebRestoreStep("urlTokenPresent", token, "")
        port.recordSteps(steps)
        return LiteWebActivateResult(
            ok = true,
            port = actualPort,
            recoveryUrlTokenPresent = token,
            recovery = finalRecovery,
            steps = steps,
        )
    }

    private fun rollbackAndFail(
        completed: List<LiteWebRestoreStep>,
        recovery: LiteWebRecoveryStatus,
        code: String?,
        completedNames: List<String>,
    ): LiteWebActivateResult {
        val steps = ArrayList(completed)
        // 逆序回滚：写 OFF → 停 daemon → 还原端口。
        if ("writeHidden" in completedNames) {
            steps += rollback("rollback:writeHiddenOff") { port.writeHidden(false) }
        }
        if ("startDaemon" in completedNames) {
            steps += rollback("rollback:stopDaemon") { port.stopDaemon() }
        }
        if ("applyPort" in completedNames) {
            steps += rollback("rollback:revertPort") { port.revertPort() }
        }
        val rollbackFailed = steps.drop(completed.size).any { !it.ok }
        val effectiveCode = when {
            rollbackFailed -> LiteWebRecoveryCodes.ROLLBACK_FAILED
            code.isNullOrEmpty() -> "ACTIVATE_FAILED"
            else -> code
        }
        steps += LiteWebRestoreStep(
            "rollbackComplete", !rollbackFailed,
            if (rollbackFailed) "部分步骤回滚失败，请手动恢复" else "",
        )
        port.recordSteps(steps)
        return LiteWebActivateResult(
            ok = false,
            port = runCatching { port.currentPort() }.getOrDefault(LiteWebPortPolicy.DEFAULT_PORT),
            recoveryUrlTokenPresent = false,
            recovery = runCatching { port.recovery() }.getOrDefault(recovery),
            steps = steps,
            code = effectiveCode,
        )
    }

    private fun failure(
        steps: List<LiteWebRestoreStep>,
        recovery: LiteWebRecoveryStatus,
        code: String?,
    ): LiteWebActivateResult {
        port.recordSteps(steps)
        return LiteWebActivateResult(
            ok = false,
            port = runCatching { port.currentPort() }.getOrDefault(LiteWebPortPolicy.DEFAULT_PORT),
            recoveryUrlTokenPresent = false,
            recovery = recovery,
            steps = steps,
            code = code ?: "ACTIVATE_FAILED",
        )
    }

    private fun rollback(name: String, action: () -> LiteWebRestoreStep): LiteWebRestoreStep {
        val result = runCatching(action).getOrElse {
            LiteWebRestoreStep(name, false, "ROLLBACK_EXCEPTION:${it.javaClass.simpleName}")
        }
        return if (result.name == name) result else result.copy(name = name)
    }
}

// ------------------------------------------------------------------ restore transaction

data class LiteWebRestoreResult(
    val action: String,
    val steps: List<LiteWebRestoreStep>,
    val needReboot: Boolean,
) {
    val ok: Boolean get() = steps.isNotEmpty() && steps.all { it.ok }
}

object LiteWebRestoreActions {
    const val UNHIDE = "unhide"
    const val FULL = "full"
    val ALL: Set<String> = setOf(UNHIDE, FULL)

    fun validate(action: String?): String? = when {
        action == null || action.isBlank() -> "RESTORE_ACTION_MISSING"
        action in ALL -> null
        else -> "RESTORE_ACTION_INVALID"
    }
}

class LiteWebRestoreTransaction(private val port: LiteWebRestorePort) {
    /** 仅取消隐藏（POST /api/hidden enable=false 等价）。 */
    fun unhide(): LiteWebRestoreResult = execute(
        LiteWebRestoreActions.UNHIDE,
        listOf({ port.writeHidden(false) }, port::verify),
    )

    /** 完整恢复：校验备份 → 重装 APK → 回读包 → 写 OFF → 恢复组件 → 验证。 */
    fun full(): LiteWebRestoreResult = execute(
        LiteWebRestoreActions.FULL,
        listOf(
            port::verifyBackupSha,
            port::installApk,
            port::verifyPackageInstalled,
            { port.writeHidden(false) },
            port::restoreComponents,
            port::verify,
        ),
    )

    fun run(action: String): LiteWebRestoreResult = when (action) {
        LiteWebRestoreActions.UNHIDE -> unhide()
        LiteWebRestoreActions.FULL -> full()
        else -> LiteWebRestoreResult(
            action,
            listOf(LiteWebRestoreStep("validate", false, "RESTORE_ACTION_INVALID")),
            false,
        )
    }

    private fun execute(action: String, planned: List<() -> LiteWebRestoreStep>): LiteWebRestoreResult {
        val steps = ArrayList<LiteWebRestoreStep>()
        for (step in planned) {
            val result = runCatching(step).getOrElse {
                LiteWebRestoreStep("exception", false, "RESTORE_EXCEPTION:${it.javaClass.simpleName}")
            }
            steps += result
            if (!result.ok) break
        }
        port.recordSteps(steps)
        return LiteWebRestoreResult(
            action = action,
            steps = steps,
            needReboot = steps.all { it.ok } && runCatching { port.needReboot() }.getOrDefault(false),
        )
    }
}

// ------------------------------------------------------------------ unhide (deactivate parasite)

/**
 * 「完整解除寄生」的固定步骤（顺序即执行顺序，最后一步会杀掉 daemon 自己）。
 *
 * 与 App 侧 `HiddenDeactivateStep` 同义，但这是 **WebUI daemon 自己的入口**：
 * 隐藏生效后 App 入口被抑制、`POST /api/activate` 也 501，用户唯一能自救的就是这个接口。
 */
object LiteWebUnhideSteps {
    const val RESTORE_HOST_SO = "restore_host_so"
    const val REMOVE_LOADER = "remove_loader"
    const val REVOKE_SU_AUTH = "revoke_su_auth"
    const val STOP_DAEMON = "stop_daemon"

    /**
     * **advisory** 步：把历史半截备份隔离到 `recovery/host-quarantine-<date>/`（只改名不删除）。
     *
     * 只在确实存在陈旧残留时出现，且**只有完整备份**（≥1 个）才会让本步缺席。它不属于
     * 「解除寄生成功」的必要条件：真机现场 4 个 10-30 遗留的半截目录曾把一键解除钉死成
     * 永久 409（D2），所以本步失败**不得**改写解除结论。
     */
    const val CLEANUP_STALE_BACKUPS = "cleanup_stale_backups"

    /** 必须成功的四步（顺序即执行顺序，最后一步会杀掉 daemon 自己）。 */
    val ORDER: List<String> = listOf(RESTORE_HOST_SO, REMOVE_LOADER, REVOKE_SU_AUTH, STOP_DAEMON)

    /** 允许失败、且失败不改变解除结论的「尽力而为」步骤。 */
    val ADVISORY: Set<String> = setOf(CLEANUP_STALE_BACKUPS)
}

/** 解除寄生的结构化失败码（与 [dev.maplesu.manager.litehidden.ParasiteCodes] 同风格，不复用其常量值）。 */
object LiteWebUnhideCodes {
    const val RESTORE_HOST_SO_FAILED = "HIDDEN_RESTORE_HOST_SO_FAILED"
    const val HOST_BACKUP_AMBIGUOUS = "HIDDEN_HOST_BACKUP_AMBIGUOUS"
    const val LOADER_DELETE_FAILED = "HIDDEN_LOADER_DELETE_FAILED"
    const val SU_AUTH_REVOKE_FAILED = "HIDDEN_SU_AUTH_REVOKE_FAILED"
    const val SU_AUTH_BACKEND_UNAVAILABLE = "HIDDEN_SU_AUTH_BACKEND_UNAVAILABLE"
    const val DAEMON_STOP_FAILED = "LITEWEB_DAEMON_STOP_FAILED"
    const val HIDDEN_STATE_OFF_FAILED = "HIDDEN_STATE_OFF_FAILED"

    /** 陈旧残留隔离失败（advisory 步自己的错误码；不影响解除结论）。 */
    const val STALE_BACKUP_QUARANTINE_FAILED = "HIDDEN_STALE_BACKUP_QUARANTINE_FAILED"
}

/**
 * 解除寄生端口：实现方**按 [LiteWebUnhideSteps.ORDER] 顺序执行**，失败即停、不回滚已完成步骤
 * （宿主库已逐字节还原是好事，不能因为后面一步失败再把它改回去），并如实返回每一步。
 *
 * 未接线时返回 [UnavailableUnhidePort]（handler 仍回 501，绝不假装已解除）。
 */
fun interface LiteWebUnhidePort {
    fun deactivate(): List<LiteWebRestoreStep>
}

object UnavailableUnhidePort : LiteWebUnhidePort {
    override fun deactivate(): List<LiteWebRestoreStep> = listOf(
        LiteWebRestoreStep(
            LiteWebUnhideSteps.RESTORE_HOST_SO,
            false,
            LiteWebRecoveryCodes.RESTORE_BACKEND_UNAVAILABLE,
        ),
    )
}

/** 解除结果：`ok` 只有在**四步全部 ok** 时才为 true；失败步与错误码单独给出，前端不必猜。 */
data class LiteWebUnhideResult(
    val ok: Boolean,
    val steps: List<LiteWebRestoreStep>,
    val failedStep: String = "",
    val code: String = "",
    /** 失败可重试（已完成的步骤保留，前端可原样再发一次）。后端不可用/成功时=false。 */
    val retryable: Boolean = false,
) {
    val backendUnavailable: Boolean
        get() = steps.isNotEmpty() && steps.all { it.error == LiteWebRecoveryCodes.RESTORE_BACKEND_UNAVAILABLE }
}

/**
 * 解除寄生事务：只做「顺序 + 失败即停 + 诚实汇总」，不自己碰 root。
 *
 * 为什么失败即停：停 daemon 是最后一步且会杀掉服务本身 —— 前面任何一步失败都必须**留住**
 * daemon（保留 WebUI 与重试通道），否则用户彻底失去入口。
 */
class LiteWebUnhideTransaction(private val port: LiteWebUnhidePort) {
    fun run(): LiteWebUnhideResult {
        val steps = runCatching { port.deactivate() }.getOrElse {
            listOf(
                LiteWebRestoreStep(
                    LiteWebUnhideSteps.RESTORE_HOST_SO,
                    false,
                    "UNHIDE_EXCEPTION:${it.javaClass.simpleName}",
                ),
            )
        }
        // advisory 步（隔离陈旧备份）失败不改写结论：必须做的四步都 ok 就是解除成功，
        // 否则用户的「一键解除」会被一次清理失败重新变成 409（D2 的同类病）。
        val failed = steps.firstOrNull { !it.ok && it.name !in LiteWebUnhideSteps.ADVISORY }
        val mandatoryOk = steps.any { it.name in LiteWebUnhideSteps.ORDER && it.ok }
        val code = failed?.error.orEmpty()
        return LiteWebUnhideResult(
            ok = mandatoryOk && failed == null,
            steps = steps,
            failedStep = failed?.name.orEmpty(),
            code = code,
            retryable = failed != null && code != LiteWebRecoveryCodes.RESTORE_BACKEND_UNAVAILABLE,
        )
    }
}

// ------------------------------------------------------------------ settings whitelist

sealed interface LiteWebSettingsWriteResult {
    data class Ok(val key: String, val value: String) : LiteWebSettingsWriteResult

    data class Forbidden(val key: String) : LiteWebSettingsWriteResult

    data class Invalid(val key: String, val reason: String) : LiteWebSettingsWriteResult

    data class Unavailable(val reason: String) : LiteWebSettingsWriteResult

    data class Failed(val key: String, val reason: String) : LiteWebSettingsWriteResult
}

interface LiteWebSettingsPort {
    fun read(): Map<String, String>

    fun write(key: String, value: String): LiteWebSettingsWriteResult
}

object UnavailableSettingsPort : LiteWebSettingsPort {
    override fun read(): Map<String, String> = emptyMap()

    override fun write(key: String, value: String): LiteWebSettingsWriteResult =
        LiteWebSettingsWriteResult.Unavailable("SETTINGS_BACKEND_UNAVAILABLE")
}

object LiteWebSettingsPolicy {
    val WRITABLE: Set<String> = setOf(
        "ui_style", "theme", "language", "snow", "wallpaper_enabled", "wallpaper_switch",
    )
    val FORBIDDEN: Set<String> = setOf(
        "root", "authorization", "superuser", "selinux", "adb", "module_install",
        "stealth", "hidden_code", "lite_hidden", "installer",
    )

    private val KEY_PATTERN = Regex("^[a-z][a-z0-9_]{1,31}$")
    private val BOOLEAN_KEYS = setOf("snow", "wallpaper_enabled", "wallpaper_switch")
    private val TOKEN_KEYS = setOf("ui_style", "theme", "language")
    private val VALUE_PATTERN = Regex("^[A-Za-z0-9._-]{0,64}$")

    fun checkKey(key: String): String? = when {
        key in FORBIDDEN -> "SETTINGS_KEY_FORBIDDEN"
        key !in WRITABLE -> "SETTINGS_KEY_NOT_WRITABLE"
        !KEY_PATTERN.matches(key) -> "SETTINGS_KEY_INVALID"
        else -> null
    }

    fun checkValue(key: String, value: String): String? = when {
        value.length > 256 -> "SETTINGS_VALUE_TOO_LONG"
        key in BOOLEAN_KEYS && value !in setOf("true", "false") -> "SETTINGS_VALUE_INVALID_BOOLEAN"
        key in TOKEN_KEYS && !VALUE_PATTERN.matches(value) -> "SETTINGS_VALUE_INVALID"
        value.contains('\u0000') || value.any { it.code < 0x20 } -> "SETTINGS_VALUE_INVALID"
        else -> null
    }
}

// ------------------------------------------------------------------ diagnostics / work mode / module action

data class LiteWebDiagnosticsView(
    val probe: String = "unknown",
    val rootBackend: String = "unavailable",
    val port: Int = LiteWebPortPolicy.DEFAULT_PORT,
    val version: String = "",
    val mode: String = "UNKNOWN",
    val serverVersion: Int = LiteWebConstants.SERVER_VERSION,
    val apkBackupPresent: Boolean? = null,
    val apkShaValid: Boolean? = null,
    val daemonUptimeSeconds: Long? = null,
    val bootPersistence: String = LiteWebBootPersistence.UNKNOWN,
)

interface LiteWebDiagnosticsPort {
    fun read(): LiteWebDiagnosticsView
}

object UnavailableDiagnosticsPort : LiteWebDiagnosticsPort {
    override fun read(): LiteWebDiagnosticsView = LiteWebDiagnosticsView()
}

data class LiteWebWorkModeView(
    val mode: String = "UNKNOWN",
    val canSwitch: Boolean = false,
    val blocker: String? = "MODE_SWITCH_READ_ONLY",
    val target: String = "",
)

interface LiteWebWorkModePort {
    fun read(): LiteWebWorkModeView
}

object UnavailableWorkModePort : LiteWebWorkModePort {
    override fun read(): LiteWebWorkModeView = LiteWebWorkModeView()
}

sealed interface LiteWebModuleActionResult {
    data class Ok(val moduleId: String, val action: String, val output: String) : LiteWebModuleActionResult

    data class Failed(val code: String, val reason: String) : LiteWebModuleActionResult

    data class Unavailable(val reason: String) : LiteWebModuleActionResult
}

interface LiteWebModuleActionPort {
    fun run(moduleId: String, action: String): LiteWebModuleActionResult
}

object UnavailableModuleActionPort : LiteWebModuleActionPort {
    override fun run(moduleId: String, action: String): LiteWebModuleActionResult =
        LiteWebModuleActionResult.Unavailable("MODULE_ACTION_BACKEND_UNAVAILABLE")
}
