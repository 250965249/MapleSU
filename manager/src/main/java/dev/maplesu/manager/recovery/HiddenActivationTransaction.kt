package dev.maplesu.manager.recovery

/** daemon 启动+HTTP ping 验证结果（ping 失败不得继续卸载）。 */
data class DaemonVerification(
    val started: Boolean,
    val pingOk: Boolean,
    val port: Int? = null,
    val code: String = "",
    val detail: String = "",
)

/** 事务步骤名（固定顺序；服务端/内部返回 ok/fail+reason，UI 不出现“演练”字样）。 */
enum class FullHideStep(val wire: String) {
    BACKUP("backup"),
    WEBUI_START("webui_start"),
    WEBUI_PING("webui_ping"),
    BACKUP_SHA("backup_sha"),
    BOOT_PERSISTENCE("boot_persistence"),
    HIDE_STATE("hide_state"),
    UNINSTALL_APK("uninstall_apk"),
}

data class ActivationStep(
    val step: String,
    val ok: Boolean,
    val reason: String = "",
)

data class ActivationResult(
    val ok: Boolean,
    val code: String = "",
    val steps: List<ActivationStep> = emptyList(),
    val detail: String = "",
)

object ActivationCodes {
    const val BOOT_PERSISTENCE_UNPROVEN = BootPersistenceEvidence.UNPROVEN_CODE
    const val BACKUP_FAILED = "RECOVERY_BACKUP_FAILED"
    const val BACKUP_SHA_MISMATCH = "RECOVERY_APK_SHA_MISMATCH"
    const val DAEMON_UNVERIFIED = "LITEWEB_DAEMON_UNVERIFIED"
    const val HIDDEN_ON_FAILED = "LITE_HIDDEN_ON_FAILED"
    const val UNINSTALL_FAILED = "MANAGER_UNINSTALL_FAILED"
    const val ROLLBACK_INCOMPLETE = "ACTIVATION_ROLLBACK_INCOMPLETE"
}

/**
 * 真实卸载 APK 的一键事务（内部原语；服务端 API 由 wm-installer 暴露）。
 *
 * 固定步骤：`backup → webui_start → webui_ping → backup_sha → boot_persistence →
 * hide_state → uninstall_apk`。每步返回 ok/fail+reason；任一步失败立即回滚
 * （停 daemon / 取消隐藏 / 清备份），**绝不卸载**。
 *
 * 启动持久性未证明（[BootPersistenceEvidence.proven] == false）→ 在 boot_persistence 步
 * 失败并返回 `BOOT_PERSISTENCE_UNPROVEN`（卸载后重启将失去恢复入口）。
 */
class FullHideTransaction(
    private val prepare: () -> RecoveryPrepareResult,
    private val startDaemon: () -> DaemonVerification,
    private val verifyBackupSha: (RecoveryManifest) -> Boolean,
    private val writeHidden: (Boolean) -> Boolean,
    private val uninstall: () -> RecoveryCommandResult,
    private val stopDaemon: () -> Unit = {},
    private val clearBackup: () -> Unit = {},
    private val bootPersistence: BootPersistenceEvidence = BootPersistenceEvidence.UNPROVEN,
) {
    fun activate(): ActivationResult {
        val steps = mutableListOf<ActivationStep>()

        // 1. backup
        val prepared = prepare()
        if (prepared !is RecoveryPrepareResult.Ok) {
            val code = (prepared as? RecoveryPrepareResult.Failed)?.code ?: ActivationCodes.BACKUP_FAILED
            steps += ActivationStep(FullHideStep.BACKUP.wire, false, code)
            return ActivationResult(false, code, steps)
        }
        steps += ActivationStep(FullHideStep.BACKUP.wire, true)

        // 2-3. daemon start + ping
        val daemon = startDaemon()
        steps += ActivationStep(
            FullHideStep.WEBUI_START.wire, daemon.started,
            if (daemon.started) "" else daemon.detail.ifEmpty { daemon.code },
        )
        if (!daemon.started) return rollback(steps, ActivationCodes.DAEMON_UNVERIFIED, daemon.detail)
        steps += ActivationStep(
            FullHideStep.WEBUI_PING.wire, daemon.pingOk,
            if (daemon.pingOk) "" else daemon.detail.ifEmpty { "ping failed" },
        )
        if (!daemon.pingOk) return rollback(steps, ActivationCodes.DAEMON_UNVERIFIED, daemon.detail)

        // 4. backup apk sha re-check
        val shaOk = runCatching { verifyBackupSha(prepared.manifest) }.getOrDefault(false)
        steps += ActivationStep(
            FullHideStep.BACKUP_SHA.wire, shaOk,
            if (shaOk) "" else ActivationCodes.BACKUP_SHA_MISMATCH,
        )
        if (!shaOk) return rollback(steps, ActivationCodes.BACKUP_SHA_MISMATCH)

        // 5. boot persistence guard
        steps += ActivationStep(
            FullHideStep.BOOT_PERSISTENCE.wire, bootPersistence.proven,
            if (bootPersistence.proven) "" else BootPersistenceEvidence.UNPROVEN_CODE,
        )
        if (!bootPersistence.proven) {
            return rollback(steps, ActivationCodes.BOOT_PERSISTENCE_UNPROVEN, bootPersistence.detail)
        }

        // 6. hidden ON
        val hiddenOk = runCatching { writeHidden(true) }.getOrDefault(false)
        steps += ActivationStep(
            FullHideStep.HIDE_STATE.wire, hiddenOk,
            if (hiddenOk) "" else ActivationCodes.HIDDEN_ON_FAILED,
        )
        if (!hiddenOk) return rollback(steps, ActivationCodes.HIDDEN_ON_FAILED)

        // 7. uninstall apk
        val uninstalled = uninstall()
        val uninstallOk = uninstalled.code == 0
        steps += ActivationStep(
            FullHideStep.UNINSTALL_APK.wire, uninstallOk,
            if (uninstallOk) "" else uninstalled.output.trim(),
        )
        if (!uninstallOk) return rollback(steps, ActivationCodes.UNINSTALL_FAILED, uninstalled.output.trim())

        return ActivationResult(true, steps = steps)
    }

    private fun rollback(
        steps: List<ActivationStep>,
        code: String,
        detail: String = "",
    ): ActivationResult {
        val rollbackSteps = mutableListOf<ActivationStep>()
        val hiddenOff = runCatching { writeHidden(false) }.getOrDefault(false)
        rollbackSteps += ActivationStep("rollback_hide_state", hiddenOff)
        runCatching { stopDaemon() }
        rollbackSteps += ActivationStep("rollback_webui_stop", true)
        runCatching { clearBackup() }
        rollbackSteps += ActivationStep("rollback_backup_clear", true)
        val rollbackIncomplete = !hiddenOff
        return ActivationResult(
            ok = false,
            code = code,
            steps = steps + rollbackSteps,
            detail = if (rollbackIncomplete) "$detail;${ActivationCodes.ROLLBACK_INCOMPLETE}".trim(';') else detail,
        )
    }
}
