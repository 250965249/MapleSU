package dev.maplesu.manager.recovery

import kotlinx.serialization.Serializable

/** 一次 root 命令（daemon/恢复步骤用；主机测试注入 fake）。 */
data class RecoveryCommandResult(val code: Int, val output: String)

fun interface RecoveryCommandRunner {
    fun run(script: String): RecoveryCommandResult
}

/** 恢复步骤报告（每步独立结果，失败不合并成"成功"）。 */
@Serializable
data class RecoveryRestoreReport(
    val ok: Boolean,
    val code: String = "",
    val steps: List<String> = emptyList(),
    val detail: String = "",
    val awaitingConfirmation: Boolean = false,
    val completed: Boolean = false,
    val restoring: Boolean = false,
) {
    /** Only fixed status fields, never shell output, confirmation nonce or access token. */
    fun diagnosticLine(confirmation: Boolean = false): String {
        val safeCode = code.takeIf { it.matches(Regex("^[A-Z][A-Z0-9_]{0,79}$")) }
            ?: if (ok) "OK" else "UNSPECIFIED"
        val safeSteps = steps.map { it.substringBefore('(') }
            .filter { it.matches(Regex("^[a-z0-9_]+:(ok|pending|failed)$")) }
        return "MAPLESU_RESTORE phase=${if (confirmation) "confirm" else "install"} " +
            "ok=$ok awaiting=$awaitingConfirmation code=$safeCode steps=${safeSteps.joinToString(",")}"
    }
}

object RestoreCodes {
    const val VERIFY_FAILED = "RECOVERY_VERIFY_FAILED"
    const val APK_SHA_MISMATCH = "RECOVERY_APK_SHA_MISMATCH"
    const val APK_STAGE_FAILED = "RECOVERY_APK_STAGE_FAILED"
    const val APK_INSTALL_FAILED = "RECOVERY_APK_INSTALL_FAILED"
    const val APK_INSTALL_VERIFY_FAILED = "RECOVERY_APK_INSTALL_VERIFY_FAILED"
    const val HIDDEN_OFF_FAILED = "RECOVERY_HIDDEN_OFF_FAILED"
    const val LAUNCHER_FAILED = "RECOVERY_LAUNCHER_FAILED"
    const val DATA_VERIFY_FAILED = "RECOVERY_DATA_VERIFY_FAILED"
    const val PARASITE_CLEANUP_FAILED = "RECOVERY_PARASITE_CLEANUP_FAILED"
}

data class RecoveryCleanupResult(
    val ok: Boolean,
    val code: String = "",
    val steps: List<String> = emptyList(),
)

/**
 * `pm install` 的 APK **必须先搬到 `/data/local/tmp`**。
 *
 * 真机实测：`pm install -r /data/adb/maplesu/recovery/manager.apk` 会失败——
 * system_server 无权读 `adb_data_file`（"System server has no access to read file context
 * u:object_r:adb_data_file:s0"）。`/data/local/tmp` 是 `shell_data_file`，安装会话可读。
 * 返回落盘路径；失败返回 null（调用方 fail-closed，不继续安装）。
 */
internal fun stageApkForInstall(
    runner: (String) -> RecoveryCommandResult,
    apkPath: String,
): String? {
    val staged = "/data/local/tmp/maplesu-install-${System.currentTimeMillis()}.apk"
    var ready = false
    try {
        val copy = runner("cp -f '$apkPath' '$staged' && chmod 0644 '$staged' && echo LITE_OK")
        ready = copy.code == 0 && copy.output.contains("LITE_OK")
        return if (ready) staged else null
    } finally {
        if (!ready) cleanupStagedApk(runner, staged)
    }
}

internal fun cleanupStagedApk(runner: (String) -> RecoveryCommandResult, staged: String) {
    runner("rm -f '$staged' 2>/dev/null; echo LITE_OK")
}

internal fun installStagedApk(
    runner: (String) -> RecoveryCommandResult,
    staged: String,
): RecoveryCommandResult = try {
    runner(
        "(trap 'rm -f \"$staged\"' EXIT; " +
            "trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; " +
            "pm install -r '$staged')",
    )
} finally {
    cleanupStagedApk(runner, staged)
}

/**
 * 恢复管理器 APK（`POST /api/restore {action:"full"}` 的服务端实现）：
 * 备份校验 → APK 回装 → 桌面入口与保留数据回读 → Ultra 待确认票据 → hidden OFF → 管理器接管。
 * Ultra 由 prepareHandover 持久化待确认状态，保留宿主启动入口与恢复身份，确认后再清理。
 * 没有两阶段接管的既有调用仍按 cleanup / finalizeRestoration 完成恢复。
 * 任一步失败即返回结构化失败，且**不继续后续步骤**（fail-closed）。
 */
class RecoveryRestoreService(
    private val bundle: RecoveryBundle,
    private val runner: RecoveryCommandRunner,
    private val packageName: String = "dev.maplesu.manager",
    private val apkPath: String = RecoveryPaths.APK,
    private val hiddenStatePath: String = RecoveryPaths.HIDDEN_STATE,
    private val cleanup: (() -> RecoveryCleanupResult)? = null,
    private val retainedUid: () -> Int? = { null },
    private val finalizeRestoration: () -> RecoveryCleanupResult = { RecoveryCleanupResult(true) },
    private val prepareHandover: (() -> RecoveryCleanupResult)? = null,
) {
    fun restoreFull(): RecoveryRestoreReport {
        val steps = mutableListOf<String>()
        val verification = bundle.verify()
        steps += if (verification.ok) "verify:ok" else "verify:failed(${verification.problems.joinToString(",")})"
        if (!verification.ok) {
            return RecoveryRestoreReport(false, RestoreCodes.VERIFY_FAILED, steps, verification.code)
        }
        val manifest = verification.manifest!!
        if (manifest.packageName != packageName) {
            return RecoveryRestoreReport(false, RestoreCodes.VERIFY_FAILED, steps, "package_mismatch")
        }

        val sha = runner.run("sha256sum '$apkPath'")
        val backupSha = sha.output.trim().substringBefore(' ')
        steps += "apk_sha:${if (sha.code == 0 && backupSha == manifest.apkSha256) "ok" else "mismatch"}"
        if (sha.code != 0 || backupSha != manifest.apkSha256) {
            return RecoveryRestoreReport(false, RestoreCodes.APK_SHA_MISMATCH, steps, backupSha)
        }

        // pm install 从 /data/adb 读不到（system_server 无权读 adb_data_file）→ 先搬到
        // /data/local/tmp（shell_data_file），装完立刻删。
        val staged = stageApkForInstall(runner::run, apkPath)
        steps += "apk_stage:${if (staged != null) "ok" else "failed"}"
        if (staged == null) {
            return RecoveryRestoreReport(false, RestoreCodes.APK_STAGE_FAILED, steps, apkPath)
        }
        val install = installStagedApk(runner::run, staged)
        val installed = install.code == 0 && install.output.lineSequence().any { it.trim() == "Success" }
        steps += "pm_install:${if (installed) "ok" else "failed"}"
        if (!installed) {
            return RecoveryRestoreReport(false, RestoreCodes.APK_INSTALL_FAILED, steps, install.output.trim())
        }

        val pathProbe = runner.run("pm path '$packageName'")
        val pathOk = pathProbe.code == 0 && pathProbe.output.lineSequence().any {
            it.trim().matches(Regex("^package:/data/app/[^\\r\\n]+/base\\.apk$"))
        }
        steps += "pm_path:${if (pathOk) "ok" else "failed"}"
        if (!pathOk) {
            return RecoveryRestoreReport(false, RestoreCodes.APK_INSTALL_VERIFY_FAILED, steps, pathProbe.output.trim())
        }

        val entry = runner.run(
            "pm enable --user 0 '$packageName' >/dev/null 2>&1 && " +
                "pm enable --user 0 '$packageName/com.maplesu.core.ui.LauncherAlias' >/dev/null 2>&1 && " +
                "ENTRY=\$(cmd package resolve-activity --brief --user 0 -a android.intent.action.MAIN " +
                "-c android.intent.category.LAUNCHER '$packageName' 2>/dev/null | tail -n 1) && " +
                "[ \"\$ENTRY\" = '$packageName/com.maplesu.core.ui.LauncherAlias' ] && " +
                "echo MAPLESU_RESTORE_LAUNCHER_OK",
        )
        val entryOk = entry.code == 0 && marker(entry.output, "MAPLESU_RESTORE_LAUNCHER_OK")
        steps += "launcher:${if (entryOk) "ok" else "failed"}"
        if (!entryOk) return RecoveryRestoreReport(false, RestoreCodes.LAUNCHER_FAILED, steps)

        val expectedUid = retainedUid()
        if (expectedUid != null && expectedUid !in 10000..99999) {
            steps += "data:failed(DATA_RECEIPT_INVALID)"
            return RecoveryRestoreReport(false, RestoreCodes.DATA_VERIFY_FAILED, steps, "DATA_RECEIPT_INVALID")
        }
        val dataFailure = verifyManagerData(expectedUid, manifest.createdAt, steps)
        steps += if (dataFailure == null) "data:ok" else "data:failed($dataFailure)"
        if (dataFailure != null) return RecoveryRestoreReport(false, RestoreCodes.DATA_VERIFY_FAILED, steps, dataFailure)

        // Ultra retains the host bootstrap and recovery identity until the manager takes over.
        val cleaned = if (prepareHandover != null) RecoveryCleanupResult(true)
            else runCatching { cleanup?.invoke() }.getOrNull()
        if (cleaned != null) steps += cleaned.steps
        if (cleaned?.ok != true) {
            return RecoveryRestoreReport(
                false, cleaned?.code?.ifEmpty { RestoreCodes.PARASITE_CLEANUP_FAILED }
                    ?: RestoreCodes.PARASITE_CLEANUP_FAILED, steps,
            )
        }

        // Boot recovery accepts hidden=1 OR a pending ticket. Persist the ticket first:
        // a crash/write failure after hidden OFF must never disable both boot conditions.
        if (prepareHandover != null) {
            val handover = runCatching { prepareHandover?.invoke() }.getOrNull()
            if (handover?.ok != true) {
                return RecoveryRestoreReport(false, handover?.code?.ifEmpty { "RECOVERY_HANDOVER_WRITE_FAILED" }
                    ?: "RECOVERY_HANDOVER_WRITE_FAILED", steps)
            }
            steps += handover.steps
        }

        val hiddenOff = runner.run(
            "mkdir -p '${hiddenStatePath.substringBeforeLast('/')}' && " +
                "printf '0' > '$hiddenStatePath' && chmod 600 '$hiddenStatePath' && " +
                "[ \"\$(cat '$hiddenStatePath' 2>/dev/null)\" = '0' ] && echo MAPLESU_RESTORE_HIDDEN_OFF_OK",
        )
        val hiddenOk = hiddenOff.code == 0 && marker(hiddenOff.output, "MAPLESU_RESTORE_HIDDEN_OFF_OK")
        steps += "hidden_off:${if (hiddenOk) "ok" else "failed"}"
        if (!hiddenOk) {
            return RecoveryRestoreReport(false, RestoreCodes.HIDDEN_OFF_FAILED, steps, hiddenOff.output.trim())
        }
        if (prepareHandover != null) {
            // Some ROMs block background activity launches. Leave the web entry alive either way.
            val launch = runner.run("am start --user 0 -n '$packageName/com.maplesu.core.ui.MainActivity' --ez maplesu_restore true")
            steps += "launch_manager:${if (launch.code == 0) "ok" else "pending"}"
            return RecoveryRestoreReport(true, steps = steps, awaitingConfirmation = true)
        }
        val finalized = runCatching(finalizeRestoration).getOrNull()
        if (finalized != null) steps += finalized.steps
        if (finalized?.ok != true) {
            return RecoveryRestoreReport(false, finalized?.code?.ifEmpty { RestoreCodes.PARASITE_CLEANUP_FAILED }
                ?: RestoreCodes.PARASITE_CLEANUP_FAILED, steps)
        }
        return RecoveryRestoreReport(true, "", steps)
    }

    private fun marker(output: String, value: String): Boolean =
        output.lineSequence().map(String::trim).count { it == value } == 1

    private fun verifyManagerData(expectedUid: Int?, backupGeneration: Long, steps: MutableList<String>): String? {
        val script = managerDataVerificationScript(packageName, expectedUid, backupGeneration)
        val reasons = setOf("DATA_DIRECTORY_MISSING", "DATA_OWNER_UNREADABLE", "DATA_DIRECTORY_UNSAFE",
            "DATA_PACKAGE_QUERY_FAILED", "DATA_PACKAGE_UID_MISMATCH", "DATA_BACKUP_FAILED",
            "DATA_MIGRATION_FAILED", "DATA_LABEL_RESTORE_FAILED")
        val transient = setOf("DATA_DIRECTORY_MISSING", "DATA_OWNER_UNREADABLE",
            "DATA_PACKAGE_QUERY_FAILED", "DATA_PACKAGE_UID_MISMATCH")
        var reason = "DATA_VERIFICATION_UNAVAILABLE"
        repeat(3) { attempt ->
            // Package installation and CE data preparation can become visible at different times.
            val result = runner.run((if (attempt > 0) "sleep 1; " else "") + script)
            if (marker(result.output, "MAPLESU_RESTORE_DATA_BACKUP_OK") && "data_backup:ok" !in steps) {
                steps += "data_backup:ok"
            }
            if (result.code == 0 && marker(result.output, "MAPLESU_RESTORE_DATA_OK")) {
                if (marker(result.output, "MAPLESU_RESTORE_UID_CHANGED")) steps += "data_uid:ok"
                return null
            }
            reason = result.output.lineSequence().map(String::trim)
                .filter { it.startsWith("MAPLESU_RESTORE_DATA_FAILED=") }
                .singleOrNull()?.substringAfter('=')?.takeIf { it in reasons } ?: "DATA_VERIFICATION_UNAVAILABLE"
            if (reason !in transient) return reason
        }
        return reason
    }
}
