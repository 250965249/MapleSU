package dev.maplesu.manager.workmode.superuser

import android.content.Context
import dev.maplesu.manager.runtime.RootExec
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.WallClock
import java.io.File

/** root 脚本执行结果（与 libsu/DirectRoot 解耦，便于主机 fake）。 */
data class RootScriptResult(val code: Int, val out: String)

fun interface RootScriptRunner {
    fun run(script: String): RootScriptResult
}

/**
 * 真机实现：经模式感知 [RootExec] 执行（LITE 下 Ultra Env 优先、Lite 内核凭据兜底，
 * 其他模式 Lite → Ultra）。脚本失败不伪造成功；完整失败时返回最后失败码/输出。
 */
class DirectRootScriptRunner(private val context: Context) : RootScriptRunner {
    override fun run(script: String): RootScriptResult {
        val result = RootExec.execute(context.applicationContext, script)
        return RootScriptResult(result.code, result.output)
    }
}

/** 原件备份证据（由 root 侧 `sha256sum/stat` 读出）。 */
data class BackupEvidence(
    val originalAbsent: Boolean,
    val sha256: String? = null,
    val uid: Int? = null,
    val gid: Int? = null,
    /** 权限位（八进制字符串解析后的十进制位，如 0700 = 0x1C0）。 */
    val mode: Int? = null,
)

/**
 * W19 的 root 侧脚本（纯字符串构造 + 纯解析，主机可测）：
 * - 备份原件（存在→复制+sha+uid/gid/mode；不存在→ABSENT 标记）；
 * - 恢复原件 / 删除新增文件 / 清理新建目录 / 移除 root 拥有的 side library。
 *
 * 凭据绝不进脚本（不含任何 credential/rootKey 变量）。
 */
object LiteImplantScripts {
    const val MARK_SAVED = "ORIGINAL:SAVED"
    const val MARK_ABSENT = "ORIGINAL:ABSENT"
    const val MARK_RESTORED = "RESTORED"
    const val MARK_REMOVED = "REMOVED"
    const val MARK_REVERTED = "REVERTED"

    private const val SH = "/system/bin"

    fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    /** 修改前备份原件；输出一行 `ORIGINAL:SAVED:<sha>:<uid>:<gid>:<mode>` 或 `ORIGINAL:ABSENT`。 */
    fun backup(targetPath: String, backupPath: String): String {
        val backupDir = File(backupPath).parent
        return buildString {
            appendLine("set -eu")
            appendLine("$SH/mkdir -p ${quote(backupDir)}")
            appendLine("$SH/chmod 0700 ${quote(backupDir)}")
            appendLine("$SH/chown 0:0 ${quote(backupDir)}")
            appendLine("if [ -e ${quote(targetPath)} ]; then")
            appendLine("  $SH/cp -f ${quote(targetPath)} ${quote(backupPath)}")
            appendLine("  $SH/chmod 0600 ${quote(backupPath)}")
            appendLine("  $SH/chown 0:0 ${quote(backupPath)}")
            appendLine(
                "  $SH/printf 'ORIGINAL:SAVED:%s:%s:%s:%s\\n' " +
                    "\"\$($SH/sha256sum ${quote(backupPath)} | $SH/cut -d' ' -f1)\" " +
                    "\"\$($SH/stat -c %u ${quote(targetPath)})\" " +
                    "\"\$($SH/stat -c %g ${quote(targetPath)})\" " +
                    "\"\$($SH/stat -c %a ${quote(targetPath)})\"",
            )
            appendLine("else")
            appendLine("  $SH/printf 'ORIGINAL:ABSENT\\n'")
            appendLine("fi")
        }
    }

    /** 解析备份脚本输出；无法识别 → null（fail closed，不猜）。 */
    fun parseBackup(out: String): BackupEvidence? {
        val line = out.lineSequence().map { it.trim() }.firstOrNull {
            it.startsWith(MARK_ABSENT) || it.startsWith(MARK_SAVED)
        } ?: return null
        if (line.startsWith(MARK_ABSENT)) return BackupEvidence(originalAbsent = true)
        val parts = line.split(':')
        if (parts.size != 6) return null
        val sha = parts[2]
        if (!sha.matches(Regex("[0-9a-f]{64}"))) return null
        return BackupEvidence(
            originalAbsent = false,
            sha256 = sha,
            uid = parts[3].toIntOrNull(),
            gid = parts[4].toIntOrNull(),
            mode = parts[5].toIntOrNull(8),
        )
    }

    /** 恢复原件（内容 + 属主 + 权限 + SELinux label）并读回 sha 校验。 */
    fun restoreOriginal(
        backupPath: String,
        targetPath: String,
        sha256: String?,
        uid: Int?,
        gid: Int?,
        mode: Int?,
    ): String = buildString {
        appendLine("set -eu")
        appendLine("$SH/cp -f ${quote(backupPath)} ${quote(targetPath)}")
        if (uid != null && gid != null) appendLine("$SH/chown $uid:$gid ${quote(targetPath)}")
        if (mode != null) appendLine("$SH/chmod ${mode.toString(8)} ${quote(targetPath)}")
        appendLine("$SH/chcon u:object_r:apk_data_file:s0 ${quote(targetPath)}")
        if (sha256 != null && sha256.isNotBlank()) {
            appendLine(
                "read -r actual < <($SH/sha256sum ${quote(targetPath)}); " +
                    "if [ \"\${actual%% *}\" != ${quote(sha256)} ]; then exit 4; fi",
            )
        }
        appendLine("$SH/printf '$MARK_RESTORED\\n'")
    }

    /** 原本不存在的目标：删除我们新增的文件（`rm -f` 幂等）。 */
    fun removeTarget(targetPath: String): String = buildString {
        appendLine("set -eu")
        appendLine("$SH/rm -f ${quote(targetPath)}")
        appendLine("if [ -e ${quote(targetPath)} ]; then exit 3; fi")
        appendLine("$SH/printf '$MARK_REMOVED\\n'")
    }

    /** 清理我们新建的目录：按深度从深到浅（先 arm64 再 lib），仅空目录、非致命。 */
    fun cleanupCreatedDirs(directories: List<String>): String = buildString {
        appendLine("set -u")
        directories
            .distinct()
            .sortedByDescending { directory -> directory.count { it == '/' } }
            .forEach { directory ->
                appendLine("$SH/rmdir ${quote(directory)} 2>/dev/null || true")
            }
        appendLine("$SH/printf '$MARK_REVERTED\\n'")
    }

    /** 移除 root 拥有的 side library（上游植入随机命名，但都是 root:root 的 lib*）。 */
    fun removeSideLibraries(libraryDirectory: String): String = buildString {
        appendLine("set -u")
        appendLine("if [ -d ${quote(libraryDirectory)} ]; then")
        appendLine(
            "  $SH/find ${quote(libraryDirectory)} -maxdepth 1 -name 'lib*' -user 0 " +
                "-exec $SH/rm -f {} + 2>/dev/null || true",
        )
        appendLine("fi")
        appendLine("$SH/printf '$MARK_REVERTED\\n'")
    }
}

/**
 * 备份工作流：在修改前把原件落到控制面 `<shared>/originals/<pkg>/`（0600 root），
 * 产出**未激活**的 [ImplantIntent]（由 recorder 先登记，成功后置 active）。
 * 任何失败 → [ImplantPreparation.ok]=false + [LiteImplantCodes.BACKUP_FAILED]（调用方必须放弃写入）。
 */
class LiteImplantBackupWorkflow(
    private val runner: RootScriptRunner,
    private val sharedDirectory: File,
    private val clock: Clock = WallClock,
) {
    fun prepareDelivery(
        packageName: String,
        uid: Int,
        deliverPath: String,
        deliverSha256: String,
        createdDirs: List<String> = emptyList(),
        now: Long = clock.nowMillis(),
    ): ImplantPreparation = prepare(
        kind = ImplantKinds.DELIVERY,
        packageName = packageName,
        uid = uid,
        targetPath = deliverPath,
        deliverPath = deliverPath,
        deliverSha256 = deliverSha256,
        createdDirs = createdDirs,
        now = now,
        evidenceName = "deliver-su",
    )

    fun prepareWiring(
        packageName: String,
        uid: Int,
        targetLibraryPath: String,
        deliverPath: String,
        deliverSha256: String,
        createdDirs: List<String> = emptyList(),
        now: Long = clock.nowMillis(),
    ): ImplantPreparation = prepare(
        kind = ImplantKinds.WIRING,
        packageName = packageName,
        uid = uid,
        targetPath = targetLibraryPath,
        deliverPath = deliverPath,
        deliverSha256 = deliverSha256,
        createdDirs = createdDirs,
        now = now,
        evidenceName = "wiring-${File(targetLibraryPath).name}",
    )

    private fun prepare(
        kind: String,
        packageName: String,
        uid: Int,
        targetPath: String,
        deliverPath: String,
        deliverSha256: String,
        createdDirs: List<String>,
        now: Long,
        evidenceName: String,
    ): ImplantPreparation {
        val backupDirectory = File(sharedDirectory, "originals/$packageName")
        val backupFile = File(backupDirectory, "$evidenceName.bin")
        val prepared = runCatching { backupDirectory.mkdirs() || backupDirectory.isDirectory }.getOrDefault(false)
        if (!prepared) return ImplantPreparation.failed(LiteImplantCodes.BACKUP_FAILED, "backup dir")
        val result = try {
            runner.run(LiteImplantScripts.backup(targetPath, backupFile.absolutePath))
        } catch (error: Throwable) {
            return ImplantPreparation.failed(LiteImplantCodes.BACKUP_FAILED, error.javaClass.simpleName)
        }
        if (result.code != 0) {
            return ImplantPreparation.failed(LiteImplantCodes.BACKUP_FAILED, "code=${result.code}")
        }
        val evidence = LiteImplantScripts.parseBackup(result.out)
            ?: return ImplantPreparation.failed(LiteImplantCodes.BACKUP_FAILED, "unparsable evidence")
        if (!evidence.originalAbsent && !backupFile.isFile) {
            // root 脚本声称备份成功但文件不可见 → fail closed（绝不在无原件证据时改目标）。
            return ImplantPreparation.failed(LiteImplantCodes.BACKUP_FAILED, "backup file missing")
        }
        val intent = ImplantIntent(
            packageName = packageName,
            uid = uid,
            deliverPath = deliverPath,
            deliverSha256 = deliverSha256,
            wiringTargetLib = if (kind == ImplantKinds.WIRING) targetPath else null,
            wiringOriginalSha256 = evidence.sha256,
            sideLibraryPath = null,
            createdDirs = createdDirs.distinct().sorted(),
            pathInjection = kind == ImplantKinds.PATH_INJECTION,
            recordedAt = now,
            kind = kind,
            originalAbsent = evidence.originalAbsent,
            originalBackupPath = if (evidence.originalAbsent) null else backupFile.absolutePath,
            originalSha256 = evidence.sha256,
            originalMode = evidence.mode,
            originalUid = evidence.uid,
            originalGid = evidence.gid,
            active = false,
        )
        return ImplantPreparation(ok = true, intent = intent)
    }

    /** 测试/诊断：备份文件路径（与 [prepare] 同一规则）。 */
    fun backupPathFor(packageName: String, evidenceName: String): File =
        File(File(sharedDirectory, "originals/$packageName"), "$evidenceName.bin")
}
