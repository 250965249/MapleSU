package dev.maplesu.manager.workmode.migration

import java.io.File

/**
 * 外部还原策略（05 §3.3 / §3.7 / §4.2）。
 *
 * 本类只**规划与校验**外部还原工具调用，绝不执行：
 * - 只处理副本，不碰块设备；
 * - 禁止 `-f` / `--flash`（会直写分区，绕过共用事务，红线 4/13）；
 * - KSU 的 `boot-restore` 会触发 `clean_backup` 删除其它 `ksu_backup_*`（05 C1），
 *   因此调用前必须所有外部 stock 备份已备份并通过读回校验。
 */
enum class RestoreLevel { P0_STOCK_COPY, P2_EXTERNAL_TOOL, P3_UNAVAILABLE }

/** 一次外部还原调用（文件态）。 */
data class ExternalRestoreRequest(
    val strategy: RestoreStrategy,
    val partition: String,
    val inputImage: File,
    val outputDirectory: File,
    val toolPath: String? = null,
    val argv: List<String> = emptyList(),
    val backupRoot: File? = null,
    val allExternalBackupsVerified: Boolean = false,
)

object ExternalRootRestoreStrategy {

    val FORBIDDEN_FLAGS: Set<String> = setOf("-f", "--flash", "--flash-only")
    val FORBIDDEN_TOKENS: Set<String> = setOf("uninstaller.sh", "flash_image", "uninstall", "uninstall_all")

    fun level(strategy: RestoreStrategy): RestoreLevel = when (strategy) {
        RestoreStrategy.KSU_STOCK_COPY, RestoreStrategy.MAGISK_STOCK_GZ -> RestoreLevel.P0_STOCK_COPY
        RestoreStrategy.KSU_EXTERNAL_TOOL_ON_COPY, RestoreStrategy.MAGISK_INTERNAL_REBUILD ->
            RestoreLevel.P2_EXTERNAL_TOOL
        RestoreStrategy.GENERIC_STOCK_SCAN, RestoreStrategy.NONE -> RestoreLevel.P3_UNAVAILABLE
    }

    /**
     * 生成还原请求并立即校验。已知家族缺可用外部工具/备份时抛 `MIGRATION_CLEAN_IMAGE_UNAVAILABLE`
     * 之外的 `MIGRATION_EXTERNAL_TOOL_FORBIDDEN`/`MIGRATION_RESTORE_INPUT_NOT_COPY` 等明确码。
     */
    fun request(
        strategy: RestoreStrategy,
        partition: String,
        inputImage: File,
        outputDirectory: File,
        backupRoot: File,
        toolPath: String?,
        argv: List<String>,
        allExternalBackupsVerified: Boolean,
    ): ExternalRestoreRequest {
        val request = ExternalRestoreRequest(
            strategy = strategy,
            partition = partition,
            inputImage = inputImage,
            outputDirectory = outputDirectory,
            toolPath = toolPath,
            argv = argv,
            backupRoot = backupRoot,
            allExternalBackupsVerified = allExternalBackupsVerified,
        )
        validate(request)
        return request
    }

    fun validate(request: ExternalRestoreRequest) {
        val level = level(request.strategy)
        MigrationFailure.require(
            level != RestoreLevel.P3_UNAVAILABLE,
            MigrationCodes.CLEAN_IMAGE_UNAVAILABLE,
            request.partition,
        )
        if (level == RestoreLevel.P0_STOCK_COPY) {
            MigrationFailure.require(request.inputImage.isFile, MigrationCodes.CLEAN_IMAGE_UNAVAILABLE, "input")
            return
        }

        // P2：外部工具只允许对副本执行
        val backupRoot = request.backupRoot
            ?: throw MigrationFailure(MigrationCodes.RESTORE_INPUT_NOT_COPY, "no backup root")
        val rootPath = backupRoot.canonicalFile
        val inputPath = request.inputImage.canonicalFile
        MigrationFailure.require(
            inputPath.path.startsWith(rootPath.path + File.separator) || inputPath.path == rootPath.path,
            MigrationCodes.RESTORE_INPUT_NOT_COPY,
            inputPath.path,
        )
        MigrationFailure.require(
            request.inputImage.isFile,
            MigrationCodes.CLEAN_IMAGE_UNAVAILABLE,
            request.partition,
        )
        request.outputDirectory.mkdirs()
        MigrationFailure.require(
            request.outputDirectory.isDirectory,
            MigrationCodes.CLEAN_IMAGE_UNAVAILABLE,
            "output",
        )

        val argv = request.argv
        MigrationFailure.require(argv.isNotEmpty(), MigrationCodes.RESTORE_EXTERNAL_TOOL_FORBIDDEN, "empty argv")
        MigrationFailure.require(
            argv.none { it.lowercase() in FORBIDDEN_FLAGS },
            MigrationCodes.RESTORE_EXTERNAL_TOOL_FORBIDDEN,
            "flash flag",
        )
        MigrationFailure.require(
            argv.none { argument -> FORBIDDEN_TOKENS.any { token -> argument.contains(token) } },
            MigrationCodes.RESTORE_EXTERNAL_TOOL_FORBIDDEN,
            "uninstaller",
        )
        MigrationFailure.require(
            !request.toolPath.isNullOrBlank(),
            MigrationCodes.CLEAN_IMAGE_UNAVAILABLE,
            "tool",
        )
        MigrationFailure.require(
            (request.strategy == RestoreStrategy.MAGISK_INTERNAL_REBUILD) || request.allExternalBackupsVerified,
            MigrationCodes.RESTORE_BACKUP_UNVERIFIED,
            "ksud boot-restore deletes other ksu_backup_* (05 C1)",
        )
    }

    /** KSU P2 参数模板：`boot-restore --boot <copy> --out <dir>`（**无** `-f`）。 */
    fun ksuRestoreArgv(inputImage: File, outputDirectory: File): List<String> = listOf(
        "boot-restore", "--boot", inputImage.path, "--out", outputDirectory.path,
    )

    /** Magisk P2 参数模板：cpio 文件态操作 + 回封，绝不 flash。 */
    fun magiskRepackArgv(
        command: String,
        inputImage: File,
        output: File,
        extra: List<String> = emptyList(),
    ): List<String> = listOf(command) + extra + listOf(inputImage.path, output.path)

    /**
     * 干净镜像获取阶梯判定（05 §3.3）：返回该分区可用的最高级别。
     * UNKNOWN 家族只能到 P3（best-effort），已知家族 P0→P2。
     */
    fun availableLevel(
        family: Family,
        strategy: RestoreStrategy,
        partition: String,
        usableBackupPartitions: Set<String>,
        toolExecutable: Boolean,
    ): RestoreLevel = when {
        partition in usableBackupPartitions && strategy in setOf(
            RestoreStrategy.KSU_STOCK_COPY, RestoreStrategy.MAGISK_STOCK_GZ,
        ) -> RestoreLevel.P0_STOCK_COPY
        family.isKnown && toolExecutable && level(strategy) == RestoreLevel.P2_EXTERNAL_TOOL ->
            RestoreLevel.P2_EXTERNAL_TOOL
        else -> RestoreLevel.P3_UNAVAILABLE
    }
}

/**
 * 外部管理器 APK 卸载策略（05 §5.6；红线 12）。
 *
 * 只在 M9 `VERIFIED` 之后、且包名经双重过滤（detected ∧ on-device ∧ ≠ 自身）才允许。
 * 这里不执行 `pm`，只做纯策略计算；`PmUninstaller` 是设备侧端口。
 */
data class ApkUninstallPlan(
    val selected: List<String>,
    val skipped: List<String>,
    val error: String = "",
)

fun interface PmUninstaller {
    /** 返回进程退出码（0 = 成功）。 */
    fun uninstall(packageName: String): Int
}

data class ApkUninstallResult(val packageName: String, val exitCode: Int) {
    val ok: Boolean get() = exitCode == 0
}

object ExternalApkPolicy {
    fun plan(
        requested: List<String>,
        detected: Set<String>,
        selfPackages: Set<String>,
        onDevice: Set<String>,
        verifiedState: Boolean,
    ): ApkUninstallPlan {
        val cleaned = requested.map { it.trim() }.filter { it.isNotEmpty() }.distinct()
        if (!verifiedState) {
            return ApkUninstallPlan(
                selected = emptyList(),
                skipped = cleaned,
                error = MigrationCodes.APK_UNINSTALL_BEFORE_VERIFIED,
            )
        }
        if (cleaned.any { it in selfPackages }) {
            // 自身包名出现在任何卸载请求里：整个请求拒绝（不执行任何 pm 调用）。
            return ApkUninstallPlan(
                selected = emptyList(),
                skipped = cleaned,
                error = MigrationCodes.SELF_UNINSTALL_REFUSED,
            )
        }
        val selected = mutableListOf<String>()
        val skipped = mutableListOf<String>()
        for (pkg in cleaned) {
            when {
                pkg !in detected -> skipped += pkg
                pkg !in onDevice -> skipped += pkg
                else -> selected += pkg
            }
        }
        return ApkUninstallPlan(selected, skipped)
    }
}

class ExternalPackageUninstaller(
    private val pm: PmUninstaller,
    private val selfPackages: Set<String> = setOf(MigrationPaths.SELF_PACKAGE),
) {
    fun uninstall(plan: ApkUninstallPlan): List<ApkUninstallResult> {
        if (plan.error.isNotEmpty()) return emptyList()
        return plan.selected
            .filter { it !in selfPackages }
            .map { packageName -> ApkUninstallResult(packageName, pm.uninstall(packageName)) }
    }
}
