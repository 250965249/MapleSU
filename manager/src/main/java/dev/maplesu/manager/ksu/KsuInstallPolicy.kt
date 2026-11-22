// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

/**
 * KSU 安装请求的策略层（纯函数，主机可测）。
 *
 * 职责：把 UI 的 `installBoot` 参数翻译成"允许/拒绝 + 受控 [KsuBootPatchOptions]"。
 * 所有会破坏 D10 的红线参数在这里被拒绝（不是提示、不是忽略）：
 * - `ota` / `--ota -u`：不得安装到未使用槽；
 * - `forceBackup` / `--backup`：备份语义由切换事务的 baseline/pre 负责；
 * - 用户提供的 `.ko`（`--kernel` 类输入）：B 只允许分支内嵌 LKM；
 * - 白名单外的分区：B 只支持 `init_boot` / `boot`（与 KernelSU 一致，D4）。
 *
 * 与 [KsuCommands.FORBIDDEN_TOKENS] 的关系：本层拒绝语义输入，构造层拒绝任何
 * 漏网的 flag；两层都在，任何一层单独失效都不会写出分区。
 */
enum class KsuInstallRejectReason {
    OTA_UNSUPPORTED,
    FORCE_BACKUP_UNSUPPORTED,
    LKM_URI_UNSUPPORTED,
    NO_SOURCE_IMAGE,
    PARTITION_UNSUPPORTED,
    BLOCK_MODULES_INVALID,
}

sealed class KsuInstallDecision {
    data class Allowed(val options: KsuBootPatchOptions) : KsuInstallDecision()

    data class Rejected(
        val reason: KsuInstallRejectReason,
        val detail: String,
    ) : KsuInstallDecision()
}

object KsuInstallPolicy {

    private val BLOCK_MODULE_NAME = Regex("^[A-Za-z0-9_]{1,64}$")
    private const val MAX_BLOCK_MODULES_LEN = 255

    /** 默认分区（B v1 = 独立 init_boot + LKM，D4）；`partition` 为空时用它。 */
    const val ALLOWED_PARTITION = "init_boot"

    /**
     * 白名单（与 KernelSU 一致：`init_boot` **或** `boot`）。
     *
     * 白名单外的任何值（含 `/dev/block/by-name/...` 这类节点路径）一律
     * [KsuInstallRejectReason.PARTITION_UNSUPPORTED] —— 参数级约束，不做字符串匹配。
     */
    val ALLOWED_PARTITIONS: Set<String> = setOf("init_boot", "boot")

    fun evaluate(
        bootUriPresent: Boolean,
        kmi: String?,
        lkmIsUri: Boolean,
        ota: Boolean,
        partition: String?,
        allowShell: Boolean,
        enableAdb: Boolean,
        forceBackup: Boolean,
        blockModules: String,
        /**
         * 本次是"直接安装"（没有用户文件）：源镜像由 root 从当前槽的目标分区提取
         * （`RootPartitionExtractor`）。**只有**会真的去提取的调用方才能传 `true`；
         * 其它调用方保持默认 `false`，"没有源镜像"仍然是显式拒绝。
         */
        directInstall: Boolean = false,
    ): KsuInstallDecision {
        if (ota) {
            return KsuInstallDecision.Rejected(
                KsuInstallRejectReason.OTA_UNSUPPORTED,
                "OTA/inactive-slot install is not supported in mode B",
            )
        }
        if (forceBackup) {
            return KsuInstallDecision.Rejected(
                KsuInstallRejectReason.FORCE_BACKUP_UNSUPPORTED,
                "backup-as-stock is owned by the switch transaction (baseline/pre), not by boot-patch",
            )
        }
        if (lkmIsUri) {
            return KsuInstallDecision.Rejected(
                KsuInstallRejectReason.LKM_URI_UNSUPPORTED,
                "a user-supplied .ko file is not allowed in mode B; the branch LKM is embedded",
            )
        }
        val normalizedPartition = partition?.trim()?.ifEmpty { null } ?: ALLOWED_PARTITION
        if (normalizedPartition !in ALLOWED_PARTITIONS) {
            return KsuInstallDecision.Rejected(
                KsuInstallRejectReason.PARTITION_UNSUPPORTED,
                "mode B only patches ${ALLOWED_PARTITIONS.sorted()}, got '$normalizedPartition'",
            )
        }
        val modules = parseBlockModules(blockModules)
        if (!isBlockModulesValid(modules)) {
            return KsuInstallDecision.Rejected(
                KsuInstallRejectReason.BLOCK_MODULES_INVALID,
                "invalid --block-module list: '$blockModules'",
            )
        }
        if (!bootUriPresent && !directInstall) {
            // 没有文件、又不是直装：没有任何可修补的源镜像（不猜、不空跑）。
            return KsuInstallDecision.Rejected(
                KsuInstallRejectReason.NO_SOURCE_IMAGE,
                "mode B install requires either an image file or a direct-install partition read",
            )
        }
        return KsuInstallDecision.Allowed(
            KsuBootPatchOptions(
                kmi = kmi,
                allowShell = allowShell,
                enableAdb = enableAdb,
                partition = normalizedPartition,
                blockModules = modules,
            ),
        )
    }

    /** 与 UI 侧 `parseBlockModules` 同语义（逗号分隔、去空白、丢空项）。 */
    fun parseBlockModules(input: String): List<String> =
        input.split(',').map { it.trim() }.filter { it.isNotEmpty() }

    /** 与 UI 侧 `isBlockModulesValid` 同语义（每个名字合法 + 总长 ≤255）。 */
    fun isBlockModulesValid(input: String): Boolean = isBlockModulesValid(parseBlockModules(input))

    private fun isBlockModulesValid(names: List<String>): Boolean =
        names.all { BLOCK_MODULE_NAME.matches(it) } &&
            names.joinToString(",").length <= MAX_BLOCK_MODULES_LEN
}

/**
 * 安装入口的分派意图（W11b 补丁；审计要求）。
 *
 * `installBoot` 是用户在安装页的**显式动作**：未判定态下不能因为"模式还没判定完"
 * 就拒绝用户自装 Lite（那会让 Lite 自装失效）。因此这里显式声明
 * [ModeIntent.EXPLICIT_LITE]；静默后台任务仍走默认 [ModeIntent.IMPLICIT] → BLOCKED。
 */
object KsuInstallDispatch {
    fun targetForExplicitInstall(): NativesFacadeTarget =
        NativesFacade.target(ModeIntent.EXPLICIT_LITE)
}
