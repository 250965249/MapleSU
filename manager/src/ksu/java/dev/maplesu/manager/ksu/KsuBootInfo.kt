// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import java.io.File

/**
 * ramdisk 归属四态（7K `boot_patch.rs:626-700` / `cli.rs:248-262`）。
 *
 * ⚠️ 契约：`ramdisk-state` 是机器接口，词表固定小写：
 * `ours|compatible|foreign|stock`。**无法读取/未识别 → UNKNOWN，绝不默认 STOCK** ——
 * 默认 STOCK 会让「在别人已打补丁的镜像上再打一层」被放行。
 */
enum class RamdiskState(val token: String) {
    OUR("ours"),
    COMPATIBLE("compatible"),
    FOREIGN("foreign"),
    STOCK("stock"),
    UNKNOWN("unknown"),
    ;

    companion object {
        fun fromToken(raw: String?): RamdiskState {
            val t = raw?.trim()?.lowercase() ?: return UNKNOWN
            return entries.firstOrNull { it.token == t } ?: UNKNOWN
        }
    }
}

/** `ksud debug info` 的解析结果。 */
data class KsuKernelInfo(
    val version: Int,
    val flags: Long,
    val uapiVersion: Int,
    val features: Long,
    val lkm: Boolean,
    val bundled: Boolean,
    val lateLoad: Boolean,
    val runtimeMode: String,
    val raw: String,
)

/**
 * `ksud debug info` 输出解析器。
 *
 * 7K 输出形如（`cli.rs:884-900`）：
 * ```
 * version: 32650
 * uapi_version: 7
 * flags: 0x00000021
 * features: 0x0000001f
 * lkm: true
 * bundled: false
 * late_load: false
 * runtime_mode: lkm
 * ```
 * 解析必须**宽容**（缺字段 → 对应字段取 sentinel），因为这是诊断接口不是 ABI。
 */
object KsuDebugInfoParser {
    fun parse(output: String): KsuKernelInfo? {
        if (output.isBlank()) return null
        fun field(name: String): String? = output.lineSequence()
            .map { it.trim() }
            .firstOrNull { it.startsWith("$name:") }
            ?.substringAfter(':')?.trim()

        fun int(name: String): Int = field(name)?.toIntOrNull() ?: -1
        fun long(name: String): Long {
            val v = field(name) ?: return 0L
            return if (v.startsWith("0x", ignoreCase = true)) {
                v.substring(2).toLongOrNull(16) ?: 0L
            } else {
                v.toLongOrNull() ?: 0L
            }
        }
        fun bool(name: String): Boolean = field(name)?.equals("true", ignoreCase = true) == true

        val hasAny = output.contains("version:") || output.contains("uapi_version:")
        if (!hasAny) return null
        return KsuKernelInfo(
            version = int("version"),
            flags = long("flags"),
            uapiVersion = int("uapi_version"),
            features = long("features"),
            lkm = bool("lkm"),
            bundled = bool("bundled"),
            lateLoad = bool("late_load"),
            runtimeMode = field("runtime_mode") ?: "",
            raw = output.trim(),
        )
    }
}

/**
 * ramdisk 结构断言（W12 的「只产候选」之后、写分区之前必须过的一道闸）。
 *
 * 期望布局沿用上游：`init` / `init.real` / `kernelsu.ko` / `ksu_config`。
 * 归属标记新增 0 字节条目 `maplesu_id`（7K 的 `sevenk.ko` 判据
 * 与「沿用上游 kernelsu.ko」冲突，改用独立标记）。
 */
object KsuRamdiskLayout {
    const val ENTRY_INIT = "init"
    const val ENTRY_INIT_REAL = "init.real"
    const val ENTRY_KERNELSU_KO = "kernelsu.ko"
    const val ENTRY_KSU_CONFIG = "ksu_config"
    const val ENTRY_OURS_MARKER = "maplesu_id"
    const val FOREIGN_ARTIFACT = "sevenk.ko"

    val REQUIRED_ENTRIES: List<String> = listOf(
        ENTRY_INIT, ENTRY_INIT_REAL, ENTRY_KERNELSU_KO, ENTRY_KSU_CONFIG,
    )

    /** 断言结果：要么通过并给出归属，要么带明确原因拒绝。 */
    sealed class Verdict {
        abstract val entries: Set<String>

        data class Accepted(
            val state: RamdiskState,
            override val entries: Set<String>,
        ) : Verdict()

        data class Rejected(
            val reasons: List<String>,
            override val entries: Set<String>,
        ) : Verdict()

        val isAccepted: Boolean get() = this is Accepted
    }

    /**
     * 校验 cpio 条目名集合。
     *
     * 拒绝条件（任一命中）：
     * - 含 `sevenk.ko`（7K 双条目布局的产物 → FOREIGN_ARTIFACT，主文档:467 明确不采用）；
     * - 缺 `init` / `init.real` / `kernelsu.ko` / `ksu_config`；
     * - 已有 `init.real` 但**不是**我方产物（没有 `maplesu_id`）时是否拒绝由调用方
     *   [requireOursMarker] 决定（切换事务里「源镜像已有历史第三方 KSU 残留 → 拒绝生产」）。
     */
    fun verify(
        entries: Collection<String>,
        requireOursMarker: Boolean = false,
    ): Verdict {
        val set = entries.map { it.trim() }.filter { it.isNotEmpty() }.toSet()
        val reasons = mutableListOf<String>()
        if (FOREIGN_ARTIFACT in set) {
            reasons += "FOREIGN_ARTIFACT: $FOREIGN_ARTIFACT present (7K 双条目布局不采用)"
        }
        for (required in REQUIRED_ENTRIES) {
            if (required !in set) reasons += "MISSING_ENTRY: $required"
        }
        val hasMarker = ENTRY_OURS_MARKER in set
        if (requireOursMarker && !hasMarker && reasons.isEmpty()) {
            reasons += "MISSING_ENTRY: $ENTRY_OURS_MARKER (requireOursMarker=true)"
        }
        if (reasons.isNotEmpty()) return Verdict.Rejected(reasons, set)
        return Verdict.Accepted(
            state = if (hasMarker) RamdiskState.OUR else RamdiskState.COMPATIBLE,
            entries = set,
        )
    }

    /**
     * 从 ramdisk cpio 原始字节里列出条目名（最小实现，仅支持 newc 的 110 字节头）。
     *
     * 生产路径不靠它（ksud 的 `boot-info ramdisk-state` 才是权威），它用于
     * 「候选镜像落地后的独立复核」与单测构造畸形样本。
     */
    fun listNewcEntries(data: ByteArray): List<String> {
        val names = mutableListOf<String>()
        var offset = 0
        while (offset + 110 <= data.size) {
            val magic = String(data, offset, 6, Charsets.US_ASCII)
            if (magic != "070701" && magic != "070702") break
            val mode = hex(data, offset + 14, 8)
            val fileSize = hex(data, offset + 54, 8)
            val nameSize = hex(data, offset + 94, 8)
            if (nameSize <= 0 || offset + 110 + nameSize > data.size) break
            val name = String(data, offset + 110, nameSize - 1, Charsets.UTF_8)
            names += name
            // 头部 110 + 名字（含 NUL），再按 4 字节对齐；文件数据同样按 4 对齐
            var next = offset + 110 + nameSize
            next = align4(next)
            next += fileSize
            next = align4(next)
            if (next <= offset) break
            offset = next
            // Trailer 是 cpio 结束标志
            if (name == "TRAILER!!!") break
            if (mode == 0) break
        }
        return names
    }

    private fun hex(data: ByteArray, offset: Int, len: Int): Int {
        if (offset + len > data.size) return -1
        return String(data, offset, len, Charsets.US_ASCII).toIntOrNull(16) ?: -1
    }

    private fun align4(value: Int): Int = (value + 3) and 3.inv()
}

/**
 * KSU 模式的 boot 信息后端（`BootInfoOps`）。
 *
 * 全部走 ksud 的机器接口；**未接线/ksud 缺失时不抛**，返回空值并记录。
 */
class KsuBootInfo(
    private val backend: KsuCommandBackend,
    private val timeoutMs: Long = KsuTimeouts.COMMAND_MS,
) {
    fun currentKmi(): String? = capture(KsuBootInfoSubcommand.CURRENT_KMI)?.lineSequence()
        ?.firstOrNull()?.trim()?.ifEmpty { null }

    fun supportedKmis(): List<String> =
        capture(KsuBootInfoSubcommand.SUPPORTED_KMIS)?.lines()
            ?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()

    fun isAbDevice(): Boolean = capture(KsuBootInfoSubcommand.IS_AB_DEVICE)?.trim()
        ?.equals("true", ignoreCase = true) == true

    fun defaultPartition(): String? = capture(KsuBootInfoSubcommand.DEFAULT_PARTITION)?.trim()
        ?.ifEmpty { null }

    fun availablePartitions(): List<String> = capture(KsuBootInfoSubcommand.AVAILABLE_PARTITIONS)
        ?.lines()?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()

    fun slotSuffix(ota: Boolean): String? {
        val cmd = KsuCommands.bootInfo(backend.daemonPath(), KsuBootInfoSubcommand.SLOT_SUFFIX) +
            if (ota) listOf("-u") else emptyList()
        val result = backend.runCommand(cmd, timeoutMs)
        return if (result.code == 0) result.outText.trim().ifEmpty { null } else null
    }

    /**
     * ramdisk 归属：`ksud boot-info ramdisk-state [--boot <img>]`。
     * 未识别词一律 UNKNOWN（**不得**默认 STOCK）。
     */
    fun ramdiskState(image: File? = null): RamdiskState {
        val daemon = backend.daemonPath()
        val cmd = try {
            KsuCommands.bootInfo(daemon, KsuBootInfoSubcommand.RAMDISK_STATE, image)
        } catch (e: KsuCommandRejectedException) {
            KsuLog.rejected("KsuBootInfo", e.token)
            return RamdiskState.UNKNOWN
        }
        val result = backend.runCommand(cmd, timeoutMs)
        if (result.code != 0) {
            KsuLog.record("boot-info-failed", "ramdisk-state code=${result.code}")
            return RamdiskState.UNKNOWN
        }
        return RamdiskState.fromToken(result.outText.lines().firstOrNull { it.isNotBlank() })
    }

    fun kernelInfo(): KsuKernelInfo? {
        val result = backend.runCommand(
            KsuCommands.debugInfo(backend.daemonPath()), KsuTimeouts.DEBUG_INFO_MS)
        if (result.code != 0) {
            KsuLog.record("debug-info-failed", "code=${result.code}")
            return null
        }
        return KsuDebugInfoParser.parse(result.outText)
    }

    private fun capture(subcommand: String): String? {
        val cmd = try {
            KsuCommands.bootInfo(backend.daemonPath(), subcommand)
        } catch (e: KsuCommandRejectedException) {
            KsuLog.rejected("KsuBootInfo", e.token)
            return null
        }
        val result = backend.runCommand(cmd, timeoutMs)
        return if (result.code == 0) result.outText else null
    }

    companion object {
        fun unavailable(reason: String): KsuBootInfo {
            KsuLog.unavailable("KsuBootInfo", reason)
            return KsuBootInfo(KsuCommandBackend.unavailable(reason))
        }
    }
}
