// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.installer

import java.io.File
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

/**
 * 一条命令在**已认证 root shell** 里的执行结果。
 *
 * 为什么是"命令行"而不是 argv：root shell 端口（libsu / `ksud debug su`）本来就只有
 * `add(String)` 这一个能力；真正的参数级约束在 [DirectInstallCommands] 的**唯一构造点**里，
 * 调用方拿不到任意命令行（与 `KsuCommands` 的纪律一致）。
 */
data class RootShellResult(
    val code: Int,
    val out: List<String> = emptyList(),
    val err: List<String> = emptyList(),
) {
    val stdout: String get() = out.joinToString("\n").trim()

    val stderr: String get() = err.joinToString("\n").trim()

    /** 第一条非空 stdout（命令构造层保证输出是单值/单行）。 */
    val firstLine: String get() = out.firstOrNull { it.isNotBlank() }?.trim().orEmpty()
}

/** root shell 端口（生产 = libsu；测试 = 假设备）。 */
fun interface RootShellRunner {
    fun run(command: String, timeoutMs: Long): RootShellResult
}

/** 直装分区提取的稳定失败码（UI 只做本地化映射，禁止字符串匹配）。 */
object DirectInstallCodes {
    /** 请求的分区不在白名单（`init_boot` / `boot`）内。 */
    const val PARTITION_UNSUPPORTED = "DIRECT_INSTALL_PARTITION_UNSUPPORTED"

    /** by-name 下找不到该分区的块设备节点（槽位拼错 / 机型没有这个分区）。 */
    const val DEVICE_NODE_MISSING = "DIRECT_INSTALL_DEVICE_NODE_MISSING"

    /** `dd` 退出码非 0。 */
    const val EXTRACT_FAILED = "DIRECT_INSTALL_EXTRACT_FAILED"

    /** `dd` 报成功但产物不存在或空文件。 */
    const val EXTRACT_EMPTY = "DIRECT_INSTALL_EXTRACT_EMPTY"

    /** 产物超过上限（防止把整块磁盘/错误节点拷进来）。 */
    const val EXTRACT_TOO_LARGE = "DIRECT_INSTALL_EXTRACT_TOO_LARGE"

    /** `wc -c` 读不回可解析的字节数。 */
    const val SIZE_READBACK_FAILED = "DIRECT_INSTALL_SIZE_READBACK_FAILED"

    /** 设备回报的字节数与本地文件长度不一致（回读校验失败）。 */
    const val SIZE_MISMATCH = "DIRECT_INSTALL_SIZE_MISMATCH"

    /** `sha256sum` 读不回合法摘要。 */
    const val DIGEST_READBACK_FAILED = "DIRECT_INSTALL_DIGEST_READBACK_FAILED"

    /** 设备回报的摘要与本地重算的摘要不一致（拷贝被截断/被改写）。 */
    const val DIGEST_MISMATCH = "DIRECT_INSTALL_DIGEST_MISMATCH"
}

/**
 * 命令构造的**唯一入口**（纯函数，主机可测）。
 *
 * 四条命令都用固定形态 + 单引号引用路径，不接受任何拼接进来的自由文本：
 * 1. [slotCommand]：`getprop ro.boot.slot_suffix`
 * 2. [resolveNodeCommand]：按候选顺序找出真实存在的 by-name 节点
 * 3. [ddCommand]：`dd if=/dev/block/by-name/<partition><slot> of=<cache>/... bs=1M`
 * 4. [sizeCommand] / [digestCommand]：`wc -c` / `sha256sum`（回读校验）
 */
object DirectInstallCommands {
    /** 槽位属性读取（失败只意味着 fallback，不是错误）。 */
    const val SLOT_COMMAND: String = "getprop ${InstallPartitionNodes.SLOT_PROPERTY}"

    /** 单条命令的超时（`dd` 单独给足窗口）。 */
    const val SMALL_TIMEOUT_MS: Long = 60_000L

    /** 整分区 `dd`（96 MiB 起）的窗口。 */
    const val DD_TIMEOUT_MS: Long = 600_000L

    /** 抽一个仍存在的块设备节点（按 [InstallPartitionNodes.nodeCandidates] 的顺序）。 */
    fun resolveNodeCommand(candidates: List<String>): String {
        require(candidates.isNotEmpty()) { "DIRECT_INSTALL_NO_NODE_CANDIDATE" }
        candidates.forEach {
            require(it.startsWith(InstallPartitionNodes.BY_NAME_DIR + "/")) {
                "DIRECT_INSTALL_NODE_OUT_OF_BY_NAME: $it"
            }
        }
        val quoted = candidates.joinToString(" ") { quote(it) }
        return "for n in $quoted; do if [ -b \"\$n\" ]; then echo \"\$n\"; break; fi; done"
    }

    /** `dd if=<node> of=<image> bs=1M`。 */
    fun ddCommand(node: String, image: File): String {
        require(node.startsWith(InstallPartitionNodes.BY_NAME_DIR + "/")) {
            "DIRECT_INSTALL_NODE_OUT_OF_BY_NAME: $node"
        }
        return "dd if=${quote(node)} of=${quote(image.absolutePath)} bs=1M"
    }

    /** `wc -c <image>`：设备侧字节数（与 App 侧文件长度对账）。 */
    fun sizeCommand(image: File): String = "wc -c ${quote(image.absolutePath)}"

    /** `sha256sum <image>`：设备侧摘要（与 App 侧重算对账）。 */
    fun digestCommand(image: File): String = "sha256sum ${quote(image.absolutePath)}"

    /** 单引号引用（与 `KsuInstallProducer.shellQuote` 同规则；本包不依赖 `ksu` 包）。 */
    fun quote(token: String): String {
        if (token.isNotEmpty() && token.all { it.isLetterOrDigit() || it in SAFE_CHARS }) return token
        return "'" + token.replace("'", "'\\''") + "'"
    }

    private const val SAFE_CHARS = "_-./:=+,@%"
}

/** 提取成功的产物（**已**通过长度与摘要回读校验）。 */
data class ExtractedPartitionImage(
    val image: File,
    val partition: InstallPartition,
    /** 实际使用的槽位（设备上报值，或 fallback `_a`）。 */
    val slotSuffix: String,
    /** 实际读取的块设备节点（`/dev/block/by-name/init_boot_a`）。 */
    val deviceNode: String,
    val size: Long,
    val sha256: String,
)

/** 提取结论：要么是可用的镜像文件，要么是稳定码 + 细节（绝不返回"半份镜像"）。 */
sealed interface PartitionExtractResult {
    data class Extracted(val value: ExtractedPartitionImage) : PartitionExtractResult

    data class Failed(val code: String, val detail: String) : PartitionExtractResult
}

/**
 * 「直接安装」时从**当前设备**提取目标分区镜像（用户口径：不要强制用户先选 boot 文件）。
 *
 * 与 KernelSU 的实现一致：读当前槽的 by-name 节点 → 落一份完整镜像 → 交给 `ksud boot-patch`
 * 修补 → 产物走既有刷写事务。本类**只读**分区、只写 App 私有目录，绝不写分区。
 *
 * 校验链（任一失败即 `Failed`，并把半成品删掉）：
 * 1. 分区名必须在白名单（[InstallPartition]）内；
 * 2. by-name 下必须存在该节点（`[ -b ]`）；
 * 3. `dd` 退出码 0；
 * 4. `wc -c` 回报的字节数 > 0 且 ≤ [maxBytes]，且等于本地文件长度（回读）；
 * 5. `sha256sum` 回报 64 位十六进制，且等于本地重算摘要（回读）。
 *
 * @param runner 已认证 root shell（生产 = [RootShellResult] 的 libsu 实现）
 * @param cacheDir 产物目录（`context.cacheDir/ksu-direct-install`）
 * @param maxBytes 单份镜像上限（默认 512 MiB，与页面探测上限一致）
 */
class RootPartitionExtractor(
    private val runner: RootShellRunner,
    private val cacheDir: File,
    private val maxBytes: Long = DEFAULT_MAX_BYTES,
) {

    /** 读设备槽位（失败 = 未上报，调用方按 fallback 处理，不是错误）。 */
    fun readSlotSuffix(): String? {
        val result = runner.run(DirectInstallCommands.SLOT_COMMAND, DirectInstallCommands.SMALL_TIMEOUT_MS)
        if (result.code != 0) return null
        return result.firstLine.ifEmpty { null }
    }

    /**
     * 提取 [partition] 的当前槽镜像。
     *
     * @param rawSlotSuffix `getprop ro.boot.slot_suffix` 的原始值（`null` = 未上报 → fallback `_a`）
     */
    fun extract(
        partition: InstallPartition,
        rawSlotSuffix: String?,
    ): PartitionExtractResult {
        if (partition.wire !in InstallPartition.ALLOWED_WIRE) {
            return PartitionExtractResult.Failed(
                DirectInstallCodes.PARTITION_UNSUPPORTED,
                "partition '${partition.wire}' is not one of ${InstallPartition.ALLOWED_WIRE}",
            )
        }
        val slot = InstallPartitionNodes.slotSuffix(rawSlotSuffix)
        val candidates = InstallPartitionNodes.nodeCandidates(partition, rawSlotSuffix)
        val node = when (val found = resolveNode(candidates)) {
            is NodeResolution.Found -> found.node
            is NodeResolution.Missing -> return found.failure
        }

        val image = File(
            cacheDir.apply { mkdirs() },
            "${InstallPartitionNodes.nodeName(partition, slot)}.img",
        )
        // 同一路径可能是上一次失败留下的残片：先删掉，避免"dd 失败但旧文件还在"被当成成功。
        runCatching { if (image.exists()) image.delete() }

        val dd = runner.run(
            DirectInstallCommands.ddCommand(node, image),
            DirectInstallCommands.DD_TIMEOUT_MS,
        )
        if (dd.code != 0) {
            runCatching { image.delete() }
            return PartitionExtractResult.Failed(
                DirectInstallCodes.EXTRACT_FAILED,
                "dd ${node} -> ${image.absolutePath} code=${dd.code} err=${dd.stderr}",
            )
        }
        if (!image.isFile || image.length() <= 0L) {
            runCatching { image.delete() }
            return PartitionExtractResult.Failed(
                DirectInstallCodes.EXTRACT_EMPTY,
                "dd reported success but ${image.absolutePath} is missing or empty",
            )
        }

        val reportedSize = runner.run(
            DirectInstallCommands.sizeCommand(image),
            DirectInstallCommands.SMALL_TIMEOUT_MS,
        )
        if (reportedSize.code != 0) {
            return fail(DirectInstallCodes.SIZE_READBACK_FAILED, image) {
                "wc -c code=${reportedSize.code} err=${reportedSize.stderr}"
            }
        }
        val size = reportedSize.stdout.substringBefore(' ').substringBefore('\t').toLongOrNull()
            ?: return fail(DirectInstallCodes.SIZE_READBACK_FAILED, image) {
                "wc -c output unparseable: '${reportedSize.stdout}'"
            }
        if (size <= 0L) {
            return fail(DirectInstallCodes.EXTRACT_EMPTY, image) { "wc -c reports 0 bytes" }
        }
        if (size > maxBytes) {
            return fail(DirectInstallCodes.EXTRACT_TOO_LARGE, image) {
                "extracted $size bytes > limit $maxBytes"
            }
        }
        if (image.length() != size) {
            return fail(DirectInstallCodes.SIZE_MISMATCH, image) {
                "device reports $size bytes, local file is ${image.length()}"
            }
        }

        val reportedDigest = runner.run(
            DirectInstallCommands.digestCommand(image),
            DirectInstallCommands.SMALL_TIMEOUT_MS,
        )
        val digest = reportedDigest.firstLine.substringBefore(' ').substringBefore('\t')
        if (reportedDigest.code != 0 || !SHA256_PATTERN.matches(digest)) {
            return fail(DirectInstallCodes.DIGEST_READBACK_FAILED, image) {
                "sha256sum code=${reportedDigest.code} out='${reportedDigest.stdout}'"
            }
        }
        val localDigest = runCatching { sha256Of(image) }.getOrNull()
            ?: return fail(DirectInstallCodes.DIGEST_READBACK_FAILED, image) {
                "cannot hash ${image.absolutePath}"
            }
        if (!localDigest.equals(digest, ignoreCase = true)) {
            return fail(DirectInstallCodes.DIGEST_MISMATCH, image) {
                "device reports $digest, local $localDigest"
            }
        }
        return PartitionExtractResult.Extracted(
            ExtractedPartitionImage(
                image = image,
                partition = partition,
                slotSuffix = slot,
                deviceNode = node,
                size = size,
                sha256 = localDigest,
            ),
        )
    }

    /** 节点探测结论（内部类型：不把"探测"和"已提取的镜像"混在同一个结果里）。 */
    private sealed interface NodeResolution {
        data class Found(val node: String) : NodeResolution

        data class Missing(val failure: PartitionExtractResult.Failed) : NodeResolution
    }

    /** 找出第一个存在的节点；找不到 = [DirectInstallCodes.DEVICE_NODE_MISSING]。 */
    private fun resolveNode(candidates: List<String>): NodeResolution {
        val command = runCatching { DirectInstallCommands.resolveNodeCommand(candidates) }
            .getOrElse {
                return NodeResolution.Missing(
                    PartitionExtractResult.Failed(
                        DirectInstallCodes.PARTITION_UNSUPPORTED,
                        it.message.orEmpty(),
                    ),
                )
            }
        val result = runner.run(command, DirectInstallCommands.SMALL_TIMEOUT_MS)
        val node = result.firstLine
        if (result.code != 0 || node.isEmpty() || node !in candidates) {
            return NodeResolution.Missing(
                PartitionExtractResult.Failed(
                    DirectInstallCodes.DEVICE_NODE_MISSING,
                    "no block device among $candidates (code=${result.code} out='${result.stdout}')",
                ),
            )
        }
        return NodeResolution.Found(node)
    }

    private inline fun fail(
        code: String,
        image: File,
        detail: () -> String,
    ): PartitionExtractResult.Failed {
        runCatching { image.delete() }
        return PartitionExtractResult.Failed(code, detail())
    }

    companion object {
        /** 与 `InstallBootFlow.PROBE_SIZE_LIMIT`（512 MiB）一致的镜像上限。 */
        const val DEFAULT_MAX_BYTES: Long = 512L * 1024 * 1024

        private val SHA256_PATTERN = Regex("^[0-9a-fA-F]{64}$")

        /** 流式摘要（绝不让 96 MiB 镜像整块进堆）。 */
        fun sha256Of(file: File): String {
            val digest = try {
                MessageDigest.getInstance("SHA-256")
            } catch (error: NoSuchAlgorithmException) {
                throw IllegalStateException("SHA256_UNAVAILABLE", error)
            }
            file.inputStream().use { input ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    digest.update(buffer, 0, read)
                }
            }
            return digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        }
    }
}
