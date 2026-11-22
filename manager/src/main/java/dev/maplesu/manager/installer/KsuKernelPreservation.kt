package dev.maplesu.manager.installer

import dev.maplesu.image.BootImageInspector
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.security.MessageDigest

/**
 * Normal（KSU / LKM）的**内核不变**门：LKM 补丁只允许改 ramdisk（`init`/`init.real`/
 * `kernelsu.ko`/`ksu_config`/`maplesu_id`），**永远不许改 kernel 段**。
 *
 * 为什么必须有这一层（用户口径 + D4）：
 * - Normal 的目标分区可以是 `init_boot`（镜像里根本没有 kernel 段）或 `boot`（kernel 与
 *   ramdisk 在同一个容器里）。`boot` 目标下，一旦候选的 kernel 段与源镜像不同，写进分区
 *   就等于**换成了别人的内核**——这不是 LKM 路线，属于 Ultra 内核路线的语义；
 * - `ksud boot-patch` 的构造层已经禁止了 `--kernel`（`KsuCommands.FORBIDDEN_TOKENS`），
 *   但"命令里没这个 flag"不等于"输出字节里 kernel 没变"：所以我们直接在**字节层**断言
 *   （`BootImageInspector` 给出的 `kernelOffset`/`kernelSize` 区间 SHA-256）。
 *
 * 判定口径（fail-closed）：
 * - `init_boot` 目标：容器里**不许有** kernel 段（有 = 把 boot 镜像当 init_boot 写）；
 *   裸 ramdisk 组件（没有 `ANDROID!` magic）合法，它本身就没有 kernel 段；
 * - `boot` 目标：源镜像必须给出（否则无法证明），两侧都必须是可解析的 `ANDROID!` 容器，
 *   kernel 段长度与摘要都必须相等；
 * - 容器读不出来（畸形/越界/IO）一律拒绝，**不**当作"没变化"。
 */
object KsuKernelPreservation {

    /** 候选的 kernel 段与源镜像不一致（LKM 补丁改到了内核 = 不允许）。 */
    const val CODE_KERNEL_CHANGED = "PRODUCE_CANDIDATE_KERNEL_CHANGED"

    /** 无法证明 kernel 未变（缺源镜像 / 容器读不出 / 不是 boot 容器）；fail-closed。 */
    const val CODE_KERNEL_UNVERIFIED = "PRODUCE_KERNEL_UNVERIFIED"

    /** `init_boot` 目标却拿到带 kernel 段的候选。 */
    const val CODE_KERNEL_UNEXPECTED = "PRODUCE_CANDIDATE_KERNEL_UNEXPECTED"

    /** `init_boot` 目标却拿带 kernel 段的镜像当**源**（选错分区/选错文件）。 */
    const val CODE_SOURCE_KERNEL_UNEXPECTED = "PRODUCE_SOURCE_KERNEL_UNEXPECTED"

    /** 一个镜像的 kernel 段事实（区间来自 `BootImageInspector`，摘要是该区间的 SHA-256）。 */
    sealed interface Layout {
        /** 不是 `ANDROID!` 容器：裸 ramdisk 组件，**没有** kernel 段可保护。 */
        data object NotContainer : Layout

        /** `ANDROID!` 容器。`kernelSize == 0` = 该容器不带内核（正常 `init_boot`）。 */
        data class Container(
            val kernelOffset: Long,
            val kernelSize: Long,
            val kernelSha256: String,
        ) : Layout

        /** 容器无法解析（畸形 / 越界 / IO）；调用方必须拒绝，不得当作"没变化"。 */
        data class Unreadable(val code: String) : Layout
    }

    /** 检查结论。 */
    sealed interface Verdict {
        data object Ok : Verdict

        data class Rejected(val code: String, val detail: String) : Verdict
    }

    /**
     * 读一个镜像的 kernel 段事实。
     *
     * @return [Layout.NotContainer] = 没有 `ANDROID!` magic（裸 ramdisk 组件）；
     *         [Layout.Unreadable] = 看起来是容器但解析不了。
     */
    fun inspectLayout(image: File): Layout {
        if (!image.isFile) return Layout.Unreadable("MISSING")
        val magic = magicOf(image) ?: return Layout.Unreadable("UNREADABLE_HEADER")
        if (!String(magic, Charsets.US_ASCII).equals(ANDROID_MAGIC)) return Layout.NotContainer
        val report = try {
            BootImageInspector.inspect(image)
        } catch (error: IOException) {
            return Layout.Unreadable(error.message ?: "INVALID_CONTAINER")
        }
        if (report.kernelOffset < 0 || report.kernelSize < 0 ||
            report.kernelOffset + report.kernelSize > report.fileSize
        ) {
            return Layout.Unreadable("KERNEL_OUT_OF_BOUNDS")
        }
        val digest = if (report.kernelSize > 0L) {
            try {
                sha256Range(image, report.kernelOffset, report.kernelSize)
            } catch (error: IOException) {
                return Layout.Unreadable(error.message ?: "KERNEL_UNREADABLE")
            }
        } else {
            ""
        }
        return Layout.Container(report.kernelOffset, report.kernelSize, digest)
    }

    /** 头 8 字节（`ANDROID!` magic）；读不到 → null。 */
    private fun magicOf(image: File): ByteArray? = try {
        val input = RandomAccessFile(image, "r")
        try {
            if (input.length() < ANDROID_MAGIC.length) {
                null
            } else {
                val magic = ByteArray(ANDROID_MAGIC.length)
                input.readFully(magic)
                magic
            }
        } finally {
            input.close()
        }
    } catch (error: IOException) {
        null
    }

    /**
     * 断言「补丁只改 ramdisk、没改 kernel」。
     *
     * @param partition 目标分区 wire 值（`init_boot` / `boot`；其它值由调用方先拒绝）
     * @param source 产候选用的源镜像；`null` = 没有源镜像（`boot` 目标下直接拒绝）
     * @param candidate 待写入的候选镜像
     */
    fun check(partition: String, source: File?, candidate: File): Verdict {
        val target = partition.trim().lowercase()
        val bootTarget = target == KsuInstallProducerDefaults.BOOT_PARTITION
        if (bootTarget && source == null) {
            return Verdict.Rejected(
                CODE_KERNEL_UNVERIFIED,
                "boot target needs the source image: the kernel block may only be proven " +
                    "unchanged against the image it was patched from",
            )
        }
        val candidateLayout = inspectLayout(candidate)
        if (candidateLayout is Layout.Unreadable) {
            return Verdict.Rejected(
                CODE_KERNEL_UNVERIFIED,
                "candidate container is unreadable (${candidateLayout.code}); " +
                    "cannot prove the kernel block is unchanged",
            )
        }
        val sourceLayout: Layout? = source?.let { inspectLayout(it) }
        if (sourceLayout is Layout.Unreadable) {
            return Verdict.Rejected(
                CODE_KERNEL_UNVERIFIED,
                "source container is unreadable (${sourceLayout.code}); " +
                    "cannot prove the kernel block is unchanged",
            )
        }
        val candidateKernel = candidateLayout as? Layout.Container
        val sourceKernel = sourceLayout as? Layout.Container

        if (bootTarget) {
            if (candidateKernel == null || sourceKernel == null) {
                return Verdict.Rejected(
                    CODE_KERNEL_UNVERIFIED,
                    "boot target needs two ANDROID! boot containers " +
                        "(candidate=${candidateLayout.label()}, source=${sourceLayout?.label()})",
                )
            }
            if (candidateKernel.kernelSize != sourceKernel.kernelSize) {
                return Verdict.Rejected(
                    CODE_KERNEL_CHANGED,
                    "kernel block size changed: ${sourceKernel.kernelSize} -> " +
                        "${candidateKernel.kernelSize} (the LKM patch must only touch the ramdisk)",
                )
            }
            if (sourceKernel.kernelSize > 0L &&
                !candidateKernel.kernelSha256.equals(sourceKernel.kernelSha256, ignoreCase = true)
            ) {
                return Verdict.Rejected(
                    CODE_KERNEL_CHANGED,
                    "kernel block changed: ${sourceKernel.kernelSha256} -> " +
                        "${candidateKernel.kernelSha256} (the LKM patch must only touch the ramdisk)",
                )
            }
            return Verdict.Ok
        }

        // init_boot：镜像里就没有 kernel 段。
        if (candidateKernel != null && candidateKernel.kernelSize > 0L) {
            return Verdict.Rejected(
                CODE_KERNEL_UNEXPECTED,
                "init_boot candidate carries a ${candidateKernel.kernelSize}-byte kernel block; " +
                    "an init_boot image has none (wrong partition?)",
            )
        }
        if (sourceKernel != null && sourceKernel.kernelSize > 0L) {
            return Verdict.Rejected(
                CODE_SOURCE_KERNEL_UNEXPECTED,
                "init_boot source carries a ${sourceKernel.kernelSize}-byte kernel block; " +
                    "that is a boot-partition image, not init_boot",
            )
        }
        return Verdict.Ok
    }

    /** 诊断/日志用的布局标签（不暴露内部结构细节）。 */
    private fun Layout.label(): String = when (this) {
        Layout.NotContainer -> "RAMDISK_COMPONENT"
        is Layout.Container -> "BOOT_CONTAINER(kernelSize=$kernelSize)"
        is Layout.Unreadable -> "UNREADABLE($code)"
    }

    /** `[offset, offset+length)` 区间的 SHA-256（只读，不整文件读入内存）。 */
    fun sha256Range(file: File, offset: Long, length: Long): String {
        require(offset >= 0L && length >= 0L) { "INVALID_RANGE" }
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            var remainingSkip = offset
            while (remainingSkip > 0L) {
                val stepped = input.skip(remainingSkip)
                if (stepped > 0L) {
                    remainingSkip -= stepped
                } else {
                    if (input.read() < 0) throw IOException("SHORT_KERNEL")
                    remainingSkip -= 1L
                }
            }
            var remaining = length
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (remaining > 0L) {
                val read = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
                if (read < 0) throw IOException("SHORT_KERNEL")
                digest.update(buffer, 0, read)
                remaining -= read.toLong()
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xFF) }
    }

    private const val ANDROID_MAGIC = "ANDROID!"
}
