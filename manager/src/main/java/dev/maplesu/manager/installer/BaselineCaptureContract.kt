package dev.maplesu.manager.installer

import dev.maplesu.manager.workmode.switch.AvbFacts
import dev.maplesu.manager.workmode.switch.BaselinePartition

/**
 * P0：baseline 捕获的端口与类型（真实镜像字节来源）。
 *
 * 审计缺口：`BaselineStore.capture` 只写 manifest（`open()` 恒 null），真机 S0-04 必然失败。
 * 本文件定义"从当前分区只读取整分区 → 校验 → 写控制面"的注入契约；
 * 生产实现见 [BaselineCaptureService] / [InstallerBaselineMaterializer]，
 * 主机测试用 fake 分区读取器，不触碰 Android/root/真实分区。
 */
object BaselineCaptureCodes {
    /** 读取/落盘阶段失败但 manifest 尚未建立。 */
    const val CAPTURE_READ_FAILED = "BASELINE_CAPTURE_READ_FAILED"
    const val CAPTURE_SIZE_MISMATCH = "BASELINE_PARTITION_SIZE_MISMATCH"
    const val CAPTURE_SHA_MISMATCH = "BASELINE_PARTITION_SHA_MISMATCH"
    const val CAPTURE_WRITE_FAILED = "BASELINE_CAPTURE_WRITE_FAILED"
    const val CAPTURE_READBACK_FAILED = "BASELINE_CAPTURE_READBACK_FAILED"
    const val IMPORT_SOURCE_MISSING = "BASELINE_IMPORT_SOURCE_MISSING"
    const val AVB_TAIL_INVALID = "BASELINE_AVB_TAIL_INVALID"
}

/** 只读分区事实（来自 installer 服务观测；sha256 为整分区摘要）。 */
data class BaselinePartitionFacts(
    val name: String,
    val size: Long,
    val sha256: String,
)

/** 当前设备/槽事实（只读；生产由 InstallerServiceClient.observeBootChain + getprop 适配）。 */
data class BaselineDeviceSnapshot(
    val slot: String,
    val firmware: String,
    val kernelRelease: String,
    val selinux: String,
    val partitions: Map<String, BaselinePartitionFacts>,
    val vbmeta: BaselineVbmetaFacts? = null,
) {
    /** baseline 至少需要 boot；有独立 init_boot 时两组都捕获（B/LKM 路线）。 */
    fun requiredPartitions(): List<String> = buildList {
        add("boot")
        if ("init_boot" in partitions) add("init_boot")
    }
}

data class BaselineVbmetaFacts(
    val present: Boolean,
    val sha256: String? = null,
    val verificationDisabled: Boolean = false,
)

data class BaselinePartitionRead(
    val name: String,
    /** 实际写出的字节数（必须 == 分区长度）。 */
    val size: Long,
    /** 实际写出字节的 sha256。 */
    val sha256: String,
)

/**
 * 只读分区读取器（生产 = installer 服务内 UID0 读取；主机测试 = fake 临时文件）。
 * 实现必须写满整分区（禁止短读补零），并返回真实 sha。
 */
interface BaselinePartitionSourcePort {
    fun snapshot(): BaselineDeviceSnapshot

    /** 把 `name` 分区完整写入 [destination]（覆盖），并返回 size/sha。 */
    fun readPartition(name: String, destination: java.io.File): BaselinePartitionRead
}

/**
 * A/B 补丁证据（来自控制面只读事实，不能靠猜）。
 * - [liteKernelMarker]：控制面 `installed.json` 的 Lite 内核 marker；null = 不可判定。
 * - [ksuUapi]：已记录的 KSU UAPI（null = 无）。
 * - [readable]=false 表示控制面读不到（没有 root/文件缺失）→ 必须 STALE/UNCLEAN 阻断。
 */
data class BaselinePatchEvidence(
    val readable: Boolean,
    val liteKernelMarker: Boolean?,
    val ksuUapi: Int?,
    val detail: String = "",
    val ultraKernelMarker: Boolean = false,
    val priorWriteRecorded: Boolean = false,
)

fun interface BaselinePatchEvidencePort {
    fun read(): BaselinePatchEvidence
}

/** cleanliness 结论（不可猜：证据不足时 clean=false + 明确 code）。 */
data class BaselineCleanReport(
    val clean: Boolean,
    val patchMarkers: dev.maplesu.manager.workmode.switch.PatchMarkers,
    val avbTailPreserved: Map<String, Boolean>,
    val evidence: List<String>,
    val code: String = "",
    val detail: String = "",
)

fun interface BaselineCleanlinessPort {
    fun verify(
        images: Map<String, java.io.File>,
        expectedSizes: Map<String, Long>,
        evidence: BaselinePatchEvidence,
    ): BaselineCleanReport
}

/** 来源分级（与 01 §6.2 provenance 对齐；CAPTURED_PRE_WRITE = PRE_FIRST_WRITE_CAPTURE）。 */
object BaselineSources {
    /** 已存在 OEM/外部 stock 备份 → 只读导入。 */
    const val OEM_PACKAGE = dev.maplesu.manager.workmode.switch.BaselineProvenance.OEM_PACKAGE

    /** 首次写入前捕获（本机当前槽真实镜像）。 */
    const val CAPTURED_PRE_WRITE =
        dev.maplesu.manager.workmode.switch.BaselineProvenance.PRE_FIRST_WRITE_CAPTURE

    /** 用户手动导入 OEM 镜像文件（UI 后续接入；host API 用同一 import 通道）。 */
    const val USER_IMPORT = OEM_PACKAGE

    val ALL: Set<String> = dev.maplesu.manager.workmode.switch.BaselineProvenance.ALL
}

/** UI 门面状态（App 侧只读；不缓存推断，全部来自 BaselineStore + 设备事实）。 */
enum class BaselineFacadeState { PRESENT_OK, MISSING, STALE, IMPORT_REQUIRED, CORRUPT }

data class BaselineFacadeStatus(
    val state: BaselineFacadeState,
    val baselineId: String? = null,
    val code: String = "",
    val detail: String = "",
    val canCapture: Boolean = false,
    val requiresImport: Boolean = false,
    val check: dev.maplesu.manager.workmode.switch.BaselineCheck? = null,
)

data class BaselineEnsureResult(
    val status: BaselineFacadeStatus,
    /** "NONE" | "CAPTURE" | "IMPORT" | "BLOCK"。 */
    val action: String,
    /** 非空即当前不能进入切换 S0（02 S0-04 硬门槛）。 */
    val blocker: String? = null,
)

/** `baseline/<id>/` 里除 manifest 外的镜像目录约定。 */
object BaselineImageNames {
    fun imageName(partition: String): String = "$partition.img"
}

/** 供 02 的 S0-04/S0-05 直接消费：由 cleanliness/facts 构造 manifest 分区行。 */
fun baselinePartition(
    facts: BaselinePartitionFacts,
    avbTailPreserved: Boolean,
): BaselinePartition = BaselinePartition(
    name = facts.name,
    size = facts.size,
    sha256 = facts.sha256,
    avbTailPreserved = avbTailPreserved,
)

/** vbmeta 事实 → manifest 的 AvbFacts（只读投影，不写 vbmeta）。 */
fun baselineAvbFacts(vbmeta: BaselineVbmetaFacts?): AvbFacts = AvbFacts(
    vbmetaPresent = vbmeta?.present == true,
    vbmetaSha256 = vbmeta?.sha256,
    verificationDisabled = vbmeta?.verificationDisabled == true,
)
