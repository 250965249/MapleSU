package dev.maplesu.manager.installer

import java.io.File

/** Shared Normal candidate contracts; mode switching uses the current workmode plan and clients. */
object KsuInstallCodes {
    /** No active installation submission is available to the caller. */
    const val NOT_ACTIVE = "SWITCH_NOT_ACTIVE"
}

/** 生产候选（由 `KsuInstallProducer` 适配；字段与 `KsuProducedCandidate` 一一对应）。 */
data class KsuProducedArtifact(
    val candidate: File,
    val size: Long,
    val sha256: String,
    val partition: String,
    /** `RamdiskInspector.Form` 名；未知时 null。 */
    val form: String?,
    /** `RamdiskState` token；未知时 null。 */
    val ramdiskState: String?,
    val sourceSha256: String,
    val kernelsuKoSha256: String?,
    /**
     * 产这个候选用的**源镜像**（默认 null = 旧装配没上报）。
     *
     * `boot` 目标下它是必需的：只有拿到源镜像才能证明"kernel 段逐字节未变"
     * （[KsuKernelPreservation]）。`init_boot` 目标不要求（镜像里没有 kernel 段）。
     */
    val source: File? = null,
)

object KsuInstallProducerDefaults {
    /** Normal 的默认目标分区（独立 `init_boot` + LKM，D4）。 */
    const val PARTITION = "init_boot"

    /**
     * Normal 的第二个可选目标分区（用户口径 2026-11-01：「Normal 可以选 init_boot 或 boot」）。
     *
     * 没有独立 `init_boot` 的机型只能走 `boot`；此时 kernel 与 ramdisk 在同一个容器里，
     * 因此 kernel 段必须逐字节保持不变（[KsuKernelPreservation]）。
     */
    const val BOOT_PARTITION = "boot"

    /** Normal 允许的写入目标（顺序 = `init_boot` 在前，与选择器一致）。 */
    val TARGETS: Set<String> = linkedSetOf(PARTITION, BOOT_PARTITION)

    /** wire 值是否属于 Normal 的合法目标（大小写/空白规范化后再判，白名单外一律 false）。 */
    fun isTarget(partition: String?): Boolean =
        TARGETS.contains(partition?.trim()?.lowercase().orEmpty())

    /** 规范化后的目标分区；非法/空 → null（**不兜底**成默认值）。 */
    fun normalize(partition: String?): String? =
        partition?.trim()?.lowercase()?.takeIf { TARGETS.contains(it) }
}

/** 候选校验期望（满长 = 目标分区长度；归属标记要求可配置，默认 fail-closed 要求 owned）。 */
data class KsuCandidateExpectation(
    val partition: String = KsuInstallProducerDefaults.PARTITION,
    val partitionSize: Long,
    val requireOwned: Boolean = true,
)

sealed interface KsuVerifyOutcome {
    data class Ok(
        val tailSha256: String,
        val form: String,
        val owned: Boolean,
        val kernelsuKoSha256: String?,
    ) : KsuVerifyOutcome

    data class Rejected(val code: String, val detail: String = "") : KsuVerifyOutcome
}

/** 候选结构校验端口（生产实现 = [RamdiskCandidateVerifier]，image-core `RamdiskInspector`）。 */
fun interface KsuCandidateVerifierPort {
    fun verify(artifact: KsuProducedArtifact, expectation: KsuCandidateExpectation): KsuVerifyOutcome
}

/** Error contract retained for InstallCommit client failure projection. */
class KsuInstallAbort(
    val stage: String,
    val code: String,
    val detail: String = "",
    val switchId: String = "",
    val aborted: Boolean = false,
    val rolledBack: Boolean = false,
    val requiresExternalRecovery: Boolean = false,
) : Exception("$code: $detail")

/** KMI 解析（S0-19；与 `KS:228,241` 同规则：android12-* 不走独立 init_boot）。 */
object KmiRule {
    private val PATTERN = Regex("^android(\\d+)-(\\d+(?:\\.\\d+)*)$")

    /** `5.10.198-android13-8-test` → `android13-5.10`；无法解析 → null。 */
    fun parse(kernelRelease: String): String? =
        KsuKmiDetector.parseKernelRelease(kernelRelease)?.let { (series, major) ->
            "android$major-$series"
        }

    /**
     * 是否允许 Normal（独立 `init_boot` + LKM）直装。
     *
     * 与矩阵无关：`android13-5.10` 形状合法但本矩阵未构建，产物缺失由
     * [KsuKmiSelector] / ksud 的内嵌资产查找负责拒绝。
     */
    fun supported(kmi: String): Boolean =
        PATTERN.matches(kmi) && !kmi.startsWith("android12-")
}
