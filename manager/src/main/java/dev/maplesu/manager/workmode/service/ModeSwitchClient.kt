package dev.maplesu.manager.workmode.service

import java.io.File

/**
 * App → root 服务 的 12 个模式切换 AIDL 方法端口（可主机 Fake）。
 *
 * 真实实现见 [ServiceClientModeSwitchClient]；UI/编排只依赖本接口，因此
 * `ModeSwitchFacadeTest` 可以在 JVM 里断言完整调用序列与流程收敛。
 */
data class ClientPartition(
    val name: String,
    val role: String,
    val size: Long,
    val preSha256: String,
    val targetSha256: String,
    val observedSha256: String,
    val state: String,
)

data class ClientStatus(
    val switchId: String,
    val state: String,
    val stage: String,
    val step: String,
    val fromMode: String,
    val toMode: String,
    val error: String,
    val errorDetail: String,
    val planSha256: String,
    val rebootRequired: Boolean,
    val bootObserved: Boolean,
    val canRollback: Boolean,
    val canResumeReboot: Boolean,
    val verifyFailures: Int,
    val partitions: List<ClientPartition>,
    /** Null in legacy status messages; never guessed from the current slot. */
    val slotSuffix: String? = null,
    /** Actual carrier; companions such as vendor_boot are not the installed carrier. */
    val targetPartition: String? = null,
    val signingMode: String? = null,
) {
    fun carrierCandidate(): ClientPartition? {
        val writes = partitions.filter { it.role == "WRITE_CANDIDATE" }
        return if (!targetPartition.isNullOrBlank()) writes.singleOrNull { it.name == targetPartition }
            else writes.singleOrNull { it.name in setOf("boot", "init_boot") }
    }

    val pending: Boolean
        get() = state in setOf(
            "BEGIN", "SNAPSHOT", "PRODUCE", "COMMIT", "REBOOT_REQUIRED",
            "VERIFYING", "ROLLING_BACK", "RECOVERY_REQUIRED",
        )
}

data class ClientResult(
    val ok: Boolean,
    val code: String = "",
    val detail: String = "",
    val status: ClientStatus? = null,
)

/** App 侧切换客户端端口：一个方法对应一个 AIDL 入口，全部 suspend（Binder 在 IO 线程执行）。 */
interface ModeSwitchClient {
    suspend fun preflight(switchId: String, planFields: Map<String, String>): ClientResult

    suspend fun begin(switchId: String, planFields: Map<String, String>,
                      superuserJson: File, settingsMirrorJson: File): ClientResult

    suspend fun snapshot(switchId: String): ClientResult

    /** 把服务端 PRE/BASE/CANDIDATE 只读副本导出到本地文件；失败返回 false。 */
    suspend fun exportImage(switchId: String, kind: String, partition: String, destination: File): Boolean

    suspend fun submitCandidate(switchId: String, partition: String,
                                candidate: File, candidateSha256: String): ClientResult

    suspend fun commit(switchId: String): ClientResult

    suspend fun rollback(switchId: String): ClientResult

    suspend fun abort(switchId: String): ClientResult

    fun status(switchId: String): ClientStatus?

    /** Exact task reads preserve transport/decoding errors; null means no record exists. */
    fun statusExact(switchId: String): ClientStatus? = status(switchId)

    suspend fun verify(switchId: String): ClientResult

    /** 只落 pending 标记；实际重启由 UI 决定。 */
    suspend fun markRebootRequested(switchId: String): Boolean

    suspend fun exportLog(switchId: String, destination: File): File?
}
