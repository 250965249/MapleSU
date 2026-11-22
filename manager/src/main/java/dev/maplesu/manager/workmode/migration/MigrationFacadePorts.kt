package dev.maplesu.manager.workmode.migration

import dev.maplesu.manager.workmode.WorkMode
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import java.io.File

/**
 * 迁移后端端口（W20–W22；05 §1.2/§4.1）。
 *
 * UI 只经 [MigrationFacade] 检测/开始/观察/中止；设备分区写入由 [MigrationWritePort] 完成，
 * **本层不暴露任何裸写接口**。host 测试注入 fake 端口；设备侧由 `MigrationRuntime` 组装。
 */
sealed interface MigrationDetectionResult {
    /** 检测成功：`migrationId` 供后续 observe/abort；摘要只含可展示字段。 */
    data class Ready(
        val info: ExternalRootInfo,
        val eligibility: MigrationEligibility,
        val migrationId: String = "",
    ) : MigrationDetectionResult

    /** 无 root / 探针不可用 / 后端未接线：**绝不猜测**成某个家族。 */
    data class Unavailable(val code: String) : MigrationDetectionResult
}

sealed interface MigrationStartResult {
    data class Accepted(val migrationId: String) : MigrationStartResult

    /** 计划性拒绝（阻断条件/目标不可产出）：无副作用，不创建迁移目录。 */
    data class Refused(val code: String, val reasons: List<String> = emptyList()) : MigrationStartResult

    /** 已开始但立即失败（例如备份先行校验失败）；结构化错误，不假装成功。 */
    data class Failed(val code: String, val stage: MigrationStage = MigrationStage.IDLE) : MigrationStartResult
}

/** M0–M9 的 UI 可见投影（observe 的唯一事件集）。 */
sealed interface MigrationObservation {
    data class Progress(
        val stage: MigrationStage,
        val stepIndex: Int = 0,
        val stepCount: Int = MigrationStageKeys.PROGRESS_STAGES.size,
        val stepKey: String = "",
        val logLine: String = "",
    ) : MigrationObservation

    data class Backup(val summary: MigrationBackupSummary) : MigrationObservation
    data class Completed(val result: MigrationResultUi) : MigrationObservation
    data class Failed(val failure: MigrationFailureUi) : MigrationObservation
}

interface MigrationFacade {
    suspend fun detect(): MigrationDetectionResult

    /** 计划性拒绝返回 [MigrationStartResult.Refused]；接受后立即返回 Accepted 并异步推进。 */
    suspend fun start(target: WorkMode): MigrationStartResult

    fun observe(migrationId: String): Flow<MigrationObservation>

    /** 只在破坏性写入开始前有效；返回 false = 后端拒绝（UI 转恢复入口）。 */
    suspend fun abort(migrationId: String): Boolean

    /** 当前迁移 id（未检测则空串）；UI 从检测页跳转进度页时使用。 */
    fun currentMigrationId(): String = ""
}

/** 默认无后端：诚实降级，绝不伪造检测/进度（05 §6.2）。 */
object UnavailableMigrationFacade : MigrationFacade {
    const val CODE = "MIGRATION_BACKEND_UNAVAILABLE"

    override suspend fun detect(): MigrationDetectionResult = MigrationDetectionResult.Unavailable(CODE)

    override suspend fun start(target: WorkMode): MigrationStartResult =
        MigrationStartResult.Refused(CODE)

    override fun observe(migrationId: String): Flow<MigrationObservation> = emptyFlow()

    override suspend fun abort(migrationId: String): Boolean = false
}

// ---------------------------------------------------------------------------------------------
// 设备/主机基础设施端口
// ---------------------------------------------------------------------------------------------

/** 只读探针端口：返回检测输入；不可用必须显式失败，禁止返回"猜出来的家族"。 */
sealed interface MigrationProbeResult {
    data class Ready(
        val probe: ExternalRootProbe,
        val inventory: PackageInventory = PackageInventory(),
    ) : MigrationProbeResult

    data class Unavailable(val code: String) : MigrationProbeResult
}

fun interface MigrationProbePort {
    suspend fun read(): MigrationProbeResult
}

/** 备份端口（M1）：任何一项读回校验失败都必须让整个迁移中止（红线 11）。 */
sealed interface MigrationBackupOutcome {
    /** 备份完成且 manifest 已验证（`backup.complete == true`）。 */
    data class Verified(
        val summary: MigrationBackupSummary,
        val manifestPath: String = "",
        val manifestSha256: String = "",
    ) : MigrationBackupOutcome

    data class Failed(val code: String, val detail: String = "") : MigrationBackupOutcome
}

fun interface MigrationBackupPort {
    suspend fun capture(migrationId: String, info: ExternalRootInfo): MigrationBackupOutcome
}

/** 目标分区写入结果（设备侧事务；host 默认不可用 → 结构化错误，不假装成功）。 */
sealed interface MigrationWriteOutcome {
    data class Written(val rebootRequired: Boolean = true) : MigrationWriteOutcome

    /** 已写部分回滚成功。 */
    data class RolledBack(val code: String) : MigrationWriteOutcome

    /** 回滚未完成，需要外部恢复（不得报成功）。 */
    data class RecoveryRequired(val code: String) : MigrationWriteOutcome

    /** 未写入/未开始写入的失败（可按普通失败处理）。 */
    data class Failed(val code: String) : MigrationWriteOutcome
}

/** 分区写入端口：实现方必须是共用分区事务（05 红线 4）。 */
interface MigrationWritePort {
    /** false = 本环境没有可用写入通道（如未接 root 服务）；start 会在写入前结构化失败。 */
    fun available(): Boolean

    /** 目标用户态部署（KSU bootstrap / Lite 凭据、模块/授权落地）。 */
    suspend fun deploy(migrationId: String, target: WorkMode): MigrationWriteOutcome =
        MigrationWriteOutcome.Written()

    suspend fun write(migrationId: String, target: WorkMode, plan: MigrationPlan): MigrationWriteOutcome
}

object UnavailableMigrationWritePort : MigrationWritePort {
    const val CODE = "MIGRATION_DEVICE_WRITE_UNAVAILABLE"

    override fun available(): Boolean = false

    override suspend fun write(migrationId: String, target: WorkMode, plan: MigrationPlan): MigrationWriteOutcome =
        MigrationWriteOutcome.Failed(CODE)
}

object UnavailableMigrationBackupPort : MigrationBackupPort {
    const val CODE = "MIGRATION_DEVICE_BACKUP_UNAVAILABLE"

    override suspend fun capture(migrationId: String, info: ExternalRootInfo): MigrationBackupOutcome =
        MigrationBackupOutcome.Failed(CODE, "no root/backup channel")
}

/** 迁移工作目录根（设备 = `/data/adb/maplesu-workmode`；host 测试 = 临时目录）。 */
fun migrationWorkRoot(override: File? = null): File = override ?: File(MigrationPaths.ROOT)
