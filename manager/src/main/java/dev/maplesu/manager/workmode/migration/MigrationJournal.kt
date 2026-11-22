package dev.maplesu.manager.workmode.migration

import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.control.ControlPermissions
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.ProcBootIdSource
import dev.maplesu.manager.workmode.detect.WallClock
import kotlinx.serialization.Serializable
import java.io.File
import java.io.IOException

/**
 * 迁移 WAL / journal（05 §4.4 / §4.8）。
 *
 * 两层语义：
 * - `journal.json` 是**状态权威**（原子整文件替换，schema 1）；
 * - `history[]` 是 intent→done 追证，用于崩溃后判定"每个分区到底写没写"。
 *
 * 恢复永远以**分区读回**为准，不以 journal 猜测分区状态（主文档:705-713）。
 */
enum class MigrationState(val wire: String) {
    M0_DETECTED("M0_DETECTED"),
    M1_BACKED_UP("M1_BACKED_UP"),
    M2_PLANNED("M2_PLANNED"),
    M3_PRODUCED("M3_PRODUCED"),
    M4_WRITING("M4_WRITING"),
    M5_DEPLOYING("M5_DEPLOYING"),
    M6_CLEANUP("M6_CLEANUP"),
    M7_FINALIZED("M7_FINALIZED"),
    M8_REBOOT_REQUESTED("M8_REBOOT_REQUESTED"),
    M9_VERIFIED("M9_VERIFIED"),
    M1_FAILED("M1_FAILED"),
    M2_FAILED("M2_FAILED"),
    FAILED("FAILED"),
    ROLLING_BACK("ROLLING_BACK"),
    ROLLED_BACK("ROLLED_BACK"),
    RECOVERY_REQUIRED("RECOVERY_REQUIRED");

    val isTerminal: Boolean get() = this in TERMINAL

    companion object {
        /**
         * 05 §4.3：pending 的终态集合。`RECOVERY_REQUIRED` **不是**终态——
         * 它必须继续阻断普通安装/切换/模块事务（主文档:745）。
         */
        val TERMINAL: Set<MigrationState> = setOf(
            M9_VERIFIED, ROLLED_BACK, M1_FAILED, M2_FAILED, FAILED,
        )

        fun fromWire(value: String?): MigrationState? = entries.firstOrNull { it.wire == value }

        /** 允许的状态跃迁；任何不在表内的跃迁 → `MIGRATION_JOURNAL_STATE_INVALID`。 */
        val TRANSITIONS: Map<MigrationState, Set<MigrationState>> = mapOf(
            M0_DETECTED to setOf(M1_BACKED_UP, M1_FAILED, FAILED, ROLLING_BACK),
            M1_BACKED_UP to setOf(M2_PLANNED, M2_FAILED, FAILED, ROLLING_BACK),
            M2_PLANNED to setOf(M3_PRODUCED, FAILED, ROLLING_BACK),
            M3_PRODUCED to setOf(M4_WRITING, FAILED, ROLLING_BACK),
            M4_WRITING to setOf(M5_DEPLOYING, ROLLING_BACK, RECOVERY_REQUIRED),
            M5_DEPLOYING to setOf(M6_CLEANUP, ROLLING_BACK, RECOVERY_REQUIRED),
            M6_CLEANUP to setOf(M7_FINALIZED, ROLLING_BACK, RECOVERY_REQUIRED),
            M7_FINALIZED to setOf(M8_REBOOT_REQUESTED, ROLLING_BACK),
            M8_REBOOT_REQUESTED to setOf(M9_VERIFIED, RECOVERY_REQUIRED, ROLLING_BACK),
            ROLLING_BACK to setOf(ROLLED_BACK, RECOVERY_REQUIRED, FAILED),
            // 终态不再跃迁（重试 = 新 migrationId）。
            M9_VERIFIED to emptySet(),
            ROLLED_BACK to emptySet(),
            M1_FAILED to emptySet(),
            M2_FAILED to emptySet(),
            FAILED to emptySet(),
            RECOVERY_REQUIRED to setOf(ROLLING_BACK),
        )

        fun canTransition(from: MigrationState, to: MigrationState): Boolean =
            TRANSITIONS[from]?.contains(to) == true
    }
}

@Serializable
data class JournalImage(val path: String = "", val size: Long = 0, val sha256: String = "", val source: String = "")

@Serializable
data class JournalTransport(
    val suPath: String = "",
    val ancestorCmdline: String = "",
    val servicePid: Int = -1,
) {
    /**
     * 写权限绑定（05 §4.5）：传输链必须同时出现 su 与祖先 cmdline，且服务 pid 必须是当前进程。
     * UI 标志 / Binder 参数**不**参与判定。
     */
    fun matches(chain: List<String>, currentPid: Int): Boolean {
        if (servicePid <= 0 || currentPid != servicePid) return false
        if (suPath.isBlank() || ancestorCmdline.isBlank()) return false
        val suName = suPath.substringAfterLast('/')
        return chain.any { it.contains(ancestorCmdline) } && chain.any { it.contains(suName) }
    }
}

@Serializable
data class JournalPartition(
    val name: String,
    /** PartitionAction 名称。 */
    val action: String,
    val pre: JournalImage = JournalImage(),
    val final: JournalImage = JournalImage(),
    val producerInput: JournalImage? = null,
    val residue: String = "NONE",
    val writeIntent: Boolean = false,
    val writeDone: Boolean = false,
    val readBackSha256: String = "",
) {
    fun toPlanned(): PlannedPartition = PlannedPartition(
        name = name,
        action = PartitionAction.valueOf(action),
        pre = pre.toImageRef(ImageSource.PRE_PARTITION),
        final = final.toImageRefOrNull(),
        producerInput = producerInput?.toImageRefOrNull(),
        residue = ResidueMode.valueOf(residue),
    )

    private fun JournalImage.toImageRefOrNull(): ImageRef? =
        if (sha256.isBlank() || path.isBlank()) null
        else ImageRef(path, size, sha256, ImageSource.CANDIDATE)

    private fun JournalImage.toImageRef(source: ImageSource): ImageRef = ImageRef(path, size, sha256, source)
}

@Serializable
data class JournalSource(
    val family: String = "",
    val version: String = "",
    val uapi: Int? = null,
    val managerPackages: List<String> = emptyList(),
    val restoreStrategy: String = "",
    val detectSha256: String = "",
    val transport: JournalTransport? = null,
)

@Serializable
data class JournalTarget(val mode: String = "", val targetSet: List<String> = emptyList())

@Serializable
data class JournalData(
    val moduleTotal: Int = 0,
    val moduleImported: Int = 0,
    val moduleSkipped: Int = 0,
    val authSource: String = "",
    val authIntents: Int = 0,
    val authStale: Int = 0,
    val authApplied: Int = 0,
    val apkUninstall: String = "NONE",
    val apkPackages: List<String> = emptyList(),
)

@Serializable
data class JournalBackup(
    val manifestPath: String = "",
    val sha256: String = "",
    val verified: Boolean = false,
)

@Serializable
data class JournalHistoryEntry(
    val seq: Long,
    val atEpochMs: Long,
    val phase: String,
    /** TRANSITION / INTENT / DONE / BACKUP_VERIFIED / RESIDUE / ERROR / EXTERNAL_RESTORE_UNAVAILABLE。 */
    val event: String,
    val partition: String = "",
    val fromSha256: String = "",
    val toSha256: String = "",
    val state: String = "",
    val code: String = "",
)

@Serializable
data class MigrationJournalFile(
    val schema: Int = SCHEMA,
    val migrationId: String,
    val state: String = MigrationState.M0_DETECTED.wire,
    val phase: String = "M0",
    val error: String = "",
    val createdAtEpochMs: Long = 0,
    val updatedAtEpochMs: Long = 0,
    val bootId: String = "",
    val kernelRelease: String = "",
    val firmware: String = "",
    val slotSuffix: String = "",
    val source: JournalSource = JournalSource(),
    val target: JournalTarget = JournalTarget(),
    val restoreSet: List<String> = emptyList(),
    val partitions: List<JournalPartition> = emptyList(),
    val residues: List<ResidueRecord> = emptyList(),
    val data: JournalData = JournalData(),
    val backup: JournalBackup = JournalBackup(),
    val rebootRequestUptimeMs: Long = 0,
    val history: List<JournalHistoryEntry> = emptyList(),
) {
    companion object {
        const val SCHEMA = 1
    }

    fun stateValue(): MigrationState =
        MigrationState.fromWire(state) ?: throw MigrationFailure(MigrationCodes.JOURNAL_INVALID, state)

    fun partitionOrNull(name: String): JournalPartition? = partitions.firstOrNull { it.name == name }

    fun toPlannedPartitions(): List<PlannedPartition> = partitions.map { it.toPlanned() }

    fun isTerminal(): Boolean = stateValue().isTerminal
}

/** 崩溃恢复判定（05 §4.8）：`intent` 无 `done` 的分区按读回值收敛。 */
object RecoveryRules {
    enum class Action { MARK_DONE, NOT_EXECUTED, RECOVERY_REQUIRED, NOTHING }

    data class PartitionOutcome(val partition: String, val action: Action, val observedSha256: String = "")

    /** [observed] 返回该分区当前整分区 SHA-256；null = 不可读。 */
    fun classify(
        journal: MigrationJournalFile,
        expectedFinal: Map<String, String>,
        expectedPre: Map<String, String>,
        observed: (String) -> String?,
    ): List<PartitionOutcome> {
        val outcomes = mutableListOf<PartitionOutcome>()
        for (partition in journal.partitions) {
            if (!partition.writeIntent || partition.writeDone) continue
            val name = partition.name
            val current = observed(name)
            val finalSha = expectedFinal[name] ?: partition.final.sha256
            val preSha = expectedPre[name] ?: partition.pre.sha256
            val action = when {
                current == null -> Action.RECOVERY_REQUIRED
                current == finalSha -> Action.MARK_DONE
                current == preSha -> Action.NOT_EXECUTED
                else -> Action.RECOVERY_REQUIRED
            }
            outcomes += PartitionOutcome(name, action, current ?: "")
        }
        return outcomes
    }
}

/**
 * `journal.json` 文件实现（主机可测；设备侧同一实现 + root 适配器）。
 *
 * 状态写入一次 = 整文件 canonical JSON 原子替换；history 只增（seq 单调）。
 */
class FileMigrationJournal(
    private val root: File,
    private val clock: Clock = WallClock,
    private val bootIdSource: BootIdSource = ProcBootIdSource,
) {

    fun begin(
        migrationId: String,
        source: JournalSource = JournalSource(),
        target: JournalTarget = JournalTarget(),
        restoreSet: List<String> = emptyList(),
        kernelRelease: String = "",
        firmware: String = "",
        slotSuffix: String = "",
    ): MigrationJournalFile {
        MigrationPaths.requireCanonicalId(migrationId)
        val now = clock.nowMillis()
        val journal = MigrationJournalFile(
            migrationId = migrationId,
            state = MigrationState.M0_DETECTED.wire,
            phase = "M0",
            createdAtEpochMs = now,
            updatedAtEpochMs = now,
            bootId = bootIdSource.read(),
            kernelRelease = kernelRelease,
            firmware = firmware,
            slotSuffix = slotSuffix,
            source = source.copy(
                managerPackages = source.managerPackages.sorted(),
            ),
            target = target.copy(targetSet = target.targetSet.sorted()),
            restoreSet = restoreSet.sorted(),
            history = listOf(
                JournalHistoryEntry(
                    seq = 1, atEpochMs = now, phase = "M0", event = "TRANSITION",
                    state = MigrationState.M0_DETECTED.wire,
                ),
            ),
        )
        save(journal)
        return journal
    }

    fun read(migrationId: String): MigrationJournalFile? {
        val file = MigrationPaths.journal(root, migrationId)
        if (!file.isFile) return null
        val raw = AtomicControlFile.readUtf8(file)
            ?: throw MigrationFailure(MigrationCodes.JOURNAL_INVALID, "unreadable")
        val journal = ControlJsonCodec.decodeOrNull<MigrationJournalFile>(raw)
            ?: throw MigrationFailure(MigrationCodes.JOURNAL_INVALID, "parse")
        if (journal.schema != MigrationJournalFile.SCHEMA) {
            throw MigrationFailure(MigrationCodes.JOURNAL_INVALID, "schema=${journal.schema}")
        }
        if (journal.migrationId != migrationId) {
            throw MigrationFailure(MigrationCodes.JOURNAL_INVALID, "migrationId")
        }
        // schema 合法但 state 非法同样是损坏（不允许降级为某个默认状态）。
        journal.stateValue()
        return journal
    }

    fun save(journal: MigrationJournalFile): MigrationJournalFile {
        val file = MigrationPaths.journal(root, journal.migrationId)
        file.parentFile?.let { ControlPermissions.ensureDir(it) }
        val normalized = journal.copy(
            updatedAtEpochMs = if (journal.updatedAtEpochMs == 0L) clock.nowMillis() else journal.updatedAtEpochMs,
            source = journal.source.copy(managerPackages = journal.source.managerPackages.sorted()),
            target = journal.target.copy(targetSet = journal.target.targetSet.sorted()),
            restoreSet = journal.restoreSet.sorted(),
            residues = journal.residues.sortedWith(compareBy({ it.path }, { it.kind })),
            partitions = journal.partitions.sortedBy { it.name },
        )
        AtomicControlFile.writeJson(file, ControlJsonCodec.encode(normalized))
        return normalized
    }

    fun transition(
        journal: MigrationJournalFile,
        to: MigrationState,
        phase: String = to.wire.substringBefore('_'),
        error: String = "",
    ): MigrationJournalFile {
        val from = journal.stateValue()
        MigrationFailure.require(
            MigrationState.canTransition(from, to),
            MigrationCodes.JOURNAL_STATE_INVALID,
            "${from.wire} -> ${to.wire}",
        )
        val updated = appendHistory(
            journal.copy(
                state = to.wire,
                phase = phase,
                error = error,
                updatedAtEpochMs = clock.nowMillis(),
            ),
            JournalHistoryEntry(
                seq = journal.history.size + 1L,
                atEpochMs = clock.nowMillis(),
                phase = phase,
                event = "TRANSITION",
                fromSha256 = "",
                toSha256 = "",
                state = to.wire,
                code = error,
            ),
        )
        return save(updated)
    }

    fun setPlan(
        journal: MigrationJournalFile,
        partitions: List<JournalPartition>,
        restoreSet: List<String>,
        residuals: List<ResidueRecord> = emptyList(),
    ): MigrationJournalFile = save(
        journal.copy(
            partitions = partitions,
            restoreSet = restoreSet,
            residues = journal.residues + residuals,
        ),
    )

    fun recordBackupVerified(journal: MigrationJournalFile, manifestSha256: String): MigrationJournalFile =
        appendEvent(
            journal.copy(backup = JournalBackup(
                manifestPath = "backup/manifest.json",
                sha256 = manifestSha256,
                verified = true,
            )),
            event = "BACKUP_VERIFIED",
            phase = "M1",
        )

    fun recordIntent(
        journal: MigrationJournalFile,
        partition: String,
        fromSha256: String,
    ): MigrationJournalFile {
        val partitions = journal.partitions.map { entry ->
            if (entry.name == partition) {
                entry.copy(writeIntent = true, writeDone = false, readBackSha256 = "")
            } else {
                entry
            }
        }
        return appendEvent(
            journal.copy(partitions = partitions),
            event = "INTENT",
            phase = "M4",
            partition = partition,
            fromSha256 = fromSha256,
        )
    }

    fun recordDone(
        journal: MigrationJournalFile,
        partition: String,
        readBackSha256: String,
    ): MigrationJournalFile {
        val partitions = journal.partitions.map { entry ->
            if (entry.name == partition) {
                entry.copy(writeIntent = true, writeDone = true, readBackSha256 = readBackSha256)
            } else {
                entry
            }
        }
        return appendEvent(
            journal.copy(partitions = partitions),
            event = "DONE",
            phase = "M4",
            partition = partition,
            toSha256 = readBackSha256,
        )
    }

    fun recordResidue(journal: MigrationJournalFile, residue: ResidueRecord): MigrationJournalFile =
        appendEvent(
            journal.copy(residues = journal.residues + residue),
            event = "RESIDUE",
            partition = residue.path,
            code = residue.reason,
        )

    fun recordExternalRestoreUnavailable(
        journal: MigrationJournalFile,
        partition: String,
        reason: String,
    ): MigrationJournalFile = appendEvent(
        journal,
        event = "EXTERNAL_RESTORE_UNAVAILABLE",
        partition = partition,
        code = reason,
    )

    fun recordError(journal: MigrationJournalFile, code: String): MigrationJournalFile =
        appendEvent(journal, event = "ERROR", code = code)

    /** 进入回滚（任一非终态阶段失败）。 */
    fun beginRollingBack(journal: MigrationJournalFile, code: String): MigrationJournalFile {
        val from = journal.stateValue()
        if (from == MigrationState.ROLLING_BACK) return journal
        MigrationFailure.require(
            MigrationState.canTransition(from, MigrationState.ROLLING_BACK),
            MigrationCodes.JOURNAL_STATE_INVALID,
            "${from.wire} -> ROLLING_BACK",
        )
        return transition(journal, MigrationState.ROLLING_BACK, phase = "RB", error = code)
    }

    /** 逆序回滚的每步：intent → 写 pre → 整分区读回 → done。 */
    fun recordRollbackIntent(journal: MigrationJournalFile, partition: String): MigrationJournalFile =
        appendEvent(journal, event = "ROLLBACK_INTENT", phase = "RB", partition = partition)

    fun recordRollbackDone(
        journal: MigrationJournalFile,
        partition: String,
        readBackSha256: String,
    ): MigrationJournalFile = appendEvent(
        journal,
        event = "ROLLBACK_DONE",
        phase = "RB",
        partition = partition,
        toSha256 = readBackSha256,
    )

    /** 回滚成功：分区全部读回 == pre 时调用；失败走 RECOVERY_REQUIRED（不谎报）。 */
    fun finalizeRolledBack(journal: MigrationJournalFile): MigrationJournalFile =
        transition(journal, MigrationState.ROLLED_BACK, phase = "RB")

    private fun appendEvent(
        journal: MigrationJournalFile,
        event: String,
        phase: String = journal.phase,
        partition: String = "",
        fromSha256: String = "",
        toSha256: String = "",
        code: String = "",
    ): MigrationJournalFile = save(
        appendHistory(
            journal.copy(updatedAtEpochMs = clock.nowMillis()),
            JournalHistoryEntry(
                seq = journal.history.size + 1L,
                atEpochMs = clock.nowMillis(),
                phase = phase,
                event = event,
                partition = partition,
                fromSha256 = fromSha256,
                toSha256 = toSha256,
                state = journal.state,
                code = code,
            ),
        ),
    )

    private fun appendHistory(
        journal: MigrationJournalFile,
        entry: JournalHistoryEntry,
    ): MigrationJournalFile = journal.copy(history = journal.history + entry)

    /** 所有非终态迁移 id（供安装/切换/模块事务在入口检查 pending）。 */
    fun pendingIds(): List<String> {
        val migrations = MigrationPaths.migrationsDir(root)
        val dirs = migrations.listFiles()?.filter { it.isDirectory } ?: return emptyList()
        return dirs.mapNotNull { dir ->
            // 读不出的 journal 一律按 pending 处理（fail-safe：损坏不等于已完成）。
            val journal = runCatching { read(dir.name) }.getOrNull()
            when {
                journal == null -> if (MigrationPaths.journal(root, dir.name).isFile) dir.name else null
                journal.isTerminal() -> null
                else -> journal.migrationId
            }
        }.sorted()
    }

    fun isPending(): Boolean = pendingIds().isNotEmpty()

    /** M9 残留记录 + 报告（05 §7.1）；residual 只影响验收计数，不作为失败条件。 */
    fun finalizeVerified(
        journal: MigrationJournalFile,
        residues: List<ResidueRecord>,
        residual: Boolean,
    ): MigrationJournalFile {
        val target = appendEvent(
            journal.copy(residues = residues),
            event = "VERIFIED",
            phase = "M9",
            code = if (residual) "RESIDUAL" else "",
        )
        return transition(target, MigrationState.M9_VERIFIED, phase = "M9")
    }

    /** 读不到或损坏的 journal 不得静默忽略：返回错误码让调用方进入 RECOVERY_REQUIRED。 */
    fun readOrError(migrationId: String): MigrationJournalFile? = try {
        read(migrationId)
    } catch (failure: MigrationFailure) {
        throw failure
    }
}
