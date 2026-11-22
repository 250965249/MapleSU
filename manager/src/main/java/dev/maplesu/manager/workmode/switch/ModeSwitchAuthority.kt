package dev.maplesu.manager.workmode.switch

import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.control.ControlPermissions
import dev.maplesu.manager.workmode.control.ShaCheck
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.WallClock
import kotlinx.serialization.Serializable
import java.io.File
import java.io.IOException

/**
 * `control/switch.json`（切换持久权威态，02 §3.2 字段级 schema）。
 *
 * `ControlPlane` 只读 switch 投影（`readSwitchHead()`）。本文件是状态的唯一写点；
 * `SwitchJournal` 负责追证 WAL，两者职责分开。
 *
 * 与 `SwitchHeadViewCodec.parse` 的兼容性由字段名保证：
 * `switchId/state/fromMode/toMode/startBootId/updatedAtUptimeMs/attempts.rebootRequests/error.{code,stage}`。
 */
@Serializable
data class SwitchRecordDevice(
    val slotSuffix: String = "",
    val firmware: String = "",
    val kernelRelease: String = "",
    val kmi: String = "",
    val selinux: String = "Enforcing",
)

@Serializable
data class SwitchRecordPartition(
    val name: String,
    /** `RESTORE_BASELINE` | `WRITE_CANDIDATE`（与 `SwitchStep.Role` 同名）。 */
    val role: String,
    val size: Long,
    val preSha256: String,
    val targetSha256: String,
    val tailSha256: String,
    /** PENDING | INTENT | DONE | FAILED | ROLLBACK_INTENT | ROLLED_BACK。 */
    val state: String,
    val observedSha256: String = "",
)

@Serializable
data class SwitchRecordStep(val id: String, val state: String)

@Serializable
data class SwitchRecordMove(
    val path: String,
    val kind: String,
    val target: String = "",
    val owner: String = "",
    val state: String,
    val crossMount: Boolean = false,
)

@Serializable
data class SwitchRecordMaterialize(val state: String = "PENDING", val detail: String = "")

@Serializable
data class SwitchRecordError(
    val code: String = "",
    val stage: String = "",
    val step: String = "",
    val detail: String = "",
    val atUptimeMs: Long = 0,
)

@Serializable
data class SwitchRecordAttempts(
    val bootVerifyFailures: Int = 0,
    val rebootRequests: Int = 0,
)

@Serializable
data class SwitchRecordReserve(val keepPreSwitchGenerations: Int = 1)

/** 固定键集合（多一个键 = 损坏；本类即 schema 的唯一来源）。 */
@Serializable
data class SwitchRecord(
    val schema: Int = SCHEMA,
    val switchId: String,
    val planSha256: String = "",
    /** [SwitchStateNames]。 */
    val state: String = SwitchStateNames.BEGIN,
    val stage: String = "S1",
    val step: String = "",
    val fromMode: String,
    val toMode: String,
    val fromBuild: String = "",
    val toBuild: String = "",
    val baselineId: String = "",
    val startBootId: String = "",
    val currentBootId: String = "",
    val createdAtUptimeMs: Long = 0,
    val updatedAtUptimeMs: Long = 0,
    val rebootRequestedAtUptimeMs: Long = 0,
    val rebootObservedBootId: String = "",
    val preflightSha256: String = "",
    val device: SwitchRecordDevice = SwitchRecordDevice(),
    val partitions: List<SwitchRecordPartition> = emptyList(),
    val steps: List<SwitchRecordStep> = emptyList(),
    val moves: List<SwitchRecordMove> = emptyList(),
    val materialize: SwitchRecordMaterialize = SwitchRecordMaterialize(),
    val artifacts: Map<String, String> = emptyMap(),
    val error: SwitchRecordError = SwitchRecordError(),
    val attempts: SwitchRecordAttempts = SwitchRecordAttempts(),
    val reserve: SwitchRecordReserve = SwitchRecordReserve(),
    val targetPartition: String? = null,
    /** Missing in old records; empty in new records when the source carrier is unknown. */
    val sourcePartition: String? = null,
) {
    companion object {
        const val SCHEMA = 1
        internal const val PREPARED_PLAN_PREFIX = "prepared-plan."
    }

    val pending: Boolean get() = SwitchStateNames.isPending(state)

    fun stepState(id: String): String? = steps.firstOrNull { it.id == id }?.state

    fun withStep(id: String, state: String): SwitchRecord {
        val next = steps.toMutableList()
        val index = next.indexOfFirst { it.id == id }
        if (index >= 0) next[index] = next[index].copy(state = state) else next += SwitchRecordStep(id, state)
        return copy(steps = next)
    }

    fun withError(code: String, stage: String, step: String, detail: String, atUptimeMs: Long): SwitchRecord =
        copy(error = SwitchRecordError(code, stage, step, detail, atUptimeMs))

    fun transition(
        state: String,
        stage: String,
        step: String,
        updatedAtUptimeMs: Long,
    ): SwitchRecord = copy(state = state, stage = stage, step = step, updatedAtUptimeMs = updatedAtUptimeMs)
}

sealed interface AuthorityRead {
    data object Missing : AuthorityRead

    data class Ok(val record: SwitchRecord) : AuthorityRead

    /** 字节级损坏 / schema 不认识。保留现场，禁止自动删除（01 §4.5）。 */
    data class Corrupt(val code: String, val detail: String) : AuthorityRead
}

/** `control/switch.json` 读写门面（单写者：本编排；恢复入口只读）。 */
interface SwitchAuthority {
    fun read(): AuthorityRead

    /** 同 switchId 才返回；不同或缺失返回 null（允许未指定）。 */
    fun read(switchId: String?): SwitchRecord?

    fun write(record: SwitchRecord)

    fun path(): File
}

/** 文件实现：原子替换 + `.sha256` 兄弟文件（复用 01 §4.2 的唯一写入路径）。 */
class FileSwitchAuthority(
    private val controlDir: File,
    private val clock: Clock = WallClock,
) : SwitchAuthority {

    private fun target() = File(controlDir, "switch.json")

    override fun path(): File = target()

    override fun read(): AuthorityRead {
        val target = target()
        if (!target.isFile) return AuthorityRead.Missing
        if (AtomicControlFile.verifySha(target) == ShaCheck.MISMATCH) {
            return AuthorityRead.Corrupt("SWITCH_CORRUPT", "sha mismatch")
        }
        val raw = AtomicControlFile.readUtf8(target)
            ?: return AuthorityRead.Corrupt("SWITCH_CORRUPT", "unreadable")
        val record = ControlJsonCodec.decodeOrNull(raw, SwitchRecord.serializer())
            ?: return AuthorityRead.Corrupt("SWITCH_CORRUPT", "parse failed")
        if (record.schema > SwitchRecord.SCHEMA) {
            return AuthorityRead.Corrupt("CONTROL_SCHEMA_TOO_NEW", "schema=${record.schema}")
        }
        if (!ModeSwitchHashes.isCanonicalUuid(record.switchId)) {
            return AuthorityRead.Corrupt("SWITCH_CORRUPT", "switchId")
        }
        return AuthorityRead.Ok(record)
    }

    override fun read(switchId: String?): SwitchRecord? {
        val record = (read() as? AuthorityRead.Ok)?.record ?: return null
        if (switchId != null && record.switchId != switchId) return null
        return record
    }

    override fun write(record: SwitchRecord) {
        require(ModeSwitchHashes.isCanonicalUuid(record.switchId)) { ModeSwitchCodes.PLAN_INVALID }
        require(record.schema == SwitchRecord.SCHEMA) { ModeSwitchCodes.PLAN_INVALID }
        ControlPermissions.ensureDir(controlDir)
        val json = ControlJsonCodec.encode(record, SwitchRecord.serializer())
        AtomicControlFile.writeJson(target(), json)
    }
}

/** 内存实现：主机单测/预览用；语义与文件实现一致（含 switchId 过滤）。 */
class InMemorySwitchAuthority(initial: SwitchRecord? = null) : SwitchAuthority {
    private var record: SwitchRecord? = initial

    override fun read(): AuthorityRead = record?.let { AuthorityRead.Ok(it) } ?: AuthorityRead.Missing

    override fun read(switchId: String?): SwitchRecord? =
        record?.takeIf { switchId == null || it.switchId == switchId }

    override fun write(record: SwitchRecord) {
        require(ModeSwitchHashes.isCanonicalUuid(record.switchId)) { ModeSwitchCodes.PLAN_INVALID }
        this.record = record
    }

    override fun path(): File = File("memory/switch.json")
}
