package dev.maplesu.manager.workmode.switch

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.control.ControlErrors
import dev.maplesu.manager.workmode.control.ControlPlane
import dev.maplesu.manager.workmode.control.ControlRead
import dev.maplesu.manager.workmode.control.EvidenceRedactor
import dev.maplesu.manager.workmode.control.schema.SwitchHeadView
import java.io.File

/**
 * App 侧 journal 只读门面。
 *
 * 写侧（状态机/switch.json/WAL/收敛）由切换服务负责；本门面只负责：
 * 启动门控、恢复页/进度页读取、诊断导出。**只读**，不做收敛。
 */
interface SwitchJournalFacade {
    /** 当前权威状态（读 control/switch.json 的投影）。无文件 → ControlRead.Missing。 */
    fun current(): ControlRead<SwitchHeadView>

    /** 是否有任何未完切换（含迁移 journal；主文档:745 的"所有非终态"）。 */
    fun hasPending(): Boolean

    /** 启动/手动进入时扫描；只读，不做收敛。 */
    fun scanIncomplete(): List<SwitchHeadView>

    /** 崩溃收敛的**触发**（不是实现）：调用安装/切换服务的恢复入口；本方法只负责发起与结果投影。 */
    suspend fun requestReconcile(): ReconcileOutcome

    /** 导出诊断（分区/期望哈希/镜像路径），给恢复页复制；内容脱敏，不含凭据。 */
    fun exportDiagnostics(switchId: String): String?
}

sealed interface ReconcileOutcome {
    data class Resumed(val head: SwitchHeadView) : ReconcileOutcome
    data class RolledBack(val head: SwitchHeadView) : ReconcileOutcome
    data class NeedsRecovery(val head: SwitchHeadView, val reason: String) : ReconcileOutcome
    /** 无 root / 服务不可用。 */
    data class Unavailable(val code: String) : ReconcileOutcome
}

/**
 * 文件实现（主机可测）：[control] 提供 switch.json 只读投影，[root] 指向控制面根目录
 * （扫描 `boot/work/<switchId>/journal.jsonl`）。
 */
class FileSwitchJournalFacade(
    private val control: ControlPlane,
    private val root: File,
) : SwitchJournalFacade {

    override fun current(): ControlRead<SwitchHeadView> = control.readSwitchHead()

    override fun hasPending(): Boolean {
        val head = current()
        // 损坏 = 现场存在但读不出：保守按 pending 处理（01 §4.5 第 3/4 条）。
        if (head is ControlRead.Corrupt) return true
        if (head is ControlRead.Ok && head.value.pending) return true
        return journalHeads().isNotEmpty()
    }

    override fun scanIncomplete(): List<SwitchHeadView> = buildList {
        val head = current()
        if (head is ControlRead.Ok && head.value.pending) add(head.value)
        val known = head as? ControlRead.Ok
        journalHeads()
            .filterNot { journal -> known != null && journal.switchId == known.value.switchId }
            .forEach { add(it) }
    }

    override suspend fun requestReconcile(): ReconcileOutcome {
        val head = current()
        if (head is ControlRead.Unreadable) return ReconcileOutcome.Unavailable(head.code)
        if (head is ControlRead.Corrupt) {
            return ReconcileOutcome.Unavailable(head.code)
        }
        // 真正的收敛在安装/切换服务（SwitchReconciler）；未接线前明确不可用。
        return ReconcileOutcome.Unavailable(SWITCH_SERVICE_UNAVAILABLE)
    }

    override fun exportDiagnostics(switchId: String): String? {
        val directory = File(root, "boot/work/$switchId")
        val lines = mutableListOf<String>()
        val head = current()
        if (head is ControlRead.Ok && head.value.switchId == switchId) {
            lines += "state=${head.value.state}"
            lines += "pending=${head.value.pending}"
            lines += "from=${head.value.from} to=${head.value.to}"
            lines += "bootIdAtBegin=${head.value.bootIdAtBegin}"
            lines += "error=${head.value.errorCode}/${head.value.errorStage}"
        }
        if (directory.isDirectory) {
            val journalFile = File(directory, "journal.jsonl")
            if (journalFile.isFile) {
                when (val replay = FileSwitchJournal(journalFile).replay(switchId)) {
                    is JournalReplay.Known -> {
                        lines += "journal.state=${replay.state}"
                        lines += "journal.seq=${replay.seq} stage=${replay.stage} step=${replay.step} op=${replay.lastOp}"
                    }
                    is JournalReplay.Degraded -> lines += "journal.degraded=${replay.code}"
                    JournalReplay.Empty -> lines += "journal=empty"
                }
            }
            directory.listFiles()?.sortedBy { it.name }?.forEach { file ->
                if (file.isFile && file.name != "journal.jsonl") {
                    val sha = runCatching { Hashes.sha256(file.readBytes()) }.getOrNull()
                    lines += "${file.name} size=${file.length()} sha256=${sha?.take(16) ?: "?"}"
                }
            }
        }
        if (lines.isEmpty()) return null
        return lines.joinToString("\n") { line -> redact(line) }
    }

    /** 扫描 journal，重建"最近已知状态"仍为非终态的切换（只读）。 */
    private fun journalHeads(): List<SwitchHeadView> {
        val workRoot = File(root, "boot/work")
        if (!workRoot.isDirectory) return emptyList()
        return workRoot.listFiles { file -> file.isDirectory }?.toList().orEmpty().mapNotNull { directory ->
            val journalFile = File(directory, "journal.jsonl")
            if (!journalFile.isFile) return@mapNotNull null
            val replay = FileSwitchJournal(journalFile).replay(directory.name)
            val known = replay as? JournalReplay.Known ?: return@mapNotNull null
            if (!SwitchStateNames.isPending(known.state)) return@mapNotNull null
            SwitchHeadView(
                schema = 1,
                switchId = directory.name,
                state = known.state,
                from = "",
                to = "",
                bootIdAtBegin = "",
                pending = true,
                attempts = 0,
                errorCode = "",
                errorStage = "",
                updatedAt = known.seq,
            )
        }
    }

    private fun redact(line: String): String {
        val lower = line.lowercase()
        return if (EvidenceRedactor.SENSITIVE_TOKENS.any { lower.contains(it) }) "[REDACTED]" else line
    }

    companion object {
        const val SWITCH_SERVICE_UNAVAILABLE = "SWITCH_SERVICE_UNAVAILABLE"
    }
}
