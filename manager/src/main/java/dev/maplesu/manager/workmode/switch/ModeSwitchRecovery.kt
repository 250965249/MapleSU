package dev.maplesu.manager.workmode.switch

/**
 * 掉电/进程被杀后的恢复判定，以纯函数作为切换事务的兼容层。
 *
 * 判定只依赖**只读观测**：分区整长摘要（读回）+ journal 重放结论 + bootId 是否变化。
 * 任何"不确定"都落到 [RecoveryDecision.RECOVERY_REQUIRED]，绝不猜测分区状态。
 */
enum class RecoveryDecision {
    /** 继续向前：补齐 DONE / 进入 verify。 */
    RESUME_FORWARD,

    /** 失败已记录：逆序回滚。 */
    ROLLBACK,

    /** 只能外部恢复（不得自动重试/自动重启）。 */
    RECOVERY_REQUIRED,

    /** 终态，无需动作。 */
    NOTHING_TO_DO,
}

/** 恢复判定的全部输入。 */
data class SwitchObservation(
    val state: String,
    /** `switch.json.error.code` 非空，或任一分区/步骤 state=FAILED。 */
    val failureRecorded: Boolean,
    /** 读回的整分区摘要（缺失 = 没读到）。 */
    val currentSha: Map<String, String> = emptyMap(),
    val preSha: Map<String, String> = emptyMap(),
    val targetSha: Map<String, String> = emptyMap(),
    val bootVerifyFailures: Int = 0,
    val bootIdChanged: Boolean = false,
    /** journal 断号/坏链（`RECOVERY_JOURNAL_CORRUPT`）。 */
    val journalCorrupt: Boolean = false,
)

object ModeSwitchReconciler {

    fun decide(observation: SwitchObservation): RecoveryDecision {
        val o = observation
        // 1) WAL 不可信 → 不能继续，也不能自动回滚（回滚同样依赖 journal 的"已写集合"）。
        if (o.journalCorrupt) return RecoveryDecision.RECOVERY_REQUIRED
        // 2) 终态。
        if (o.state in SwitchStateNames.TERMINAL) return RecoveryDecision.NOTHING_TO_DO
        // 3) 读回摘要必须可归属：∈ {pre, target}。空观测 = 读不到 = 不能继续。
        if (o.preSha.isNotEmpty() && o.currentSha.isEmpty()) return RecoveryDecision.RECOVERY_REQUIRED
        val unattributed = o.currentSha.filter { (name, sha) ->
            val pre = o.preSha[name]
            val target = o.targetSha[name]
            !sha.equals(pre, ignoreCase = true) && !sha.equals(target, ignoreCase = true)
        }
        if (unattributed.isNotEmpty()) return RecoveryDecision.RECOVERY_REQUIRED
        // 4) 失败记录优先回滚（哪怕当前看起来是 target 的一半）。
        if (o.failureRecorded) return RecoveryDecision.ROLLBACK
        // 5) 连续确认失败 2 次 → 强制外部恢复（02 §5.6 / DOC:711）。
        if (o.bootVerifyFailures >= 2) return RecoveryDecision.RECOVERY_REQUIRED
        // 6) 等待重启阶段。
        if (o.state == SwitchStateNames.REBOOT_REQUIRED) {
            return if (o.bootIdChanged) RecoveryDecision.RESUME_FORWARD
            else RecoveryDecision.NOTHING_TO_DO
        }
        // 7) 全 target / 全 pre / 部分混合：都继续向前，每步仍逐条判定。
        return RecoveryDecision.RESUME_FORWARD
    }

    /** 回滚执行后的终态判定：全部读回 == pre 才是 ROLLED_BACK。 */
    fun postRollbackState(observation: SwitchObservation): String {
        val allPre = observation.preSha.isNotEmpty() && observation.preSha.all { (name, sha) ->
            observation.currentSha[name]?.equals(sha, ignoreCase = true) == true
        }
        return if (allPre) SwitchStateNames.ROLLED_BACK else SwitchStateNames.RECOVERY_REQUIRED
    }

    /** 从 `switch.json` 分区行构造观测（`targetSha` 空表示尚未产出候选）。 */
    fun observe(
        record: SwitchRecord,
        liveSha: Map<String, String>,
        bootIdChanged: Boolean,
        journalCorrupt: Boolean = false,
    ): SwitchObservation = SwitchObservation(
        state = record.state,
        failureRecorded = record.error.code.isNotEmpty() ||
            record.partitions.any { it.state == "FAILED" },
        currentSha = liveSha,
        preSha = record.partitions.associate { it.name to it.preSha256 },
        targetSha = record.partitions.filter { it.targetSha256.isNotEmpty() }
            .associate { it.name to it.targetSha256 },
        bootVerifyFailures = record.attempts.bootVerifyFailures,
        bootIdChanged = bootIdChanged,
        journalCorrupt = journalCorrupt,
    )
}
